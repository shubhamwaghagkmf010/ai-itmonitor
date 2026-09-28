import re
import socket
import ipaddress
import time
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.entities import Machine, WOLRequest, User
from backend.app.api.deps import require_permission, record_audit_event

router = APIRouter()

MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

def build_magic_packet(mac_address: str) -> bytes:
    clean_mac = mac_address.replace(":", "").replace("-", "").strip()
    if len(clean_mac) != 12:
        raise ValueError(f"Invalid MAC length: {mac_address}")
    mac_bytes = bytes.fromhex(clean_mac)
    return (b'\xff' * 6) + (mac_bytes * 16)

def calculate_dynamic_subnet_broadcast(ip_str: str) -> str:
    try:
        if ip_str and ip_str != "127.0.0.1" and ip_str != "Unknown":
            net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
            return str(net.broadcast_address)
    except Exception:
        pass
    return "255.255.255.255"

def execute_hardened_wol_with_relays(db: Session, target_mac: str, target_ip: str):
    packet = build_magic_packet(target_mac)
    subnet_bcast = calculate_dynamic_subnet_broadcast(target_ip)
    dispatch_logs = []
    
    # 1. Direct Server Multi-Burst Broadcast (Ports 7, 9)
    targets = list(set([subnet_bcast, target_ip, "255.255.255.255"]))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for _ in range(3):
            for dest in targets:
                for port in [7, 9]:
                    try:
                        s.sendto(packet, (dest, port))
                    except Exception:
                        pass
            time.sleep(0.04)
    dispatch_logs.append(f"[Server Direct] Dispatched 3-Burst to {subnet_bcast} & {target_ip}")

    # 2. Automated Peer-Relay: Find any active online node on same subnet
    try:
        now = datetime.now(timezone.utc)
        online_machines = db.query(Machine).all()
        relays_triggered = 0
        
        for peer in online_machines:
            if not peer.ip_address or peer.ip_address == target_ip:
                continue
            
            # Check if peer is in same subnet
            try:
                peer_net = ipaddress.IPv4Network(f"{peer.ip_address}/24", strict=False)
                target_net = ipaddress.IPv4Network(f"{target_ip}/24", strict=False)
                
                # Check recent heartbeat (< 40s)
                if peer.last_heartbeat:
                    hb_utc = peer.last_heartbeat if peer.last_heartbeat.tzinfo else peer.last_heartbeat.replace(tzinfo=timezone.utc)
                    is_peer_online = (now - hb_utc).total_seconds() < 40
                else:
                    is_peer_online = False

                if peer_net == target_net and is_peer_online:
                    # Send UDP Relay Wake trigger to port 9999 on peer
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as r_sock:
                        r_sock.sendto(target_mac.encode('utf-8'), (peer.ip_address, 9999))
                    dispatch_logs.append(f"[Peer-Relay] Triggered active agent on {peer.hostname} ({peer.ip_address})")
                    relays_triggered += 1
            except Exception:
                pass
    except Exception as ex:
        dispatch_logs.append(f"[Peer-Relay Notice] {ex}")

    return subnet_bcast, dispatch_logs

class WakeRequestPayload(BaseModel):
    broadcast_ip: Optional[str] = None
    port: Optional[int] = 7

@router.get("/devices")
@router.get("/devices/")
def list_wol_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("wol.view"))
):
    machines = db.query(Machine).order_by(Machine.hostname.asc()).all()
    results = []
    now = datetime.now(timezone.utc)
    
    for m in machines:
        is_online = False
        if m.last_heartbeat:
            hb_utc = m.last_heartbeat if m.last_heartbeat.tzinfo else m.last_heartbeat.replace(tzinfo=timezone.utc)
            is_online = (now - hb_utc).total_seconds() < 25
        
        last_req = db.query(WOLRequest).filter(
            WOLRequest.machine_id == m.id
        ).order_by(WOLRequest.created_at.desc()).first()
        
        boot_status = "ONLINE" if is_online else "OFFLINE"
        if not is_online and last_req:
            req_time = last_req.created_at if last_req.created_at.tzinfo else last_req.created_at.replace(tzinfo=timezone.utc)
            if (now - req_time).total_seconds() < 90:
                boot_status = "BOOTING"
            
        has_valid_mac = bool(m.mac_address and MAC_REGEX.match(m.mac_address))
        calculated_bcast = calculate_dynamic_subnet_broadcast(m.ip_address)

        results.append({
            "id": m.id,
            "hostname": m.hostname,
            "ip_address": m.ip_address or "Unknown",
            "mac_address": m.mac_address if has_valid_mac else None,
            "has_valid_mac": has_valid_mac,
            "subnet_broadcast": calculated_bcast,
            "logged_in_user": m.logged_in_user or "System",
            "is_online": is_online,
            "boot_status": boot_status,
            "wol_enabled": has_valid_mac and m.wol_enabled,
            "last_heartbeat": m.last_heartbeat.isoformat() if m.last_heartbeat else None,
            "last_wol_request": m.last_wol_request.isoformat() if m.last_wol_request else None
        })
    return results

@router.post("/wake/{machine_id}")
@router.post("/wake/{machine_id}/")
def wake_machine(
    machine_id: int,
    payload: WakeRequestPayload,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("wol.execute"))
):
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Target device not found")

    if not machine.mac_address or not MAC_REGEX.match(machine.mac_address):
        raise HTTPException(
            status_code=400, 
            detail=f"Target machine '{machine.hostname}' does not have a valid physical MAC registered."
        )

    now = datetime.now(timezone.utc)
    if machine.last_wol_request:
        last_wol = machine.last_wol_request if machine.last_wol_request.tzinfo else machine.last_wol_request.replace(tzinfo=timezone.utc)
        if (now - last_wol).total_seconds() < 4:
            remaining = int(4 - (now - last_wol).total_seconds())
            raise HTTPException(
                status_code=429,
                detail=f"Cooldown active for {machine.hostname}. Please wait {remaining}s."
            )

    try:
        subnet_bcast, dispatch_logs = execute_hardened_wol_with_relays(db, machine.mac_address, machine.ip_address)
    except Exception as e:
        record_audit_event(
            db,
            actor_email=current_user.email,
            action="WOL_FAILED",
            target=f"{machine.hostname} ({machine.mac_address})",
            result="FAILED",
            ip_address=request.client.host if request.client else "internal",
            details={"error": str(e)}
        )
        raise HTTPException(status_code=500, detail=f"Failed to dispatch Magic Packet: {str(e)}")

    wol_record = WOLRequest(
        machine_id=machine.id,
        triggered_by=current_user.email,
        mac_address=machine.mac_address,
        broadcast_ip=subnet_bcast,
        port=7,
        status="PACKET_SENT"
    )
    machine.last_wol_request = now
    db.add(wol_record)
    db.commit()

    record_audit_event(
        db,
        actor_email=current_user.email,
        action="WOL_WAKE_SENT",
        target=f"{machine.hostname} ({machine.mac_address})",
        result="SUCCESS",
        ip_address=request.client.host if request.client else "internal",
        details={"mac": machine.mac_address, "subnet": subnet_bcast, "logs": dispatch_logs}
    )

    return {
        "status": "success",
        "message": f"Hardened Magic Packet blasted to {machine.hostname} ({machine.mac_address})",
        "request_id": wol_record.id,
        "mac_address": machine.mac_address,
        "boot_status": "BOOTING",
        "logs": dispatch_logs
    }
