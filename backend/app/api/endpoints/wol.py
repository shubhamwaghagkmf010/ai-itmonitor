import re
import socket
import subprocess
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

def _server_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _same_subnet(a: str, b: str) -> bool:
    try:
        na = ipaddress.IPv4Network(f"{a}/24", strict=False).network_address
        nb = ipaddress.IPv4Network(f"{b}/24", strict=False).network_address
        return na == nb
    except Exception:
        return True


def _ping_ok(ip: str) -> bool:
    try:
        return subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                              capture_output=True, timeout=2).returncode == 0
    except Exception:
        return False


def _tcp_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((ip, port))
        s.close()
        return rc == 0
    except Exception:
        return False


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
    server_ip = _server_ip()
    cross = bool(target_ip) and bool(server_ip) and not _same_subnet(server_ip, target_ip)
    dispatch_logs.append(f"[Target] {target_ip}  MAC {target_mac}  subnet-broadcast {subnet_bcast}")
    dispatch_logs.append(f"[Server] {server_ip}  -> sent magic packet x3 to {', '.join(targets)} on UDP 7 & 9")
    if cross:
        dispatch_logs.append("[WARN] Target is on a DIFFERENT subnet than the server. A broadcast usually does NOT cross a router, so this wake depends on a peer-relay agent on the target subnet (below) or router directed-broadcast.")

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
                    dispatch_logs.append(f"[Peer-Relay] Asked online agent on {peer.hostname} ({peer.ip_address}) to broadcast locally")
                    relays_triggered += 1
            except Exception:
                pass
        if relays_triggered == 0:
            dispatch_logs.append("[Peer-Relay] No online agent on the target subnet to relay through."
                                 + (" This is required for cross-subnet wake." if cross else ""))
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


@router.get("/status/{machine_id}")
def wol_status(machine_id: int, db: Session = Depends(get_db),
               current_user: User = Depends(require_permission("wol.view"))):
    """Live boot status of a target: agent heartbeat, or ICMP ping, or an open TCP port.
    Lets the UI show what stage the machine is actually at after a wake."""
    m = db.query(Machine).filter(Machine.id == machine_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Target device not found")

    now = datetime.now(timezone.utc)
    hb = False
    if m.last_heartbeat:
        hb_utc = m.last_heartbeat if m.last_heartbeat.tzinfo else m.last_heartbeat.replace(tzinfo=timezone.utc)
        hb = (now - hb_utc).total_seconds() < 30

    ip = m.ip_address if (m.ip_address and m.ip_address not in ("Unknown", "127.0.0.1")) else ""
    ping = _ping_ok(ip) if ip else False
    tcp_port = 0
    if ip and not (hb or ping):
        for port in (3389, 445, 139, 135, 22):
            if _tcp_open(ip, port):
                tcp_port = port
                break

    online = bool(hb or ping or tcp_port)
    signal = "agent" if hb else ("ping" if ping else (f"tcp:{tcp_port}" if tcp_port else "none"))
    return {"machine_id": machine_id, "hostname": m.hostname, "ip": ip or None,
            "online": online, "signal": signal,
            "stage": "ONLINE" if online else "OFFLINE"}
