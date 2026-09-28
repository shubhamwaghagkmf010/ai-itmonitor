from datetime import datetime, timezone
from typing import Optional

import csv, io
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.entities import NetworkDevice, ScanRange, User
from backend.app.api.deps import require_permission
from backend.app.services.netscan import scan_subnet, get_local_subnet

router = APIRouter()


def _utcnow():
    return datetime.now(timezone.utc)


class ScanRequest(BaseModel):
    subnet: Optional[str] = None


def _serialize(r: NetworkDevice):
    return {
        "id": r.id,
        "ip_address": r.ip_address,
        "mac_address": r.mac_address,
        "hostname": r.hostname,
        "vendor": r.vendor,
        "device_type": r.device_type,
        "os_guess": r.os_guess,
        "open_ports": r.open_ports,
        "source_subnet": r.source_subnet,
        "is_online": r.is_online,
        "notes": r.notes,
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
    }


@router.get("/subnet")
def detected_subnet(current_user: User = Depends(require_permission("telemetry.view"))):
    """The subnet the server would scan by default."""
    return {"subnet": get_local_subnet()}


@router.post("/scan")
def scan_network(payload: Optional[ScanRequest] = None,
                 db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("telemetry.view"))):
    """Discover devices on the LAN (ping sweep + ARP), upsert them into the asset inventory,
    and return what was found."""
    subnet = payload.subnet if payload else None
    result = scan_subnet(subnet)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])

    now = _utcnow()
    for d in result["devices"]:
        existing = None
        if d["mac"]:
            existing = db.query(NetworkDevice).filter(NetworkDevice.mac_address == d["mac"]).first()
        if not existing:
            existing = db.query(NetworkDevice).filter(NetworkDevice.ip_address == d["ip"]).first()

        if existing:
            existing.ip_address = d["ip"]
            existing.mac_address = d["mac"] or existing.mac_address
            existing.hostname = d["hostname"] or existing.hostname
            existing.vendor = d["vendor"]
            existing.device_type = d["device_type"]
            existing.os_guess = d.get("os_guess")
            existing.open_ports = d.get("open_ports")
            existing.source_subnet = result["subnet"]
            existing.is_online = d["is_online"]
            existing.last_seen = now
        else:
            db.add(NetworkDevice(
                ip_address=d["ip"], mac_address=d["mac"], hostname=d["hostname"],
                vendor=d["vendor"], device_type=d["device_type"],
                os_guess=d.get("os_guess"), open_ports=d.get("open_ports"),
                source_subnet=result["subnet"], is_online=d["is_online"],
                first_seen=now, last_seen=now,
            ))
    db.commit()
    return result


@router.get("/devices")
def list_devices(db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("telemetry.view"))):
    """The asset inventory: every device ever discovered, newest activity first."""
    rows = db.query(NetworkDevice).order_by(NetworkDevice.last_seen.desc()).all()
    return [_serialize(r) for r in rows]


class RangeRequest(BaseModel):
    name: str
    target: str


@router.get("/ranges")
def list_ranges(db: Session = Depends(get_db),
                current_user: User = Depends(require_permission("telemetry.view"))):
    rows = db.query(ScanRange).order_by(ScanRange.created_at.desc()).all()
    return [{"id": r.id, "name": r.name, "target": r.target, "created_at": r.created_at} for r in rows]


@router.post("/ranges")
def add_range(payload: RangeRequest, db: Session = Depends(get_db),
              current_user: User = Depends(require_permission("telemetry.view"))):
    if not payload.name.strip() or not payload.target.strip():
        raise HTTPException(status_code=400, detail="Name and target are required.")
    r = ScanRange(name=payload.name.strip(), target=payload.target.strip(), created_at=_utcnow())
    db.add(r)
    db.commit()
    db.refresh(r)
    return {"id": r.id, "name": r.name, "target": r.target, "created_at": r.created_at}


@router.delete("/ranges/{range_id}")
def delete_range(range_id: int, db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("telemetry.view"))):
    r = db.query(ScanRange).filter(ScanRange.id == range_id).first()
    if r:
        db.delete(r)
        db.commit()
    return {"deleted": range_id}


@router.get("/devices/export")
def export_devices(db: Session = Depends(get_db),
                   current_user: User = Depends(require_permission("telemetry.view"))):
    """Download the asset inventory as CSV."""
    rows = db.query(NetworkDevice).order_by(NetworkDevice.ip_address).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["IP", "MAC", "Hostname", "Vendor", "Device Type", "OS", "Open Ports",
                "Source Subnet", "Online", "First Seen", "Last Seen"])
    for r in rows:
        w.writerow([r.ip_address, r.mac_address or "", r.hostname or "", r.vendor or "",
                    r.device_type or "", r.os_guess or "", r.open_ports or "",
                    r.source_subnet or "", "yes" if r.is_online else "no",
                    r.first_seen.isoformat() if r.first_seen else "",
                    r.last_seen.isoformat() if r.last_seen else ""])
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=asset-inventory.csv"})
