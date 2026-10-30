from datetime import datetime, timezone
from threading import Lock
from typing import Optional

import csv, io
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.csv_safe import csv_safe_row
from backend.app.core.database import get_db
from backend.app.core.netutil import client_ip, parse_scan_target
from backend.app.models.entities import NetworkDevice, ScanRange, User
from backend.app.api.deps import record_audit_event, require_permission
from backend.app.services.netscan import scan_subnet, get_local_subnet

router = APIRouter()

MAX_SAVED_RANGES = 50

# A scan pings up to SCAN_MAX_HOSTS addresses with dozens of threads; two at once would only fight
# for the same sockets, so a second request is told to wait instead of piling on.
_scan_lock = Lock()


def _utcnow():
    return datetime.now(timezone.utc)


def _audit(db: Session, request: Request, actor: str, action: str, target: Optional[str] = None,
           result: str = "SUCCESS", details: Optional[dict] = None):
    record_audit_event(db, actor_email=actor, action=action, target=target, result=result,
                       ip_address=client_ip(request), details=details)


def _fit(model, column: str, value):
    """Text from the network (reverse DNS, vendor tables) cut to the column width."""
    if isinstance(value, str):
        limit = model.__table__.c[column].type.length
        return value[:limit] if limit else value
    return value


class ScanRequest(BaseModel):
    subnet: Optional[str] = Field(default=None, max_length=100)


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
def scan_network(request: Request, payload: Optional[ScanRequest] = None,
                 db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("network.manage"))):
    """Discover devices on the LAN (ping sweep + ARP), upsert them into the asset inventory,
    and return what was found. Limited to private address ranges of at most SCAN_MAX_HOSTS."""
    subnet = payload.subnet if payload else None
    if not _scan_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="A scan is already running; wait for it to finish.")
    try:
        result = scan_subnet(subnet)
        if result.get("error"):
            _audit(db, request, current_user.email, "network.scan", subnet or "default subnet", "DENIED",
                   {"reason": result["error"]})
            raise HTTPException(status_code=400, detail=result["error"])

        now = _utcnow()
        for d in result["devices"]:
            fields = {
                "hostname": _fit(NetworkDevice, "hostname", d["hostname"]),
                "vendor": _fit(NetworkDevice, "vendor", d["vendor"]),
                "device_type": _fit(NetworkDevice, "device_type", d["device_type"]),
                "os_guess": _fit(NetworkDevice, "os_guess", d.get("os_guess")),
                "open_ports": d.get("open_ports"),
                "source_subnet": _fit(NetworkDevice, "source_subnet", result["subnet"]),
                "is_online": d["is_online"],
            }
            existing = None
            if d["mac"]:
                existing = db.query(NetworkDevice).filter(NetworkDevice.mac_address == d["mac"]).first()
            if not existing:
                existing = db.query(NetworkDevice).filter(NetworkDevice.ip_address == d["ip"]).first()

            if existing:
                existing.ip_address = d["ip"]
                existing.mac_address = d["mac"] or existing.mac_address
                existing.hostname = fields["hostname"] or existing.hostname
                for k in ("vendor", "device_type", "os_guess", "open_ports", "source_subnet", "is_online"):
                    setattr(existing, k, fields[k])
                existing.last_seen = now
            else:
                db.add(NetworkDevice(ip_address=d["ip"], mac_address=d["mac"], first_seen=now, last_seen=now, **fields))
        db.commit()
        _audit(db, request, current_user.email, "network.scan", result["subnet"], "SUCCESS",
               {"devices": len(result["devices"])})
        return result
    finally:
        _scan_lock.release()


@router.get("/devices")
def list_devices(db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("telemetry.view"))):
    """The asset inventory: every device ever discovered, newest activity first."""
    rows = db.query(NetworkDevice).order_by(NetworkDevice.last_seen.desc()).all()
    return [_serialize(r) for r in rows]


class RangeRequest(BaseModel):
    name: str = Field(max_length=120)
    target: str = Field(max_length=100)


@router.get("/ranges")
def list_ranges(db: Session = Depends(get_db),
                current_user: User = Depends(require_permission("telemetry.view"))):
    rows = db.query(ScanRange).order_by(ScanRange.created_at.desc()).all()
    return [{"id": r.id, "name": r.name, "target": r.target, "created_at": r.created_at} for r in rows]


@router.post("/ranges")
def add_range(payload: RangeRequest, request: Request, db: Session = Depends(get_db),
              current_user: User = Depends(require_permission("network.manage"))):
    name, target = payload.name.strip(), payload.target.strip()
    if not name or not target:
        raise HTTPException(status_code=400, detail="Name and target are required.")
    try:
        parse_scan_target(target, settings.SCAN_MAX_HOSTS, settings.SCAN_ALLOW_PUBLIC)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid range/subnet: {e}")
    if db.query(ScanRange).count() >= MAX_SAVED_RANGES:
        raise HTTPException(status_code=400, detail=f"At most {MAX_SAVED_RANGES} ranges can be saved.")
    r = ScanRange(name=name, target=target, created_at=_utcnow())
    db.add(r)
    db.commit()
    db.refresh(r)
    _audit(db, request, current_user.email, "network.range.add", f"range #{r.id}", "SUCCESS",
           {"name": name, "target": target})
    return {"id": r.id, "name": r.name, "target": r.target, "created_at": r.created_at}


@router.delete("/ranges/{range_id}")
def delete_range(range_id: int, request: Request, db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("network.manage"))):
    r = db.query(ScanRange).filter(ScanRange.id == range_id).first()
    if r:
        name, target = r.name, r.target
        db.delete(r)
        db.commit()
        _audit(db, request, current_user.email, "network.range.delete", f"range #{range_id}", "SUCCESS",
               {"name": name, "target": target})
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
        w.writerow(csv_safe_row([r.ip_address, r.mac_address or "", r.hostname or "", r.vendor or "",
                                 r.device_type or "", r.os_guess or "", r.open_ports or "",
                                 r.source_subnet or "", "yes" if r.is_online else "no",
                                 r.first_seen.isoformat() if r.first_seen else "",
                                 r.last_seen.isoformat() if r.last_seen else ""]))
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=asset-inventory.csv"})
