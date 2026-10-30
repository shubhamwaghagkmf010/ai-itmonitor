from datetime import datetime, timezone
from typing import Optional
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.csv_safe import csv_safe_row
from backend.app.core.netutil import client_ip, is_internal_address
from backend.app.core.ratelimit import SlidingWindowLimiter
from backend.app.models.entities import Asset, Machine, MachineInventory, NetworkDevice, User
from backend.app.api.deps import has_permission, record_audit_event, require_permission

router = APIRouter()

# Every editable column, in display order.
FIELDS = [
    "asset_no", "category", "sub_category", "host_name", "make", "model",
    "allocation_type", "allocation_purpose",
    "owned_by_emp_id", "owned_by_emp_name", "workstation_number",
    "serial_no", "processor_type", "ram", "hard_disk_size",
    "os_architecture", "os_version", "os_edition",
    "license_key", "warranty_start", "warranty_end",
]

# Fields an end user may fill in from the self-service page (nothing technical/admin).
USER_FIELDS = ["owned_by_emp_id", "owned_by_emp_name", "workstation_number", "allocation_purpose"]

EXPORT_HEADERS = [
    "Asset No", "Asset Category", "Asset Sub Category", "Host Name", "Make", "Model",
    "Type of Allocation", "Purpose of Allocation", "Owned By Employee ID", "Owned By Employee Name",
    "Work Station Number", "SerialNo", "Processor Type", "RAM", "Hard Disk Size",
    "OS Architecture", "OS Version", "OS Edition", "License Key",
    "Warranty Start Date", "Warranty End Date",
]

# The register's licence keys are secrets; people who may only look at the register see them masked.
MASKED = "********"

# The self-service page has no login, so what it can do is kept small: a handful of requests a minute
# per address, and only from inside the network.
_self_read_limit = SlidingWindowLimiter(60, 60)
_self_write_limit = SlidingWindowLimiter(10, 60)


def _utcnow():
    return datetime.now(timezone.utc)


def _client_ip(request: Request) -> str:
    return client_ip(request)


def _audit(db: Session, request: Request, actor: str, action: str, target: Optional[str] = None,
           result: str = "SUCCESS", details: Optional[dict] = None):
    record_audit_event(db, actor_email=actor, action=action, target=target, result=result,
                       ip_address=client_ip(request), details=details)


class AssetIn(BaseModel):
    # Lengths match the columns, so an over-long value is a 422 and not a database error.
    asset_no: Optional[str] = Field(default=None, max_length=80)
    category: Optional[str] = Field(default=None, max_length=120)
    sub_category: Optional[str] = Field(default=None, max_length=120)
    host_name: Optional[str] = Field(default=None, max_length=255)
    make: Optional[str] = Field(default=None, max_length=120)
    model: Optional[str] = Field(default=None, max_length=160)
    allocation_type: Optional[str] = Field(default=None, max_length=120)
    allocation_purpose: Optional[str] = Field(default=None, max_length=255)
    owned_by_emp_id: Optional[str] = Field(default=None, max_length=80)
    owned_by_emp_name: Optional[str] = Field(default=None, max_length=160)
    workstation_number: Optional[str] = Field(default=None, max_length=80)
    serial_no: Optional[str] = Field(default=None, max_length=160)
    processor_type: Optional[str] = Field(default=None, max_length=200)
    ram: Optional[str] = Field(default=None, max_length=60)
    hard_disk_size: Optional[str] = Field(default=None, max_length=60)
    os_architecture: Optional[str] = Field(default=None, max_length=40)
    os_version: Optional[str] = Field(default=None, max_length=160)
    os_edition: Optional[str] = Field(default=None, max_length=160)
    license_key: Optional[str] = Field(default=None, max_length=120)
    warranty_start: Optional[str] = Field(default=None, max_length=40)
    warranty_end: Optional[str] = Field(default=None, max_length=40)


class SelfUpdate(BaseModel):
    owned_by_emp_id: Optional[str] = Field(default=None, max_length=80)
    owned_by_emp_name: Optional[str] = Field(default=None, max_length=160)
    workstation_number: Optional[str] = Field(default=None, max_length=80)
    allocation_purpose: Optional[str] = Field(default=None, max_length=255)


def _serialize(a: Asset, show_license: bool = True):
    d = {f: getattr(a, f) for f in FIELDS}
    if not show_license and d.get("license_key"):
        d["license_key"] = MASKED
    d["id"] = a.id
    d["machine_id"] = a.machine_id
    return d


def _fit(column_name: str, value):
    """Agent-reported text cut to the column's width (a long value would otherwise fail the commit)."""
    if isinstance(value, str):
        limit = Asset.__table__.c[column_name].type.length
        return value[:limit] if limit else value
    return value


# ---------------------------------------------------------------- admin CRUD

@router.get("")
@router.get("/")
def list_assets(db: Session = Depends(get_db),
                current_user: User = Depends(require_permission("assets.view"))):
    show_license = has_permission(current_user, "assets.manage")
    return [_serialize(a, show_license) for a in db.query(Asset).order_by(Asset.id).all()]


@router.post("")
@router.post("/")
def create_asset(payload: AssetIn, request: Request, db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("assets.manage"))):
    a = Asset(created_at=_utcnow(), **payload.model_dump())
    db.add(a)
    db.commit()
    db.refresh(a)
    _audit(db, request, current_user.email, "asset.create", f"asset #{a.id}", "SUCCESS",
           {"host_name": a.host_name, "fields": sorted(payload.model_dump(exclude_none=True))})
    return _serialize(a)


@router.patch("/{asset_id}")
def update_asset(asset_id: int, payload: AssetIn, request: Request, db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("assets.manage"))):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    changes = payload.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(a, k, v)
    db.commit()
    # Which fields changed, never the values: the register holds licence keys.
    _audit(db, request, current_user.email, "asset.update", f"asset #{a.id}", "SUCCESS",
           {"host_name": a.host_name, "fields": sorted(changes)})
    return _serialize(a)


@router.delete("/{asset_id}")
def delete_asset(asset_id: int, request: Request, db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("assets.manage"))):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if a:
        host = a.host_name
        db.delete(a)
        db.commit()
        _audit(db, request, current_user.email, "asset.delete", f"asset #{asset_id}", "SUCCESS", {"host_name": host})
    return {"deleted": asset_id}


@router.post("/sync")
def sync_from_agents(request: Request, db: Session = Depends(get_db),
                     current_user: User = Depends(require_permission("assets.manage"))):
    created = updated = 0
    for m in db.query(Machine).all():
        inv = db.query(MachineInventory).filter(MachineInventory.machine_id == m.id).first()
        hw = (inv.hardware if inv else None) or {}
        disks = hw.get("disks") or []
        hdd = round(sum((d.get("total_gb") or 0) for d in disks), 1)
        auto = {
            "host_name": m.hostname,
            "make": hw.get("manufacturer") or "",
            "model": hw.get("product") or "",
            "serial_no": hw.get("serial") or "",
            "processor_type": hw.get("cpu_model") or "",
            "ram": f"{hw.get('ram_total_gb')} GB" if hw.get("ram_total_gb") else "",
            "hard_disk_size": f"{hdd} GB" if hdd else "",
            "os_architecture": hw.get("arch") or m.architecture or "",
            "os_version": hw.get("os_version") or hw.get("os_pretty") or m.os_version or "",
            "os_edition": hw.get("os_edition") or hw.get("os_pretty") or "",
        }
        auto = {k: _fit(k, str(v)) if v else v for k, v in auto.items()}
        a = db.query(Asset).filter(Asset.machine_id == m.id).first()
        if a:
            for k, v in auto.items():
                if v:
                    setattr(a, k, v)
            updated += 1
        else:
            db.add(Asset(machine_id=m.id, created_at=_utcnow(), **auto))
            created += 1
    db.commit()
    _audit(db, request, current_user.email, "asset.sync", "all machines", "SUCCESS",
           {"created": created, "updated": updated})
    return {"created": created, "updated": updated}


def _agent_ip_map(db: Session):
    """IP -> (hostname, mac) learned from agents. Fills in hostname/MAC the network scan could
    not get (e.g. devices on a routed subnet), once an agent reports for that IP."""
    ip_map = {}
    for m in db.query(Machine).all():
        if not m.ip_address:
            continue
        mac = m.mac_address or ""
        inv = db.query(MachineInventory).filter(MachineInventory.machine_id == m.id).first()
        if inv and inv.hardware:
            nics = inv.hardware.get("network_adapters") or []
            for n in nics:
                if m.ip_address in (n.get("ipv4") or []) and n.get("mac"):
                    mac = n["mac"]
                    break
            if not mac:
                for n in nics:
                    if n.get("mac"):
                        mac = n["mac"]
                        break
        ip_map[m.ip_address] = (m.hostname, mac)
    return ip_map


@router.get("/coverage")
def coverage(db: Session = Depends(get_db),
             current_user: User = Depends(require_permission("assets.view"))):
    devices = db.query(NetworkDevice).all()
    assets = db.query(Asset).all()
    asset_hosts = {(a.host_name or "").lower() for a in assets if a.host_name}
    ip_map = _agent_ip_map(db)

    changed = False
    matched, unregistered = 0, []
    for d in devices:
        # Backfill hostname/MAC from agent data when the scan did not capture them.
        agent_host, agent_mac = ip_map.get(d.ip_address, ("", ""))
        if agent_host and not d.hostname:
            d.hostname = agent_host
            changed = True
        if agent_mac and (not d.mac_address):
            d.mac_address = agent_mac
            changed = True

        h = (d.hostname or "").lower()
        if h and h in asset_hosts:
            matched += 1
        else:
            unregistered.append({"ip": d.ip_address, "hostname": d.hostname, "mac": d.mac_address,
                                 "vendor": d.vendor, "device_type": d.device_type})
    if changed:
        db.commit()

    return {"network_devices": len(devices), "registered_assets": len(assets),
            "matched": matched, "unregistered_count": len(unregistered),
            "unregistered": unregistered[:500]}


@router.get("/export")
def export_assets(request: Request, db: Session = Depends(get_db),
                  current_user: User = Depends(require_permission("assets.manage"))):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EXPORT_HEADERS)
    rows = db.query(Asset).order_by(Asset.id).all()
    for a in rows:
        w.writerow(csv_safe_row([getattr(a, f) or "" for f in FIELDS]))
    _audit(db, request, current_user.email, "asset.export", "asset register", "SUCCESS", {"rows": len(rows)})
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=asset-register.csv"})


# ---------------------------------------------------------------- self-service (no login)
#
# A person on the office network opens /self-service and fills in who has the computer. They are
# recognised by their IP address, which is a convenience and not proof of identity - which is why this
# can only touch the four USER_FIELDS of a computer the monitor already knows, only from an internal
# address, and is rate limited and audited.

def _match_asset_for_ip(db: Session, ip: str, create: bool = False):
    """Find the asset for the visitor's IP: prefer an agent (Machine) by IP, else a scanned
    NetworkDevice by IP matched to an asset by hostname. Optionally create a stub asset, but only
    for a computer that is already known - an unknown address never creates anything."""
    machine = db.query(Machine).filter(Machine.ip_address == ip).first()
    device = db.query(NetworkDevice).filter(NetworkDevice.ip_address == ip).first()
    asset = None
    if machine:
        asset = db.query(Asset).filter(Asset.machine_id == machine.id).first()
        if not asset and create:
            asset = Asset(machine_id=machine.id, host_name=machine.hostname, created_at=_utcnow())
            db.add(asset); db.flush()
    if not asset and device and device.hostname:
        asset = db.query(Asset).filter(Asset.host_name == device.hostname).first()
    if not asset and create and (machine or device):
        host = (machine.hostname if machine else None) or (device.hostname if device else None) or ip
        asset = Asset(host_name=host, created_at=_utcnow())
        db.add(asset); db.flush()
    return asset, machine, device


def _self_service_guard(request: Request, limiter: SlidingWindowLimiter) -> str:
    ip = client_ip(request)
    if not is_internal_address(ip):
        raise HTTPException(status_code=403, detail="The self-service page is only available from inside the network.")
    if not limiter.allow(ip):
        raise HTTPException(status_code=429, detail="Too many requests; wait a minute and try again.")
    return ip


@router.get("/self")
def self_get(request: Request, db: Session = Depends(get_db)):
    ip = _self_service_guard(request, _self_read_limit)
    asset, machine, device = _match_asset_for_ip(db, ip, create=False)
    read_only = {
        "detected_ip": ip,
        "host_name": (asset.host_name if asset else (machine.hostname if machine else (device.hostname if device else ""))),
        "make": asset.make if asset else "",
        "model": asset.model if asset else "",
        "serial_no": asset.serial_no if asset else "",
        "processor_type": asset.processor_type if asset else "",
        "ram": asset.ram if asset else "",
        "hard_disk_size": asset.hard_disk_size if asset else "",
        "os_version": asset.os_version if asset else "",
        "os_architecture": asset.os_architecture if asset else "",
    }
    editable = {f: (getattr(asset, f) if asset else "") for f in USER_FIELDS}
    return {"found": bool(asset or machine or device), **read_only, **editable}


@router.post("/self")
def self_post(request: Request, payload: SelfUpdate, db: Session = Depends(get_db)):
    ip = _self_service_guard(request, _self_write_limit)
    asset, _machine, _device = _match_asset_for_ip(db, ip, create=True)
    if asset is None:
        raise HTTPException(status_code=404, detail="This computer is not known to the monitor yet, so it cannot be updated here.")
    changes = {k: (v.strip() if isinstance(v, str) else v)
               for k, v in payload.model_dump(exclude_unset=True).items() if k in USER_FIELDS}
    for k, v in changes.items():
        setattr(asset, k, v)
    db.commit()
    _audit(db, request, f"self-service:{ip}", "asset.self_update", f"asset #{asset.id}", "SUCCESS",
           {"host_name": asset.host_name, "fields": sorted(changes)})
    return {"status": "saved", "asset_id": asset.id}
