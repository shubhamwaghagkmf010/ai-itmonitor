from datetime import datetime, timezone
from typing import Optional
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.entities import Asset, Machine, MachineInventory, NetworkDevice, User
from backend.app.api.deps import require_permission

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


def _utcnow():
    return datetime.now(timezone.utc)


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


class AssetIn(BaseModel):
    asset_no: Optional[str] = None
    category: Optional[str] = None
    sub_category: Optional[str] = None
    host_name: Optional[str] = None
    make: Optional[str] = None
    model: Optional[str] = None
    allocation_type: Optional[str] = None
    allocation_purpose: Optional[str] = None
    owned_by_emp_id: Optional[str] = None
    owned_by_emp_name: Optional[str] = None
    workstation_number: Optional[str] = None
    serial_no: Optional[str] = None
    processor_type: Optional[str] = None
    ram: Optional[str] = None
    hard_disk_size: Optional[str] = None
    os_architecture: Optional[str] = None
    os_version: Optional[str] = None
    os_edition: Optional[str] = None
    license_key: Optional[str] = None
    warranty_start: Optional[str] = None
    warranty_end: Optional[str] = None


class SelfUpdate(BaseModel):
    owned_by_emp_id: Optional[str] = None
    owned_by_emp_name: Optional[str] = None
    workstation_number: Optional[str] = None
    allocation_purpose: Optional[str] = None


def _serialize(a: Asset):
    d = {f: getattr(a, f) for f in FIELDS}
    d["id"] = a.id
    d["machine_id"] = a.machine_id
    return d


# ---------------------------------------------------------------- admin CRUD

@router.get("")
@router.get("/")
def list_assets(db: Session = Depends(get_db),
                current_user: User = Depends(require_permission("telemetry.view"))):
    return [_serialize(a) for a in db.query(Asset).order_by(Asset.id).all()]


@router.post("")
@router.post("/")
def create_asset(payload: AssetIn, db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("telemetry.view"))):
    a = Asset(created_at=_utcnow(), **payload.model_dump())
    db.add(a)
    db.commit()
    db.refresh(a)
    return _serialize(a)


@router.patch("/{asset_id}")
def update_asset(asset_id: int, payload: AssetIn, db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("telemetry.view"))):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(a, k, v)
    db.commit()
    return _serialize(a)


@router.delete("/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db),
                 current_user: User = Depends(require_permission("telemetry.view"))):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if a:
        db.delete(a)
        db.commit()
    return {"deleted": asset_id}


@router.post("/sync")
def sync_from_agents(db: Session = Depends(get_db),
                     current_user: User = Depends(require_permission("telemetry.view"))):
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
             current_user: User = Depends(require_permission("telemetry.view"))):
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
def export_assets(db: Session = Depends(get_db),
                  current_user: User = Depends(require_permission("telemetry.view"))):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EXPORT_HEADERS)
    for a in db.query(Asset).order_by(Asset.id).all():
        w.writerow([getattr(a, f) or "" for f in FIELDS])
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=asset-register.csv"})


# ---------------------------------------------------------------- self-service (no auth)

def _match_asset_for_ip(db: Session, ip: str, create: bool = False):
    """Find the asset for the visitor's IP: prefer an agent (Machine) by IP, else a scanned
    NetworkDevice by IP matched to an asset by hostname. Optionally create a stub asset."""
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
    if not asset and create:
        host = (machine.hostname if machine else None) or (device.hostname if device else None) or ip
        asset = Asset(host_name=host, created_at=_utcnow())
        db.add(asset); db.flush()
    return asset, machine, device


@router.get("/self")
def self_get(request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)
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
    ip = _client_ip(request)
    asset, _machine, _device = _match_asset_for_ip(db, ip, create=True)
    for k, v in payload.model_dump(exclude_unset=True).items():
        if k in USER_FIELDS:
            setattr(asset, k, v)
    db.commit()
    return {"status": "saved", "asset_id": asset.id}
