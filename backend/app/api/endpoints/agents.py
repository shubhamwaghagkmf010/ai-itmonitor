from typing import List, Optional, Any
from datetime import datetime, timezone, timedelta
import os
import io
import zipfile
from fastapi import APIRouter, Depends, HTTPException, status, Query, Header, Request
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from backend.app.core.database import get_db
from backend.app.models.entities import (
    Machine, MachineMetric, ProcessSnapshot, AgentCommand, MachineStatus, Incident, IncidentSeverity, IncidentStatus, User, ExtendedMetric, MachineInventory
)
from backend.app.api.deps import get_current_user, require_permission
from backend.app.core.config import settings

router = APIRouter()

def verify_agent_key(x_agent_key: Optional[str] = Header(default=None, alias="X-Agent-Key")):
    """Agents must present X-Agent-Key when AGENT_API_KEY is configured. When it is empty,
    enrolment is open (development only)."""
    expected = settings.AGENT_API_KEY
    if expected and x_agent_key != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing agent key")
    return True


class RegisterAgentPayload(BaseModel):
    hostname: str
    os_name: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    agent_version: str = "1.0.0"
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    logged_in_user: Optional[str] = "System"

class ProcessItem(BaseModel):
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    status: Optional[str] = "running"

class IngestMetricsPayload(BaseModel):
    agent_id: str
    logged_in_user: Optional[str] = "System"
    cpu_percent: float
    ram_percent: float
    ram_used_gb: float
    ram_total_gb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    bytes_sent: float = 0.0
    bytes_recv: float = 0.0
    packets_sent: int = 0
    packets_recv: int = 0
    top_processes: List[ProcessItem] = []
    services: Optional[Any] = None
    containers: Optional[Any] = None
    sensors: Optional[Any] = None
    disks_smart: Optional[Any] = None
    gpu: Optional[Any] = None
    drives: Optional[Any] = None

class RemoteActionPayload(BaseModel):
    command_type: str
    command_str: Optional[str] = None
    pid: Optional[int] = None

class CommandResultPayload(BaseModel):
    agent_id: str
    command_id: int
    status: str
    output: Optional[str] = None

@router.post("/register")
def register_agent(payload: RegisterAgentPayload, db: Session = Depends(get_db), _agent: bool = Depends(verify_agent_key)):
    machine = db.query(Machine).filter(Machine.hostname == payload.hostname).first()
    now = datetime.now(timezone.utc)
    if not machine:
        agent_id = f"AGENT-{payload.hostname.upper()}-{abs(hash(payload.hostname)) % 10000:04d}"
        machine = Machine(
            agent_id=agent_id,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            mac_address=payload.mac_address,
            logged_in_user=payload.logged_in_user or "System",
            os_name=payload.os_name,
            os_version=payload.os_version,
            architecture=payload.architecture,
            agent_version=payload.agent_version,
            status=MachineStatus.HEALTHY,
            last_heartbeat=now
        )
        db.add(machine)
    else:
        machine.ip_address = payload.ip_address
        if payload.mac_address:
            machine.mac_address = payload.mac_address
        machine.logged_in_user = payload.logged_in_user or machine.logged_in_user
        machine.os_name = payload.os_name
        machine.os_version = payload.os_version
        machine.architecture = payload.architecture
        machine.agent_version = payload.agent_version
        machine.last_heartbeat = now
        machine.status = MachineStatus.HEALTHY

    db.commit()
    db.refresh(machine)
    return {"status": "registered", "agent_id": machine.agent_id}

@router.post("/metrics")
def ingest_metrics(payload: IngestMetricsPayload, db: Session = Depends(get_db), _agent: bool = Depends(verify_agent_key)):
    machine = db.query(Machine).filter(Machine.agent_id == payload.agent_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Agent not registered")

    now = datetime.now(timezone.utc)
    machine.last_heartbeat = now
    machine.logged_in_user = payload.logged_in_user or machine.logged_in_user
    machine.status = MachineStatus.HEALTHY
    if payload.drives is not None:
        machine.drives = payload.drives

    metric = MachineMetric(
        machine_id=machine.id,
        cpu_percent=payload.cpu_percent,
        ram_percent=payload.ram_percent,
        ram_used_gb=payload.ram_used_gb,
        ram_total_gb=payload.ram_total_gb,
        disk_percent=payload.disk_percent,
        disk_used_gb=payload.disk_used_gb,
        disk_total_gb=payload.disk_total_gb,
        timestamp=now
    )
    db.add(metric)
    db.commit()
    db.refresh(metric)

    if any([payload.services, payload.containers, payload.sensors, payload.disks_smart, payload.gpu]):
        db.add(ExtendedMetric(
            machine_id=machine.id,
            services=payload.services,
            containers=payload.containers,
            sensors=payload.sensors,
            disks_smart=payload.disks_smart,
            gpu=payload.gpu,
            timestamp=now,
        ))
        db.commit()

    if payload.top_processes:
        db.query(ProcessSnapshot).filter(ProcessSnapshot.machine_id == machine.id).delete()
        for p in payload.top_processes:
            proc_entry = ProcessSnapshot(
                machine_id=machine.id,
                metric_id=metric.id,
                pid=p.pid,
                name=p.name,
                cpu_percent=p.cpu_percent,
                memory_percent=p.memory_percent,
                status=p.status,
                timestamp=now
            )
            db.add(proc_entry)
        db.commit()

    pending = db.query(AgentCommand).filter(
        AgentCommand.machine_id == machine.id,
        AgentCommand.status == "PENDING"
    ).all()

    cmds = []
    for c in pending:
        cmds.append({
            "command_id": c.id,
            "type": c.command_type,
            "payload": c.payload_json
        })
        c.status = "DISPATCHED"
    db.commit()

    return {"status": "ingested", "machine_status": machine.status.value, "pending_commands": cmds}

@router.get("/machines")
def get_machines(db: Session = Depends(get_db), current_user: User = Depends(require_permission("telemetry.view"))):
    machines = db.query(Machine).all()
    results = []
    now = datetime.now(timezone.utc)
    for m in machines:
        is_alive = bool(m.last_heartbeat and (now - m.last_heartbeat).total_seconds() < 20)
        curr_status = m.status.value if is_alive else "OFFLINE"
        results.append({
            "id": m.id,
            "agent_id": m.agent_id,
            "hostname": m.hostname,
            "ip_address": m.ip_address,
            "mac_address": m.mac_address,
            "logged_in_user": m.logged_in_user or "System",
            "os_name": m.os_name,
            "architecture": m.architecture,
            "agent_version": m.agent_version,
            "status": curr_status,
            "last_heartbeat": m.last_heartbeat.isoformat() if m.last_heartbeat else None
        })
    return results

@router.get("/machines/{machine_id}/metrics")
def get_metrics(machine_id: int, limit: int = 20, db: Session = Depends(get_db), current_user: User = Depends(require_permission("telemetry.view"))):
    metrics = db.query(MachineMetric).filter(
        MachineMetric.machine_id == machine_id
    ).order_by(MachineMetric.timestamp.desc()).limit(limit).all()
    metrics.reverse()
    rows = [
        {
            "id": m.id,
            "timestamp": m.timestamp.strftime("%H:%M:%S"),
            "cpu_percent": m.cpu_percent,
            "ram_percent": m.ram_percent,
            "ram_used_gb": m.ram_used_gb,
            "ram_total_gb": m.ram_total_gb,
            "disk_percent": m.disk_percent,
            "disk_used_gb": m.disk_used_gb,
            "disk_total_gb": m.disk_total_gb
        }
        for m in metrics
    ]
    if rows:
        machine = db.query(Machine).filter(Machine.id == machine_id).first()
        rows[-1]["drives"] = machine.drives if (machine and machine.drives) else None
    return rows

@router.get("/machines/{machine_id}/processes")
def get_processes(machine_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_permission("processes.view"))):
    procs = db.query(ProcessSnapshot).filter(
        ProcessSnapshot.machine_id == machine_id
    ).order_by(ProcessSnapshot.cpu_percent.desc(), ProcessSnapshot.memory_percent.desc()).limit(50).all()
    return [
        {
            "id": p.id,
            "pid": p.pid,
            "name": p.name,
            "cpu_percent": p.cpu_percent,
            "memory_percent": p.memory_percent,
            "status": p.status
        }
        for p in procs
    ]

@router.post("/machines/{machine_id}/kill-process")
def kill_process(machine_id: int, pid: int = Query(...), db: Session = Depends(get_db), current_user: User = Depends(require_permission("processes.kill"))):
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    cmd = AgentCommand(
        machine_id=machine.id,
        command_type="KILL_PROCESS",
        payload_json={"pid": pid},
        status="PENDING"
    )
    db.add(cmd)
    db.commit()
    return {"status": "dispatched", "message": f"Kill signal queued for PID {pid}"}

@router.post("/machines/{machine_id}/remote-action")
def send_remote_action(machine_id: int, payload: RemoteActionPayload, db: Session = Depends(get_db), current_user: User = Depends(require_permission("remote_ops.execute"))):
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    cmd = AgentCommand(
        machine_id=machine.id,
        command_type=payload.command_type,
        payload_json={"command_str": payload.command_str, "pid": payload.pid},
        status="PENDING"
    )
    db.add(cmd)
    db.commit()
    db.refresh(cmd)
    return {"status": "dispatched", "command_id": cmd.id}

@router.get("/machines/{machine_id}/command-output/{command_id}")
def get_command_output(machine_id: int, command_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_permission("remote_ops.execute"))):
    cmd = db.query(AgentCommand).filter(
        AgentCommand.id == command_id,
        AgentCommand.machine_id == machine_id
    ).first()
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")
    return {"command_id": cmd.id, "status": cmd.status, "output": cmd.result_output or "Executing on remote host..."}

@router.post("/command-result")
def receive_command_result(payload: CommandResultPayload, db: Session = Depends(get_db), _agent: bool = Depends(verify_agent_key)):
    cmd = db.query(AgentCommand).filter(AgentCommand.id == payload.command_id).first()
    if cmd:
        cmd.status = payload.status
        cmd.result_output = payload.output
        cmd.executed_at = datetime.now(timezone.utc)
        db.commit()
    return {"status": "acknowledged"}


@router.get("/machines/{machine_id}/extended")
def get_extended_metrics(machine_id: int, db: Session = Depends(get_db),
                         current_user: User = Depends(require_permission("telemetry.view"))):
    """Latest extended telemetry (services, containers, sensors, SMART, GPU) for a machine."""
    row = (db.query(ExtendedMetric)
             .filter(ExtendedMetric.machine_id == machine_id)
             .order_by(ExtendedMetric.timestamp.desc())
             .first())
    if not row:
        return {"machine_id": machine_id, "services": None, "containers": None,
                "sensors": None, "disks_smart": None, "gpu": None, "timestamp": None}
    return {
        "machine_id": machine_id,
        "services": row.services,
        "containers": row.containers,
        "sensors": row.sensors,
        "disks_smart": row.disks_smart,
        "gpu": row.gpu,
        "timestamp": row.timestamp,
    }


@router.get("/machines/{machine_id}/history")
def get_metric_history(machine_id: int, hours: int = 24,
                       db: Session = Depends(get_db),
                       current_user: User = Depends(require_permission("telemetry.view"))):
    """CPU/RAM/disk over a time window. Short ranges return raw points; longer ranges are
    downsampled (hourly, then daily) so the chart stays readable over weeks."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    if hours <= 6:
        rows = (db.query(MachineMetric)
                  .filter(MachineMetric.machine_id == machine_id, MachineMetric.timestamp >= since)
                  .order_by(MachineMetric.timestamp.asc()).all())
        return [{"timestamp": r.timestamp.strftime("%H:%M"),
                 "cpu_percent": round(r.cpu_percent, 1),
                 "ram_percent": round(r.ram_percent, 1),
                 "disk_percent": round(r.disk_percent, 1)} for r in rows]

    bucket = "hour" if hours <= 48 else "day"
    trunc = func.date_trunc(bucket, MachineMetric.timestamp)
    rows = (db.query(trunc.label("b"),
                     func.avg(MachineMetric.cpu_percent),
                     func.avg(MachineMetric.ram_percent),
                     func.avg(MachineMetric.disk_percent))
              .filter(MachineMetric.machine_id == machine_id, MachineMetric.timestamp >= since)
              .group_by(trunc).order_by(trunc).all())
    fmt = "%m-%d %H:%M" if bucket == "hour" else "%m-%d"
    return [{"timestamp": b.strftime(fmt),
             "cpu_percent": round(c or 0, 1),
             "ram_percent": round(r or 0, 1),
             "disk_percent": round(d or 0, 1)} for b, c, r, d in rows]


class InventoryPayload(BaseModel):
    agent_id: str
    hardware: Optional[Any] = None
    software: Optional[Any] = None


@router.post("/inventory")
def ingest_inventory(payload: InventoryPayload, db: Session = Depends(get_db),
                     _agent: bool = Depends(verify_agent_key)):
    machine = db.query(Machine).filter(Machine.agent_id == payload.agent_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Agent not registered")
    sw_count = len(payload.software) if isinstance(payload.software, list) else 0
    now = datetime.now(timezone.utc)
    inv = db.query(MachineInventory).filter(MachineInventory.machine_id == machine.id).first()
    if inv:
        inv.hardware = payload.hardware
        inv.software = payload.software
        inv.software_count = sw_count
        inv.collected_at = now
    else:
        db.add(MachineInventory(machine_id=machine.id, hardware=payload.hardware,
                                software=payload.software, software_count=sw_count, collected_at=now))
    db.commit()
    return {"status": "inventory stored", "software_count": sw_count}


@router.get("/machines/{machine_id}/inventory")
def get_inventory(machine_id: int, db: Session = Depends(get_db),
                  current_user: User = Depends(require_permission("telemetry.view"))):
    inv = db.query(MachineInventory).filter(MachineInventory.machine_id == machine_id).first()
    if not inv:
        return {"machine_id": machine_id, "hardware": None, "software": [], "software_count": 0, "collected_at": None}
    return {"machine_id": machine_id, "hardware": inv.hardware, "software": inv.software or [],
            "software_count": inv.software_count, "collected_at": inv.collected_at}


@router.get("/software/search")
def software_search(q: str, db: Session = Depends(get_db),
                    current_user: User = Depends(require_permission("telemetry.view"))):
    """Find which machines have a package matching q (name contains q)."""
    ql = (q or "").lower().strip()
    if not ql:
        return []
    results = []
    for inv in db.query(MachineInventory).all():
        machine = db.query(Machine).filter(Machine.id == inv.machine_id).first()
        for pkg in (inv.software or []):
            if ql in (pkg.get("name", "") or "").lower():
                results.append({
                    "machine_id": inv.machine_id,
                    "hostname": machine.hostname if machine else "",
                    "name": pkg.get("name"), "version": pkg.get("version"),
                })
    return results[:500]


# The packaged Windows/cross-platform agent, downloadable without auth so it is easy to
# roll out to endpoints (it contains no secrets — only the server URL, set at run time).
_AGENT_BUNDLE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "agent_dist", "ai-itmonitor-agent.zip"))


_AGENT_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "agent"))
_AGENT_PKG = os.path.join(_AGENT_SRC, "_pkg")


def _agent_files():
    out = {}
    base = os.path.dirname(_AGENT_SRC)
    for root, _dirs, names in os.walk(_AGENT_SRC):
        if "__pycache__" in root or (os.sep + "_pkg") in (root + os.sep):
            continue
        for n in names:
            if n.endswith(".pyc"):
                continue
            full = os.path.join(root, n)
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            with open(full, "rb") as fh:
                out[rel] = fh.read()
    return out


def _tpl(name, server_url):
    with open(os.path.join(_AGENT_PKG, name), encoding="utf-8") as fh:
        return fh.read().replace("__SERVER_URL__", server_url)


@router.get("/download")
def download_agent(request: Request, os_name: str = Query("linux", alias="os")):
    if not os.path.isdir(_AGENT_SRC):
        raise HTTPException(status_code=404, detail="Agent source not found on the server.")
    host = request.headers.get("host", "")
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    server_url = scheme + "://" + host + "/api/v1/agents"
    target = (os_name or "linux").lower()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rel, data in _agent_files().items():
            z.writestr(rel, data)
        z.writestr("requirements.txt", "httpx\npsutil\n")
        z.writestr("README.txt", _tpl("README.txt", server_url))
        if target == "windows":
            z.writestr("run.bat", _tpl("run.bat", server_url))
            fname = "ai-itmonitor-agent-windows.zip"
        else:
            z.writestr("run.sh", _tpl("run.sh", server_url))
            z.writestr("install-ubuntu.sh", _tpl("install-ubuntu.sh", server_url))
            fname = "ai-itmonitor-agent-linux.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="' + fname + '"'},
    )
