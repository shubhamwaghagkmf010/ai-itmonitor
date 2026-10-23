from typing import List, Optional, Any
from datetime import datetime, timezone, timedelta
import os
import re
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
from backend.app.ai.ollama_service import analyze_app_health_with_ai
from backend.app.ai.ollama_service import analyze_slowness_with_ai

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
    machine_uid: Optional[str] = None

class ProcessItem(BaseModel):
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    status: Optional[str] = "running"

class IngestMetricsPayload(BaseModel):
    agent_id: str
    logged_in_user: Optional[str] = "System"
    mac_address: Optional[str] = None
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
    now = datetime.now(timezone.utc)
    uid = (payload.machine_uid or "").strip()
    if uid:
        agent_id = f"AGENT-{payload.hostname.upper()}-{uid[:8].upper()}"
        machine = db.query(Machine).filter(Machine.agent_id == agent_id).first()
    else:
        agent_id = f"AGENT-{payload.hostname.upper()}-{abs(hash(payload.hostname)) % 10000:04d}"
        machine = db.query(Machine).filter(Machine.hostname == payload.hostname).first()
    if not machine:
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
    if payload.mac_address and not machine.mac_address:
        machine.mac_address = payload.mac_address.upper()
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

    return {"status": "ingested", "machine_status": machine.status.value,
            "pending_commands": cmds, "latest_agent_version": _latest_agent_version(),
            "https_hint": settings.PUBLIC_HTTPS_BASE_URL}

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


# Friendly names for common applications (lower-cased exe -> display name)
_APP_NAMES = {
    "code.exe": "Visual Studio Code", "code - insiders.exe": "VS Code Insiders",
    "eclipse.exe": "Eclipse IDE", "javaw.exe": "Java (javaw)", "java.exe": "Java",
    "idea64.exe": "IntelliJ IDEA", "pycharm64.exe": "PyCharm", "studio64.exe": "Android Studio",
    "devenv.exe": "Visual Studio", "ssms.exe": "SQL Server Mgmt Studio",
    "chrome.exe": "Google Chrome", "msedge.exe": "Microsoft Edge",
    "msedgewebview2.exe": "Edge WebView2 Runtime", "firefox.exe": "Mozilla Firefox",
    "node.exe": "Node.js", "python.exe": "Python", "python3.exe": "Python",
    "explorer.exe": "Windows Explorer", "dwm.exe": "Desktop Window Manager",
    "msmpeng.exe": "Microsoft Defender", "svchost.exe": "Windows Service Host",
    "outlook.exe": "Microsoft Outlook", "teams.exe": "Microsoft Teams",
    "ms-teams.exe": "Microsoft Teams", "winword.exe": "Microsoft Word",
    "excel.exe": "Microsoft Excel", "powerpnt.exe": "Microsoft PowerPoint",
    "onedrive.exe": "OneDrive", "slack.exe": "Slack", "docker.exe": "Docker",
    "postman.exe": "Postman", "ultraviewer_desktop.exe": "UltraViewer",
}


def _app_display_name(raw: str) -> str:
    if not raw:
        return "Unknown"
    key = raw.strip().lower()
    if key in _APP_NAMES:
        return _APP_NAMES[key]
    base = raw[:-4] if key.endswith(".exe") else raw
    return base if base.isupper() else base.replace("_", " ").title()


@router.get("/machines/{machine_id}/app-monitor")
def app_monitor(machine_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(require_permission("processes.view"))):
    """Group the newest process snapshot by application and classify each as
    active / idle / unresponsive, with combined CPU & RAM and a plain-language
    explanation of why a heavy app is consuming resources."""
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    latest = db.query(func.max(ProcessSnapshot.timestamp)).filter(
        ProcessSnapshot.machine_id == machine_id).scalar()
    if not latest:
        return {"machine_id": machine_id, "hostname": machine.hostname,
                "as_of": None, "summary": {"active": 0, "idle": 0, "unresponsive": 0, "apps": 0},
                "apps": []}

    rows = db.query(ProcessSnapshot).filter(
        ProcessSnapshot.machine_id == machine_id,
        ProcessSnapshot.timestamp == latest).all()

    ACTIVE_CPU = 1.0  # percent; at/above this a process counts as "active"

    def classify(status: str, cpu: float) -> str:
        st = (status or "").lower()
        if "not responding" in st or "zombie" in st:
            return "unresponsive"
        if (cpu or 0) >= ACTIVE_CPU:
            return "active"
        return "idle"

    groups = {}
    for r in rows:
        name = _app_display_name(r.name)
        g = groups.setdefault(name, {
            "app": name, "instances": 0, "cpu": 0.0, "mem": 0.0,
            "max_cpu": 0.0, "max_mem": 0.0, "pids": [],
            "active": 0, "idle": 0, "unresponsive": 0, "raw": r.name})
        st = classify(r.status, r.cpu_percent)
        g["instances"] += 1
        g["cpu"] += r.cpu_percent or 0.0
        g["mem"] += r.memory_percent or 0.0
        g["max_cpu"] = max(g["max_cpu"], r.cpu_percent or 0.0)
        g["max_mem"] = max(g["max_mem"], r.memory_percent or 0.0)
        g[st] += 1
        if len(g["pids"]) < 12:
            g["pids"].append(r.pid)

    def state_of(g) -> str:
        if g["unresponsive"]:
            return "unresponsive"
        if g["active"]:
            return "active"
        return "idle"

    def reasons(g, state) -> list:
        out = []
        cpu, mem, n, mx = round(g["cpu"], 1), round(g["mem"], 1), g["instances"], round(g["max_cpu"], 1)
        if state == "unresponsive":
            out.append("Window is hung (Not Responding) - app is stuck waiting on I/O, "
                       "a locked resource or a long operation. End the task if it stays hung.")
        if n >= 10:
            out.append(f"{n} processes - a multi-process app (browser / Electron / WebView2). "
                       "Each tab, pane or extension is its own process, so many open items inflate the total.")
        if mx >= 25:
            out.append(f"One process is using ~{mx}% CPU on its own - likely a heavy task "
                       "(build/compile, a running query, indexing, or a busy loop).")
        elif cpu >= 15 and n == 1:
            out.append(f"This process is using ~{cpu}% CPU - a heavy task "
                       "(a running query, a build/compile, or indexing).")
        elif cpu >= 15:
            out.append(f"~{cpu}% CPU spread across {n} processes - sustained background work.")
        if mem >= 10:
            out.append(f"~{mem}% of RAM across {n} process(es) - large working set "
                       "(many tabs, a big heap, or large files open).")
        if not out:
            out.append("Usage is within a normal range.")
        return out

    apps = []
    for g in groups.values():
        state = state_of(g)
        cpu, mem = round(g["cpu"], 1), round(g["mem"], 1)
        heavy = state == "unresponsive" or cpu >= 15 or mem >= 10 or g["instances"] >= 15 or g["max_cpu"] >= 25
        apps.append({
            "app": g["app"], "process": g["raw"], "instances": g["instances"],
            "cpu_percent": cpu, "mem_percent": mem,
            "max_cpu": round(g["max_cpu"], 1), "max_mem": round(g["max_mem"], 1),
            "state": state, "heavy": heavy,
            "counts": {"active": g["active"], "idle": g["idle"], "unresponsive": g["unresponsive"]},
            "pids": g["pids"],
            "reasons": reasons(g, state) if heavy else [],
        })

    apps.sort(key=lambda a: (a["state"] == "unresponsive", a["cpu_percent"], a["mem_percent"]), reverse=True)
    summary = {
        "active": sum(a["counts"]["active"] for a in apps),
        "idle": sum(a["counts"]["idle"] for a in apps),
        "unresponsive": sum(a["counts"]["unresponsive"] for a in apps),
        "apps": len(apps),
    }
    return {"machine_id": machine_id, "hostname": machine.hostname,
            "as_of": latest.isoformat(), "summary": summary, "apps": apps}


# System / critical processes we never offer to kill from a suggested fix.
_CRITICAL_PROCS = {
    "system", "svchost.exe", "services.exe", "lsass.exe", "wininit.exe",
    "csrss.exe", "smss.exe", "winlogon.exe", "explorer.exe", "dwm.exe",
    "msmpeng.exe", "registry", "memcompression", "fontdrvhost.exe",
    "systemd", "init", "kthreadd",
}
_SEV_WEIGHT = {"high": 3, "medium": 2, "info": 1}


@router.post("/machines/{machine_id}/app-analyze")
def app_analyze(machine_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(require_permission("incidents.analyze"))):
    """AI-assisted application root-cause analysis with guided, approve-then-apply
    fixes. The AI explains the cause; the executable fixes are built here (trusted)
    and run only when a user clicks Apply (which dispatches a normal remote action)."""
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    mon = app_monitor(machine_id, db=db, current_user=current_user)
    apps = mon.get("apps", [])
    latest = db.query(func.max(ProcessSnapshot.timestamp)).filter(
        ProcessSnapshot.machine_id == machine_id).scalar()

    met = db.query(MachineMetric).filter(MachineMetric.machine_id == machine_id)\
        .order_by(MachineMetric.timestamp.desc()).first()
    host = {
        "cpu": round(met.cpu_percent, 1) if met else None,
        "ram": round(met.ram_percent, 1) if met else None,
        "disk": round(met.disk_percent, 1) if met else None,
    }

    def top_proc(raw_name):
        r = db.query(ProcessSnapshot).filter(
            ProcessSnapshot.machine_id == machine_id,
            ProcessSnapshot.timestamp == latest,
            ProcessSnapshot.name == raw_name
        ).order_by(ProcessSnapshot.cpu_percent.desc()).first()
        return r

    fixes = []
    for a in apps:
        if not (a.get("heavy") or a.get("state") == "unresponsive"):
            continue
        raw = (a.get("process") or "").lower()
        is_critical = raw in _CRITICAL_PROCS
        tp = top_proc(a.get("process"))
        pid = tp.pid if tp else None

        if a.get("state") == "unresponsive" and pid and not is_critical:
            fixes.append({
                "app": a["app"], "severity": "high", "risk": "medium",
                "title": f"End unresponsive {a['app']} (PID {pid})",
                "rationale": "The application window is hung (Not Responding). Ending it frees the "
                             "resources it is holding. Any unsaved work inside that app may be lost.",
                "action": {"command_type": "KILL_PROCESS", "pid": pid},
                "command_preview": f"End process PID {pid} ({a.get('process')})",
            })
        elif a.get("max_cpu", 0) >= 50 and pid and not is_critical:
            fixes.append({
                "app": a["app"], "severity": "high", "risk": "high",
                "title": f"Stop high-CPU process {a['app']} (PID {pid})",
                "rationale": f"A single {a.get('process')} process is using ~{a.get('max_cpu')}% CPU. If this is "
                             "not expected work (a build/query/indexing), ending it will relieve the CPU. "
                             "Confirm with the user first - ending a working app can lose data.",
                "action": {"command_type": "KILL_PROCESS", "pid": pid},
                "command_preview": f"End process PID {pid} ({a.get('process')})",
            })
        elif a.get("instances", 0) >= 15 and a.get("mem_percent", 0) >= 15:
            fixes.append({
                "app": a["app"], "severity": "medium", "risk": "info",
                "title": f"Reduce {a['app']} footprint",
                "rationale": f"{a['app']} is running {a.get('instances')} processes and holding "
                             f"~{a.get('mem_percent')}% of RAM. Closing unused tabs/windows (or restarting the "
                             "app) is the safest way to recover memory. No remote command is applied automatically.",
                "action": None,
                "command_preview": None,
            })
        elif is_critical:
            fixes.append({
                "app": a["app"], "severity": "info", "risk": "info",
                "title": f"{a['app']} is busy (system component)",
                "rationale": f"{a['app']} is a Windows system component using ~{a.get('cpu_percent')}% CPU / "
                             f"~{a.get('mem_percent')}% RAM. It is not safe to end it directly; if it stays high, "
                             "a reboot or a targeted service restart is the correct remedy.",
                "action": None, "command_preview": None,
            })
        else:
            fixes.append({
                "app": a["app"], "severity": "medium", "risk": "info",
                "title": f"Monitor {a['app']}",
                "rationale": f"{a['app']} is using ~{a.get('cpu_percent')}% CPU / ~{a.get('mem_percent')}% RAM. "
                             "If it stays elevated, inspect the in-app task driving it.",
                "action": None, "command_preview": None,
            })

    fixes.sort(key=lambda f: _SEV_WEIGHT.get(f["severity"], 0), reverse=True)
    fixes = fixes[:10]

    heavy_compact = [{
        "app": a["app"], "state": a["state"], "cpu": a["cpu_percent"],
        "mem": a["mem_percent"], "instances": a["instances"],
    } for a in apps if a.get("heavy") or a.get("state") == "unresponsive"][:6]

    ai = analyze_app_health_with_ai({
        "hostname": machine.hostname, "os_name": machine.os_name,
        "host": host, "heavy_apps": heavy_compact,
    })

    return {
        "machine_id": machine_id, "hostname": machine.hostname,
        "as_of": latest.isoformat() if latest else None,
        "host": host, "summary": mon.get("summary"),
        "root_cause": ai, "fixes": fixes,
    }


@router.post("/machines/{machine_id}/diagnose")
def diagnose_slowness(machine_id: int, db: Session = Depends(get_db),
                      current_user: User = Depends(require_permission("incidents.analyze"))):
    """Explain WHY a node is slow/hanging even when the overview looks normal.
    Reads the latest stored metrics and process snapshot, surfaces the specific
    bottleneck (single-core peg, memory pressure, disk-full, hung apps, process
    storm), narrates the root cause with the local AI, and offers guided,
    approve-then-apply fixes. For disk I/O (which the dashboard does not store),
    the UI can also dispatch a live DIAGNOSE_SYSTEM deep scan."""
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    met = db.query(MachineMetric).filter(MachineMetric.machine_id == machine_id)\
        .order_by(MachineMetric.timestamp.desc()).first()
    host = {
        "cpu": round(met.cpu_percent, 1) if met else None,
        "ram": round(met.ram_percent, 1) if met else None,
        "disk": round(met.disk_percent, 1) if met else None,
    }

    latest = db.query(func.max(ProcessSnapshot.timestamp)).filter(
        ProcessSnapshot.machine_id == machine_id).scalar()
    procs = []
    if latest:
        procs = db.query(ProcessSnapshot).filter(
            ProcessSnapshot.machine_id == machine_id,
            ProcessSnapshot.timestamp == latest).all()

    def is_crit(name):
        return (name or "").lower() in _CRITICAL_PROCS

    findings, fixes = [], []

    # 1) hung / Not Responding windows
    hung = [pr for pr in procs if "not responding" in (pr.status or "").lower()
            or (pr.status or "").lower() == "zombie"]
    for pr in hung[:5]:
        findings.append({
            "severity": "high",
            "title": f"{pr.name} is not responding (hung)",
            "detail": f"PID {pr.pid} has stopped responding. A hung window often blocks on disk or "
                      "network I/O and can freeze the desktop.",
        })
        if not is_crit(pr.name):
            fixes.append({
                "app": pr.name, "severity": "high", "risk": "medium",
                "title": f"End unresponsive {pr.name} (PID {pr.pid})",
                "rationale": "The window is hung. Ending it frees what it holds; unsaved work in that app may be lost.",
                "action": {"command_type": "KILL_PROCESS", "pid": pr.pid},
                "command_preview": f"End process PID {pr.pid} ({pr.name})",
            })

    # 2) single process pegging CPU (classic: overview CPU low, one core maxed)
    runaway = sorted([pr for pr in procs if (pr.cpu_percent or 0) >= 80],
                     key=lambda r: r.cpu_percent or 0, reverse=True)
    for pr in runaway[:4]:
        crit = is_crit(pr.name)
        findings.append({
            "severity": "high",
            "title": f"{pr.name} is using ~{round(pr.cpu_percent,1)}% CPU",
            "detail": f"PID {pr.pid} is a heavy CPU consumer. If this is not expected work "
                      "(a build/query/scan), it is the likely reason the machine feels slow.",
        })
        if not crit:
            fixes.append({
                "app": pr.name, "severity": "high", "risk": "high",
                "title": f"Stop high-CPU {pr.name} (PID {pr.pid})",
                "rationale": f"{pr.name} is pegging the CPU at ~{round(pr.cpu_percent,1)}%. Confirm with the user "
                             "first - ending a working app can lose data.",
                "action": {"command_type": "KILL_PROCESS", "pid": pr.pid},
                "command_preview": f"End process PID {pr.pid} ({pr.name})",
            })
        else:
            fixes.append({
                "app": pr.name, "severity": "medium", "risk": "info",
                "title": f"{pr.name} (system component) is busy",
                "rationale": f"{pr.name} is a Windows system process using ~{round(pr.cpu_percent,1)}% CPU. Do not end "
                             "it directly; if it stays high a reboot or a targeted service restart is the right remedy.",
                "action": None, "command_preview": None,
            })

    # 3) host-level signals
    if host["cpu"] is not None and host["cpu"] >= 85:
        findings.append({
            "severity": "high" if host["cpu"] >= 95 else "medium",
            "title": f"Overall CPU is high ({host['cpu']}%)",
            "detail": "Sustained high total CPU makes everything sluggish. See the top consumers above.",
        })
    if host["ram"] is not None and host["ram"] >= 88:
        findings.append({
            "severity": "high" if host["ram"] >= 95 else "medium",
            "title": f"Memory is nearly full ({host['ram']}%)",
            "detail": "Low free RAM forces the system to page to disk (pagefile thrashing), which slows the whole machine.",
        })
        fixes.append({
            "app": "Memory", "severity": "medium", "risk": "info",
            "title": "Relieve memory pressure",
            "rationale": "Close unused apps/browser tabs, or reboot. If this recurs, the machine likely needs more RAM.",
            "action": None, "command_preview": None,
        })
    if host["disk"] is not None and host["disk"] >= 90:
        findings.append({
            "severity": "high" if host["disk"] >= 97 else "medium",
            "title": f"System disk is almost full ({host['disk']}%)",
            "detail": "A nearly full system disk slows Windows (no room for pagefile/temp) and can cause stalls.",
        })
        fixes.append({
            "app": "Disk", "severity": "medium", "risk": "info",
            "title": "Free up disk space",
            "rationale": "Clear temp files/Recycle Bin, run Disk Cleanup, or move large files off C:.",
            "action": None, "command_preview": None,
        })

    # 4) process storm
    if len(procs) >= 250:
        findings.append({
            "severity": "info",
            "title": f"{len(procs)} processes are running",
            "detail": "A very large process count adds scheduling and memory overhead; review startup apps.",
        })

    sev_rank = {"high": 3, "medium": 2, "info": 1}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)
    fixes.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)
    fixes = fixes[:10]

    ai = analyze_slowness_with_ai({
        "hostname": machine.hostname, "os_name": machine.os_name,
        "host": host, "findings": findings[:8],
    })

    return {
        "machine_id": machine_id, "hostname": machine.hostname,
        "as_of": latest.isoformat() if latest else None,
        "host": host, "metric_age": (met.timestamp.isoformat() if met else None),
        "process_count": len(procs),
        "findings": findings, "root_cause": ai, "fixes": fixes,
    }

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


def _latest_agent_version():
    """The version the server considers current - read live from agent/version.py,
    the same file packaged into /download. Bumping it there makes every agent
    auto-update. Falls back to 0.0.0 if it cannot be read."""
    try:
        with open(os.path.join(_AGENT_SRC, "version.py"), encoding="utf-8") as fh:
            m = re.search(r'AGENT_VERSION\s*=\s*["\']([^"\']+)["\']', fh.read())
            if m:
                return m.group(1)
    except Exception:
        pass
    return "0.0.0"



class SetMacPayload(BaseModel):
    mac_address: str

@router.post("/machines/{machine_id}/set-mac")
def set_machine_mac(machine_id: int, payload: SetMacPayload, db: Session = Depends(get_db),
                    current_user: User = Depends(require_permission("wol.manage"))):
    """Manually set/correct a machine's physical MAC address (for nodes an agent
    cannot auto-detect, or to override a wrong value)."""
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    mac = (payload.mac_address or "").strip().upper().replace("-", ":")
    if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
        raise HTTPException(status_code=400, detail="Invalid MAC address. Use AA:BB:CC:DD:EE:FF")
    machine.mac_address = mac
    db.commit()
    return {"status": "updated", "mac_address": mac}


@router.delete("/machines/{machine_id}")
def delete_machine(machine_id: int, db: Session = Depends(get_db),
                   current_user: User = Depends(require_permission("wol.manage"))):
    """Remove a monitored node and all of its telemetry, incidents and commands.
    Used to clean up duplicate or decommissioned machines. Child rows are removed
    via ON DELETE CASCADE. If an agent is still running on that host it will
    re-register as a node again on its next check-in."""
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    hostname = machine.hostname
    db.delete(machine)
    db.commit()
    return {"status": "deleted", "machine_id": machine_id, "hostname": hostname}

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


@router.get("/version")
def agent_latest_version():
    """The current agent version the server is serving. Agents poll this as an
    hourly fallback; the same value also rides every /metrics heartbeat."""
    return {"version": _latest_agent_version()}


@router.post("/push-update")
def push_agent_update(machine_id: Optional[int] = Query(None), db: Session = Depends(get_db),
                      current_user: User = Depends(require_permission("wol.manage"))):
    """Tell agents to update to the latest version NOW, without waiting for their
    next version check. Queues an UPDATE_AGENT command (delivered on the next
    ~10s heartbeat). Pass machine_id to target one node, or omit for all."""
    q = db.query(Machine)
    if machine_id is not None:
        q = q.filter(Machine.id == machine_id)
    machines = q.all()
    n = 0
    for m in machines:
        db.add(AgentCommand(machine_id=m.id, command_type="UPDATE_AGENT",
                            payload_json={}, status="PENDING"))
        n += 1
    db.commit()
    return {"status": "queued", "agents": n, "latest_version": _latest_agent_version()}
