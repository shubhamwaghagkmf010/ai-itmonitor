"""Rule-based diagnostic scan: inspects a machine's stored telemetry and returns a
list of findings (storage, sustained CPU/RAM, process hogs, config gaps) with
OS-aware remediation commands. Pure stdlib + the ORM — no paid services."""
from datetime import datetime, timezone, timedelta
from backend.app.models.entities import MachineMetric, ProcessSnapshot

CPU_HIGH = 85.0
RAM_HIGH = 85.0
DISK_CRIT = 90.0
DISK_HIGH = 80.0
DISK_MED = 70.0
PROC_CPU_HIGH = 70.0
PROC_MEM_HIGH = 20.0
SUSTAIN_WINDOW_MIN = 60


def _is_windows(machine):
    return (machine.os_name or "").lower().startswith("win")


def _disk_cleanup(machine):
    if _is_windows(machine):
        return [
            "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object FullName,@{n='MB';e={[int]($_.Length/1MB)}} -First 20",
            "Remove-Item -Path $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue",
            "cleanmgr /sagerun:1",
        ]
    return [
        "du -xh / 2>/dev/null | sort -rh | head -20",
        "sudo apt-get clean && sudo apt-get autoremove -y",
        "sudo journalctl --vacuum-time=3d",
    ]


def _cpu_inspect(machine):
    if _is_windows(machine):
        return ["Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,CPU"]
    return ["ps -eo pid,comm,%cpu --sort=-%cpu | head -10"]


def _mem_inspect(machine):
    if _is_windows(machine):
        return ["Get-Process | Sort-Object WS -Descending | Select-Object -First 10 Name,Id,@{n='MB';e={[int]($_.WS/1MB)}}"]
    return ["ps -eo pid,comm,%mem --sort=-%mem | head -10"]


def run_diagnostic_scan(db, machine):
    now = datetime.now(timezone.utc)
    latest = (db.query(MachineMetric)
              .filter(MachineMetric.machine_id == machine.id)
              .order_by(MachineMetric.timestamp.desc()).first())
    since = now - timedelta(minutes=SUSTAIN_WINDOW_MIN)
    hist = (db.query(MachineMetric)
            .filter(MachineMetric.machine_id == machine.id, MachineMetric.timestamp >= since).all())
    procs = (db.query(ProcessSnapshot)
             .filter(ProcessSnapshot.machine_id == machine.id)
             .order_by(ProcessSnapshot.cpu_percent.desc()).limit(10).all())

    findings = []

    def add(category, severity, title, detail, evidence, remediation):
        findings.append({
            "category": category, "severity": severity, "title": title,
            "detail": detail, "evidence": evidence, "remediation": remediation,
        })

    ts = latest.timestamp if latest else None
    if ts and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    alive = bool(ts and (now - ts).total_seconds() < 60)

    if not latest:
        add("AVAILABILITY", "HIGH", "No telemetry received",
            "This node has never reported metrics. The agent may be stopped or cannot reach the server.",
            ["No metric samples found"], [])
    elif not alive:
        add("AVAILABILITY", "MEDIUM", "Node not reporting",
            f"Last heartbeat was {int((now - ts).total_seconds())}s ago. The agent appears offline.",
            [f"last_heartbeat {ts.isoformat()}"], [])

    # Storage
    for d in (machine.drives or []):
        pct = float(d.get("percent") or 0)
        mount = d.get("mount") or d.get("device") or "?"
        free = d.get("free_gb")
        total = d.get("total_gb")
        sev = "CRITICAL" if pct >= DISK_CRIT else "HIGH" if pct >= DISK_HIGH else "MEDIUM" if pct >= DISK_MED else None
        if sev:
            add("STORAGE", sev, f"Disk {mount} {pct:.0f}% full",
                f"Drive {mount} is {pct:.0f}% used ({free} GB free of {total} GB). Low free space slows the OS and risks write failures.",
                [f"{mount}: {pct:.0f}% used, {free} GB free of {total} GB"],
                _disk_cleanup(machine))

    # Sustained CPU / RAM from history
    if hist:
        cpus = [h.cpu_percent for h in hist if h.cpu_percent is not None]
        rams = [h.ram_percent for h in hist if h.ram_percent is not None]
        if cpus:
            avg_cpu = sum(cpus) / len(cpus)
            over = sum(1 for c in cpus if c >= CPU_HIGH)
            if avg_cpu >= CPU_HIGH or over >= max(3, int(len(cpus) * 0.6)):
                add("CPU", "CRITICAL" if avg_cpu >= 95 else "HIGH",
                    f"Sustained high CPU (~{avg_cpu:.0f}%)",
                    f"CPU averaged {avg_cpu:.0f}% over the last {SUSTAIN_WINDOW_MIN} min ({over}/{len(cpus)} samples >= {CPU_HIGH:.0f}%). Continuous load points to a runaway process or an undersized machine.",
                    [f"avg {avg_cpu:.1f}%", f"{over}/{len(cpus)} samples >= {CPU_HIGH:.0f}%"],
                    _cpu_inspect(machine))
        if rams:
            avg_ram = sum(rams) / len(rams)
            over_r = sum(1 for r in rams if r >= RAM_HIGH)
            if avg_ram >= RAM_HIGH or over_r >= max(3, int(len(rams) * 0.6)):
                add("MEMORY", "CRITICAL" if avg_ram >= 95 else "HIGH",
                    f"Sustained high memory (~{avg_ram:.0f}%)",
                    f"RAM averaged {avg_ram:.0f}% over the last {SUSTAIN_WINDOW_MIN} min. Memory pressure causes swapping and slowdowns.",
                    [f"avg {avg_ram:.1f}%", f"{over_r}/{len(rams)} samples >= {RAM_HIGH:.0f}%"],
                    _mem_inspect(machine))

    # Process hogs (point-in-time from the latest snapshot)
    for p in procs:
        cpu = p.cpu_percent or 0
        mem = p.memory_percent or 0
        if cpu >= PROC_CPU_HIGH:
            add("PROCESS", "HIGH", f"Process '{p.name}' high CPU ({cpu:.0f}%)",
                f"PID {p.pid} '{p.name}' is using {cpu:.0f}% CPU right now. If it stays high across scans it is the prime suspect for the load.",
                [f"PID {p.pid} {p.name} — {cpu:.0f}% CPU"],
                ([f"Stop-Process -Id {p.pid} -Force   # only after confirming it is safe"]
                 if _is_windows(machine) else [f"kill -15 {p.pid}   # only after confirming it is safe"]))
        elif mem >= PROC_MEM_HIGH:
            add("PROCESS", "MEDIUM", f"Process '{p.name}' high memory ({mem:.0f}%)",
                f"PID {p.pid} '{p.name}' is holding {mem:.0f}% of RAM.",
                [f"PID {p.pid} {p.name} — {mem:.0f}% MEM"], [])

    if not machine.mac_address:
        add("CONFIG", "LOW", "Physical MAC not registered",
            "Wake-on-LAN and some inventory checks need the MAC address. Set it on the node card or let the updated agent auto-detect it.",
            ["mac_address is blank"], [])

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "machine_id": machine.id,
        "hostname": machine.hostname,
        "os_name": machine.os_name,
        "scanned_at": now.isoformat(),
        "metrics": {
            "cpu_percent": latest.cpu_percent if latest else None,
            "ram_percent": latest.ram_percent if latest else None,
            "disk_percent": latest.disk_percent if latest else None,
            "online": alive,
        },
        "findings": findings,
        "counts": counts,
        "healthy": len(findings) == 0,
    }
