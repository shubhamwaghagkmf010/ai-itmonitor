import psutil
import subprocess
import shutil
import socket
import platform
from typing import Dict, Any, List


def get_system_info() -> Dict[str, Any]:
    """Collects OS and machine metadata."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        ip_address = "127.0.0.1"

    return {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_version": platform.release(),
        "architecture": platform.machine(),
        "ip_address": ip_address,
        "agent_version": "1.0.0"
    }



_SKIP_FS = {"squashfs", "tmpfs", "devtmpfs", "overlay", "aufs", "proc",
            "sysfs", "cgroup", "cgroup2", "autofs"}


def collect_drives():
    """Every mounted partition with usage, using each OS's native mount names
    (C:\\, D:\\ on Windows; /, /home on Linux/macOS). Anything unreadable
    (empty CD/card readers, pseudo filesystems) is skipped, never fatal."""
    drives = []
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception:
        return drives
    for pt in parts:
        mp = pt.mountpoint
        if not mp:
            continue
        opts = (pt.opts or "").lower()
        if "cdrom" in opts or (pt.fstype or "").lower() in _SKIP_FS:
            continue
        try:
            u = psutil.disk_usage(mp)
        except (PermissionError, OSError):
            continue
        total_gb = round(u.total / (1024 ** 3), 2)
        if total_gb <= 0:
            continue
        drives.append({
            "mount": mp,
            "device": pt.device if (pt.device and pt.device != mp) else "",
            "fstype": pt.fstype or "",
            "total_gb": total_gb,
            "used_gb": round(u.used / (1024 ** 3), 2),
            "free_gb": round(u.free / (1024 ** 3), 2),
            "percent": u.percent,
        })
    return drives


def collect_metrics() -> Dict[str, Any]:
    """Collects CPU, RAM, Disk, Network and Top Process telemetry."""
    # CPU
    cpu_percent = psutil.cpu_percent(interval=1)

    # Memory
    mem = psutil.virtual_memory()
    ram_used_gb = round((mem.total - mem.available) / (1024 ** 3), 2)
    ram_total_gb = round(mem.total / (1024 ** 3), 2)

    # Disk (root/system disk)
    disk_path = "C:\\" if platform.system() == "Windows" else "/"
    disk = psutil.disk_usage(disk_path)
    disk_used_gb = round(disk.used / (1024 ** 3), 2)
    disk_total_gb = round(disk.total / (1024 ** 3), 2)

    # Network
    net = psutil.net_io_counters()

    # Top 5 CPU/Memory Processes
    top_processes: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
        try:
            info = proc.info
            if info['name'] and info['pid'] != 0:
                top_processes.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "cpu_percent": round(info.get('cpu_percent') or 0.0, 1),
                    "memory_percent": round(info.get('memory_percent') or 0.0, 1),
                    "status": info.get('status') or "running"
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort and pick top 5 resource consumers
    top_processes.sort(key=lambda x: (x['cpu_percent'], x['memory_percent']), reverse=True)
    top_processes = top_processes[:5]

    return {
        "cpu_percent": cpu_percent,
        "ram_percent": mem.percent,
        "ram_used_gb": ram_used_gb,
        "ram_total_gb": ram_total_gb,
        "disk_percent": disk.percent,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "bytes_sent": float(net.bytes_sent),
        "bytes_recv": float(net.bytes_recv),
        "packets_sent": int(net.packets_sent),
        "packets_recv": int(net.packets_recv),
        "top_processes": top_processes,
        "drives": collect_drives()
    }


# ---------------------------------------------------------------------------
# Extended, best-effort telemetry. Every collector returns None when the host
# cannot provide it, so an agent never fails because a tool is missing.
# ---------------------------------------------------------------------------

def _run(cmd, timeout=6):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout if out.returncode == 0 else None
    except Exception:
        return None


def collect_services():
    system = platform.system()
    try:
        if system == "Windows":
            items = []
            for svc in psutil.win_service_iter():
                try:
                    d = svc.as_dict()
                    if d.get("status") == "running":
                        items.append({"name": d.get("name"), "display_name": d.get("display_name")})
                except Exception:
                    continue
            return {"running": len(items), "items": items[:50]}
        out = _run(["systemctl", "list-units", "--type=service", "--state=running",
                    "--no-legend", "--no-pager", "--plain"])
        if out is None:
            return None
        items = [{"name": ln.split()[0]} for ln in out.splitlines() if ln.split()]
        return {"running": len(items), "items": items[:50]}
    except Exception:
        return None


def collect_containers():
    if not shutil.which("docker"):
        return None
    out = _run(["docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Status}}"])
    if out is None:
        return None
    items = []
    for ln in out.splitlines():
        p = ln.split("|")
        if len(p) >= 3:
            items.append({"name": p[0], "image": p[1], "status": p[2]})
    return {"count": len(items), "items": items}


def collect_sensors():
    try:
        temps = psutil.sensors_temperatures()
    except Exception:
        return None
    if not temps:
        return None
    result = {}
    for chip, entries in temps.items():
        result[chip] = [
            {"label": e.label or chip, "current": e.current, "high": e.high, "critical": e.critical}
            for e in entries
        ]
    return result


def collect_gpu():
    if not shutil.which("nvidia-smi"):
        return None
    out = _run(["nvidia-smi",
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits"])
    if out is None:
        return None
    items = []
    for ln in out.splitlines():
        p = [x.strip() for x in ln.split(",")]
        if len(p) >= 5:
            items.append({"name": p[0], "util_percent": p[1],
                          "mem_used_mb": p[2], "mem_total_mb": p[3], "temp_c": p[4]})
    return {"count": len(items), "items": items}


def collect_smart():
    if not shutil.which("smartctl"):
        return None
    scan = _run(["smartctl", "--scan"])
    if not scan:
        return None
    disks = []
    for ln in scan.splitlines():
        parts = ln.split()
        if not parts:
            continue
        dev = parts[0]
        health = _run(["smartctl", "-H", dev])
        status = "UNKNOWN"
        if health:
            for hl in health.splitlines():
                if "overall-health" in hl.lower():
                    status = hl.split(":")[-1].strip()
        disks.append({"device": dev, "health": status})
    return {"count": len(disks), "items": disks} if disks else None


def collect_extended():
    return {
        "services": collect_services(),
        "containers": collect_containers(),
        "sensors": collect_sensors(),
        "disks_smart": collect_smart(),
        "gpu": collect_gpu(),
    }
