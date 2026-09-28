"""OCS-style inventory: detailed static hardware and the full installed-software list.
Cross-platform and best-effort:
  * Linux   -> /sys DMI + /proc/cpuinfo + dpkg/rpm
  * Windows -> PowerShell (Get-CimInstance / WMI) for make/model/serial/BIOS/CPU/OS, registry for software
Anything a host cannot provide comes back empty rather than failing."""
import platform
import subprocess
import re
import os
import json
import base64
import socket
import psutil

IS_WINDOWS = platform.system() == "Windows"


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None


def _run(cmd, timeout=25):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def _powershell(script, timeout=40):
    """Run a PowerShell snippet reliably via -EncodedCommand (avoids quoting, newline and
    execution-policy problems). Returns stdout, or empty on any failure."""
    try:
        enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    except Exception:
        return ""
    for exe in ("powershell", "pwsh"):
        try:
            r = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout
        except Exception:
            continue
    return ""


def _windows_hw():
    script = r"""
$ErrorActionPreference='SilentlyContinue'
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
$os   = Get-CimInstance Win32_OperatingSystem
$disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object {
    [pscustomobject]@{ model = $_.Model; size_gb = [math]::Round(($_.Size/1GB),1) } })

# Serial: prefer BIOS, then chassis, then motherboard; ignore common placeholders.
$bad = @('', 'To be filled by O.E.M.', 'Default string', 'None', '0', 'System Serial Number', 'Not Specified')
$serial = $bios.SerialNumber
if ($bad -contains $serial) { $serial = (Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1).SerialNumber }
if ($bad -contains $serial) { $serial = (Get-CimInstance Win32_BaseBoard).SerialNumber }

[pscustomobject]@{
  manufacturer = $cs.Manufacturer
  product      = $cs.Model
  serial       = $serial
  bios         = $bios.SMBIOSBIOSVersion
  cpu          = $cpu.Name
  cores        = $cpu.NumberOfCores
  logical      = $cpu.NumberOfLogicalProcessors
  ram_gb       = [math]::Round(($cs.TotalPhysicalMemory/1GB),1)
  os_caption   = $os.Caption
  os_version   = $os.Version
  os_arch      = $os.OSArchitecture
  disks        = $disks
} | ConvertTo-Json -Depth 4 -Compress
"""
    out = _powershell(script)
    try:
        data = json.loads(out) if out.strip() else {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def hardware():
    mem = psutil.virtual_memory()
    win = _windows_hw() if IS_WINDOWS else {}

    # partitions with sizes (cross-platform, real mounts)
    disks = []
    for pt in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(pt.mountpoint)
            disks.append({"device": pt.device, "mount": pt.mountpoint, "fstype": pt.fstype,
                          "total_gb": round(u.total / (1024 ** 3), 1)})
        except Exception:
            pass

    nics = []
    for name, addrs in psutil.net_if_addrs().items():
        mac, ips = "", []
        for a in addrs:
            if a.family == psutil.AF_LINK:
                mac = a.address
            elif a.family == socket.AF_INET:
                ips.append(a.address)
        if name != "lo":
            nics.append({"name": name, "mac": mac, "ipv4": ips})

    # CPU model
    cpu_model = win.get("cpu")
    if not cpu_model:
        ci = _read("/proc/cpuinfo") or ""
        m = re.search(r"model name\s*:\s*(.+)", ci)
        cpu_model = (m.group(1).strip() if m else "") or platform.processor() or "Unknown"

    # OS name / edition
    if IS_WINDOWS:
        os_pretty = (win.get("os_caption") or platform.platform() or "").strip()   # e.g. "Microsoft Windows 10 Pro"
        os_edition = os_pretty
        os_version = win.get("os_version") or platform.version()
        arch = win.get("os_arch") or platform.machine()
    else:
        os_pretty = platform.platform()
        osr = _read("/etc/os-release")
        if osr:
            pm = re.search(r'PRETTY_NAME="?([^"\n]+)"?', osr)
            if pm:
                os_pretty = pm.group(1)
        os_edition = os_pretty
        os_version = platform.release()
        arch = platform.machine()

    return {
        "cpu_model": cpu_model,
        "cpu_cores_physical": win.get("cores") or psutil.cpu_count(logical=False),
        "cpu_cores_logical": win.get("logical") or psutil.cpu_count(logical=True),
        "ram_total_gb": win.get("ram_gb") or round(mem.total / (1024 ** 3), 1),
        "os": f"{platform.system()} {platform.release()}",
        "os_pretty": os_pretty,
        "os_edition": os_edition,
        "os_version": os_version,
        "kernel": platform.release(),
        "arch": arch,
        "hostname": platform.node(),
        "manufacturer": win.get("manufacturer") or _read("/sys/devices/virtual/dmi/id/sys_vendor"),
        "product": win.get("product") or _read("/sys/devices/virtual/dmi/id/product_name"),
        "bios_version": win.get("bios") or _read("/sys/devices/virtual/dmi/id/bios_version"),
        "serial": win.get("serial") or _read("/sys/devices/virtual/dmi/id/product_serial"),
        "disks": disks,
        "physical_disks": win.get("disks") or [],
        "network_adapters": nics,
    }


def software():
    pkgs = []
    if IS_WINDOWS:
        try:
            import winreg
            roots = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ]
            for root, path in roots:
                try:
                    key = winreg.OpenKey(root, path)
                except Exception:
                    continue
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                        name = winreg.QueryValueEx(sub, "DisplayName")[0]
                        try:
                            ver = winreg.QueryValueEx(sub, "DisplayVersion")[0]
                        except Exception:
                            ver = ""
                        if name:
                            pkgs.append({"name": name, "version": str(ver)})
                    except Exception:
                        continue
        except Exception:
            pass
    else:
        out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        if out:
            for line in out.splitlines():
                p = line.split("\t")
                if len(p) >= 2:
                    pkgs.append({"name": p[0], "version": p[1]})
        else:
            out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"])
            for line in out.splitlines():
                p = line.split("\t")
                if len(p) >= 2:
                    pkgs.append({"name": p[0], "version": p[1]})

    seen, uniq = set(), []
    for p in sorted(pkgs, key=lambda x: x["name"].lower()):
        k = (p["name"], p["version"])
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    return uniq


def collect_inventory():
    return {"hardware": hardware(), "software": software()}


if __name__ == "__main__":
    inv = collect_inventory()
    print("HARDWARE:")
    print(json.dumps(inv["hardware"], indent=2))
    print(f"\nSOFTWARE: {len(inv['software'])} packages")
