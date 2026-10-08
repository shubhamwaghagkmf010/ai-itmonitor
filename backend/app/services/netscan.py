"""Unprivileged LAN discovery + enrichment.

Discovery: ping-sweep to populate the kernel neighbour cache, then read `ip neigh` for IP<->MAC.
Enrichment (best-effort, "as much as we can reach"):
  * vendor   - full IEEE OUI database (downloaded once and cached), falling back to a curated map
  * services - a quick TCP connect probe of common ports
  * OS guess - from the ping TTL, refined by open ports
  * type     - inferred from vendor + open ports
No root, no nmap required.
"""
import os
import ipaddress
import socket
import subprocess
import re
import csv
import pathlib
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# Small curated fallback (used before/if the full DB is unavailable).
OUI = {
    "001B21": "Intel", "BC2411": "Proxmox Server Solutions", "000C29": "VMware", "005056": "VMware",
    "525400": "QEMU/KVM", "080027": "VirtualBox", "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "309C23": "Micro-Star (MSI)",
}

OUI_CACHE = pathlib.Path(__file__).parent / "oui_cache.csv"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_oui_map = None

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 515: "Printer", 554: "RTSP/Camera",
    631: "IPP/Printer", 993: "IMAPS", 1433: "MSSQL", 1883: "MQTT", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "JetDirect/Printer",
    161: "SNMP", 5900: "VNC",
}

MOBILE = {"apple", "samsung", "xiaomi", "huawei", "oneplus", "oppo", "vivo", "realme", "lg electronics", "google", "motorola"}
NETWORK = {"cisco", "tp-link", "netgear", "d-link", "mikrotik", "ubiquiti", "juniper", "aruba", "fortinet", "zyxel"}
COMPUTER = {"dell", "hp", "hewlett", "lenovo", "asustek", "acer", "micro-star", "msi", "gigabyte", "intel"}
VM = {"proxmox", "vmware", "qemu", "virtualbox", "parallels", "xen"}


def _load_oui():
    global _oui_map
    if _oui_map is not None:
        return _oui_map
    _oui_map = dict(OUI)
    if not OUI_CACHE.exists():
        try:
            req = urllib.request.Request(OUI_URL, headers={"User-Agent": "curl/8"})
            data = urllib.request.urlopen(req, timeout=25).read()
            OUI_CACHE.write_bytes(data)
        except Exception:
            pass
    if OUI_CACHE.exists():
        try:
            with open(OUI_CACHE, newline="", encoding="utf-8", errors="ignore") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1] or ""):
                        _oui_map[row[1].upper()] = row[2].strip()
        except Exception:
            pass
    return _oui_map


def _is_randomized(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def _vendor(mac):
    if not mac:
        return "Unknown"
    if _is_randomized(mac):
        return "Private (randomized MAC)"
    return _load_oui().get(mac.replace(":", "").upper()[:6], "Unknown")


def _probe_ports(ip, timeout=0.5):
    found = []
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                found.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return found


def _ttl_os(ip):
    try:
        out = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=2).stdout
        m = re.search(r"ttl=(\d+)", out)
        if not m:
            return None, None
        ttl = int(m.group(1))
        if ttl <= 64:
            return ttl, "Linux / Unix"
        if ttl <= 128:
            return ttl, "Windows"
        return ttl, "Network device"
    except Exception:
        return None, None


def _device_type(vendor, ports, os_guess):
    v = (vendor or "").lower()
    ps = set(ports)
    if "randomized" in v and not ps:
        return "Mobile / Private"
    if 9100 in ps or 515 in ps or 631 in ps:
        return "Printer"
    if 554 in ps:
        return "IP Camera"
    if 161 in ps and not (445 in ps or 3389 in ps):
        return "Network / Router"
    if 53 in ps and (80 in ps or 443 in ps):
        return "Router / Gateway"
    if any(k in v for k in NETWORK):
        return "Network / Router"
    if any(k in v for k in VM):
        return "Virtual Machine"
    if 3389 in ps or (445 in ps and os_guess == "Windows"):
        return "Windows Computer"
    if 445 in ps:
        return "Windows Host"
    if 22 in ps and ps & {1433, 3306, 5432, 8080, 8000, 8443, 80, 443}:
        return "Linux Server"
    if 22 in ps:
        return "Linux Host"
    if any(k in v for k in MOBILE):
        return "Mobile / Tablet"
    if "randomized" in v:
        return "Mobile / Private"
    if any(k in v for k in COMPUTER):
        return "Computer / Laptop"
    if ps:
        return "Host"
    return "Unknown"


def get_local_subnet():
    env = os.environ.get("SCAN_SUBNET")
    if env and env.strip():
        return env.strip()
    out = subprocess.run(["ip", "-4", "addr"], capture_output=True, text=True).stdout
    for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out):
        ip, prefix = m.group(1), m.group(2)
        if ip.startswith("127.") or ip.startswith("172.17.") or ip.startswith("172.18."):
            continue
        return f"{ip}/{prefix}"
    return None


def _ping(ip):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, timeout=2)
        return ip if r.returncode == 0 else None
    except Exception:
        return None


def _neighbours():
    out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True).stdout
    res = {}
    for line in out.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\w+)", line)
        if m:
            res[m.group(1)] = (m.group(2).lower(), m.group(3))
    return res


def _expand(spec):
    spec = spec.strip()
    if "-" in spec:
        a, b = spec.split("-", 1)
        a, b = a.strip(), b.strip()
        if "." not in b:
            b = a.rsplit(".", 1)[0] + "." + b
        start, end = int(ipaddress.ip_address(a)), int(ipaddress.ip_address(b))
        if end < start:
            start, end = end, start
        return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)], f"{a} - {b}"
    net = ipaddress.ip_network(spec, strict=False)
    return [str(h) for h in net.hosts()], str(net)


def _enrich(ip, mac):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = ""
    ports = _probe_ports(ip)
    ttl, os_guess = _ttl_os(ip)
    vendor = _vendor(mac)
    services = [f"{p}/{COMMON_PORTS.get(p, '?')}" for p in ports]
    return {
        "ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor,
        "device_type": _device_type(vendor, ports, os_guess),
        "os_guess": os_guess or "Unknown",
        "open_ports": ", ".join(services),
        "is_online": True,
    }


def scan_subnet(cidr=None, max_hosts=1024):
    cidr = cidr or get_local_subnet()
    if not cidr:
        return {"error": "Could not determine the local subnet."}
    try:
        hosts, label = _expand(cidr)
    except ValueError as e:
        return {"error": f"Invalid range/subnet: {e}"}
    hosts = hosts[:max_hosts]

    _load_oui()  # warm the vendor DB (downloads once, then cached)

    responders = set()
    with ThreadPoolExecutor(max_workers=80) as ex:
        for res in ex.map(_ping, hosts):
            if res:
                responders.add(res)

    neigh = _neighbours()
    # "Present" = answered our ping, or the kernel has a freshly-confirmed (REACHABLE) ARP
    # entry. Stale-only cache entries are skipped so long-gone hosts don't pollute the list.
    present = [ip for ip in hosts
               if ip in responders or (ip in neigh and neigh[ip][1] == "REACHABLE")]

    def one(ip):
        mac, state = neigh.get(ip, (None, None))
        if mac == "00:00:00:00:00:00":
            mac = None
        d = _enrich(ip, mac)
        d["is_online"] = (ip in responders) or (state == "REACHABLE")
        return d

    with ThreadPoolExecutor(max_workers=40) as ex:
        devices = list(ex.map(one, present))

    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return {"subnet": label, "count": len(devices), "devices": devices}


if __name__ == "__main__":
    import json
    print(json.dumps(scan_subnet(), indent=2))
