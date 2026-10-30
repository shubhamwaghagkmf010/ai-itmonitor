import time
import json
import ssl
import uuid
import os
import sys
import httpx
import socket
import platform
import subprocess
import threading
from pathlib import Path

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.collectors.metrics import get_system_info, collect_metrics, collect_extended, get_mac_address
from agent.collectors.metrics import _not_responding_pids
from agent.version import AGENT_VERSION
from agent.collectors.inventory import collect_inventory

CONFIG_FILE = Path(__file__).parent / "agent_config.json"
SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:8000/api/v1/agents")
CA_CERT_PATH = Path(__file__).parent / "ca_cert.crt"


def _build_ssl_context():
    """Trust context for all agent HTTP calls: the normal public CA trust store
    (so a future real domain with a Let's Encrypt certificate just works, with no
    agent change needed) PLUS our own internal CA, bundled as ca_cert.crt, which
    vouches for THIS deployment's private-IP certificate (no public CA will ever
    certify a private IP). If ca_cert.crt is missing or unreadable this silently
    falls back to the public trust store only - never raises."""
    ctx = ssl.create_default_context()
    try:
        if CA_CERT_PATH.exists():
            ctx.load_verify_locations(cafile=str(CA_CERT_PATH))
    except Exception as e:
        print(f"[tls] could not load bundled CA cert (continuing without it): {e}")
    return ctx


def _migrate_to_https(client, agent_id, config, hint):
    """One-time, verified move from the legacy HTTP endpoint to the HTTPS one the
    server advertises. Only switches after a real request to the hinted URL
    succeeds, and remembers the choice in agent_config.json so it survives
    restarts. Never used for the active registration id - callers keep using the
    current SERVER_URL until this returns a new one."""
    global SERVER_URL
    if not hint or hint == SERVER_URL or not hint.startswith("https://"):
        return
    try:
        r = client.get(f"{hint}/version", timeout=10.0)
        if r.status_code == 200:
            print(f"[tls] HTTPS endpoint verified reachable - switching to {hint}")
            SERVER_URL = hint
            config["server_url"] = hint
            config["server_url_failures"] = 0
            save_config(config)
    except Exception as e:
        print(f"[tls] HTTPS endpoint not yet reachable ({e}); staying on {SERVER_URL} for now")


def _note_request_outcome(config, ok):
    """After migrating to HTTPS, revert to the original SERVER_URL if several
    consecutive requests fail - so a misconfigured or unreachable HTTPS path can
    never strand an agent that was working fine over HTTP."""
    global SERVER_URL
    if "server_url" not in config:
        return
    if ok:
        config["server_url_failures"] = 0
        return
    config["server_url_failures"] = config.get("server_url_failures", 0) + 1
    if config["server_url_failures"] >= 5:
        fallback = config.get("original_server_url") or os.getenv(
            "SERVER_URL", "http://127.0.0.1:8000/api/v1/agents")
        print(f"[tls] {config['server_url_failures']} consecutive failures on {SERVER_URL} "
              f"- reverting to {fallback}")
        SERVER_URL = fallback
        config.pop("server_url", None)
        config["server_url_failures"] = 0
    save_config(config)
METRIC_INTERVAL_SECONDS = int(os.getenv("METRIC_INTERVAL", "10"))
INVENTORY_INTERVAL = int(os.getenv("INVENTORY_INTERVAL", "1800"))  # 30 min
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")


def _agent_headers(token=None):
    """Headers on every request: the shared enrolment key, a note that this agent can keep a
    per-agent token, and that token once the server has issued one."""
    headers = {"X-Agent-Token-Support": "1"}
    if AGENT_API_KEY:
        headers["X-Agent-Key"] = AGENT_API_KEY
    if token:
        headers["X-Agent-Token"] = token
    return headers


def _remember_token(client, token):
    """Keeps the token the server issued: on disk for the next start, and on the live client."""
    config = load_config()
    config["agent_token"] = token
    save_config(config)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass
    client.headers["X-Agent-Token"] = token


def _forget_identity(client):
    """The server no longer accepts our token (it was reset or the machine re-enrolled). Drop the
    cached identity so the agent registers again."""
    config = load_config()
    for key in ("agent_id", "agent_token", "registered_uid"):
        config.pop(key, None)
    save_config(config)
    client.headers.pop("X-Agent-Token", None)


def _token_rejected(exc):
    resp = getattr(exc, "response", None)
    return resp is not None and resp.status_code == 401 and "agent token" in (resp.text or "").lower()

# --- Self-update -----------------------------------------------------------
# The server always serves the latest agent code at /download and advertises the
# latest version in every /metrics heartbeat (and via GET /version). When a newer
# version is seen (or the server pushes an UPDATE_AGENT command), the agent stages
# the new bundle and exits with code 42; the launcher (run.bat) swaps it in and
# relaunches. Windows-only - the launcher supervises the restart there.
UPDATE_CHECK_INTERVAL = int(os.getenv("UPDATE_CHECK_INTERVAL", "3600"))  # hourly fallback poll
ROOT_DIR = Path(__file__).resolve().parent.parent   # folder that holds agent/ and run.bat
STAGING_DIR = ROOT_DIR / "_staging"
UPDATE_EXIT_CODE = 42


def _parse_ver(v):
    parts = []
    for piece in str(v).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _download_update():
    """Download the latest bundle into a clean _staging dir next to this install.
    Returns True only if the new agent code is present. Never raises."""
    import zipfile, io as _io, shutil
    try:
        target = "windows" if platform.system() == "Windows" else "linux"
        url = f"{SERVER_URL}/download?os={target}"
        headers = _agent_headers(load_config().get("agent_token"))
        with httpx.Client(headers=headers, verify=_build_ssl_context()) as c:
            r = c.get(url, timeout=90.0)
            r.raise_for_status()
            content = r.content
        if STAGING_DIR.exists():
            shutil.rmtree(STAGING_DIR, ignore_errors=True)
        STAGING_DIR.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(_io.BytesIO(content)) as z:
            z.extractall(STAGING_DIR)
        if not (STAGING_DIR / "agent" / "main.py").exists():
            shutil.rmtree(STAGING_DIR, ignore_errors=True)
            print("[update] staged bundle missing agent/main.py - aborting")
            return False
        return True
    except Exception as e:
        print(f"[update] download failed: {e}")
        return False


def _maybe_update(latest):
    """If the server's latest version is newer than ours, stage it and exit 42."""
    if platform.system() != "Windows" or not latest:
        return
    try:
        if _parse_ver(latest) > _parse_ver(AGENT_VERSION):
            print(f"[update] v{latest} available (running v{AGENT_VERSION}); downloading...")
            if _download_update():
                print("[update] staged; restarting via launcher to apply...")
                sys.stdout.flush()
                sys.exit(UPDATE_EXIT_CODE)
            print(f"[update] download failed; staying on v{AGENT_VERSION}")
    except SystemExit:
        raise
    except Exception as e:
        print(f"[update] check error: {e}")


def _handle_update_command(client, agent_id, cid):
    """Server-pushed UPDATE_AGENT: stage the latest bundle and exit 42 so the
    launcher applies it. Returns a FAILED tuple only when it could not."""
    if platform.system() != "Windows":
        return "FAILED", "Auto-update is Windows-only in this build."
    if _download_update():
        try:
            client.post(f"{SERVER_URL}/command-result",
                        json={"agent_id": agent_id, "command_id": cid,
                              "status": "COMPLETED",
                              "output": "Update staged; restarting launcher to apply."},
                        timeout=15.0)
        except Exception:
            pass
        sys.stdout.flush()
        sys.exit(UPDATE_EXIT_CODE)
    return "FAILED", "Update download failed; staying on current version."



def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(config: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def _hardware_uid() -> str:
    """A stable identifier for THIS physical machine. Derived from the primary NIC
    MAC so it survives re-downloading the agent (no duplicate node) yet differs
    between machines - even cloned Windows images that share a hostname/config
    (they have different network cards, hence different MACs)."""
    try:
        mac = (get_mac_address() or "").replace(":", "").replace("-", "").strip().lower()
        if mac and len(mac) == 12 and mac != "000000000000":
            return mac
    except Exception:
        pass
    try:
        node = uuid.getnode()
        # bit 0x010000000000 set => random/locally-administered (not real hardware)
        if node and not (node >> 40) & 0x1:
            return f"{node:012x}"
    except Exception:
        pass
    return ""


def register_agent(client: httpx.Client) -> str:
    config = load_config()
    uid = _hardware_uid() or config.get("machine_uid") or uuid.uuid4().hex
    if uid != config.get("machine_uid"):
        config["machine_uid"] = uid
        save_config(config)
    if config.get("agent_id") and config.get("registered_uid") == uid:
        return config["agent_id"]

    system_info = get_system_info()
    system_info["machine_uid"] = uid
    print(f"[*] Registering node '{system_info['hostname']}' ({system_info['os_name']}) uid={uid[:8]} with central server...")
    
    try:
        response = client.post(f"{SERVER_URL}/register", json=system_info, timeout=10.0)
        response.raise_for_status()
        data = response.json()
        agent_id = data["agent_id"]
        if data.get("agent_token"):
            config["agent_token"] = data["agent_token"]
            client.headers["X-Agent-Token"] = data["agent_token"]
        config["agent_id"] = agent_id
        config["registered_uid"] = config["machine_uid"]
        config["hostname"] = system_info["hostname"]
        save_config(config)
        try:
            os.chmod(CONFIG_FILE, 0o600)  # it now holds the agent's token
        except OSError:
            pass
        print(f"[+] Successfully registered with Agent ID: {agent_id}")
        return agent_id
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 409:
            print("[-] The server says this machine is already enrolled and active; waiting to retry")
        else:
            print(f"[-] Registration failed: {e}")
        return None
    except Exception as e:
        print(f"[-] Registration failed: {e}")
        return None




def _start_wol_relay():
    """Listen on UDP 9999 for a MAC address; broadcast the Wake-on-LAN magic packet on THIS
    machine's local subnet. Lets the server wake a PC on a subnet it cannot broadcast to,
    by relaying through an always-on agent that shares the PC's subnet."""
    def _magic(mac):
        clean = mac.replace(":", "").replace("-", "").strip()
        return b"\xff" * 6 + bytes.fromhex(clean) * 16

    def _listen():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", 9999))
        except Exception as e:
            print(f"[relay] could not bind udp/9999: {e}")
            return
        caster = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        caster.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        print("[relay] Wake-on-LAN relay listening on udp/9999")
        while True:
            try:
                data, _addr = srv.recvfrom(1024)
                mac = data.decode("utf-8", "ignore").strip()
                if len(mac.replace(":", "").replace("-", "")) == 12:
                    pkt = _magic(mac)
                    for _ in range(3):
                        for port in (7, 9):
                            try:
                                caster.sendto(pkt, ("255.255.255.255", port))
                            except Exception:
                                pass
                        time.sleep(0.04)
                    print(f"[relay] broadcast magic packet locally for {mac}")
            except Exception as e:
                print(f"[relay] error: {e}")
                time.sleep(1)

    threading.Thread(target=_listen, daemon=True).start()

EXEC_TIMEOUT = int(os.getenv("CMD_TIMEOUT", "45"))


def _run_cmd(args, timeout=EXEC_TIMEOUT):
    out = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    body = ((out.stdout or "") + (out.stderr or "")).strip() or f"(exit code {out.returncode}, no output)"
    return ("COMPLETED" if out.returncode == 0 else "FAILED"), body


def _exec_shell(command_str):
    if not command_str:
        return "FAILED", "No command provided"
    try:
        if platform.system() == "Windows":
            args = ["powershell", "-NoProfile", "-NonInteractive", "-Command", command_str]
        else:
            args = ["/bin/sh", "-c", command_str]
        return _run_cmd(args)
    except subprocess.TimeoutExpired:
        return "FAILED", f"Command timed out after {EXEC_TIMEOUT}s"
    except Exception as e:
        return "FAILED", f"{type(e).__name__}: {e}"


def _service_action(action, name):
    if not name:
        return "FAILED", "No service name provided"
    verb = {"SERVICE_START": "start", "SERVICE_STOP": "stop",
            "SERVICE_RESTART": "restart", "SERVICE_STATUS": "status"}.get(action)
    try:
        if platform.system() == "Windows":
            ps = {
                "start": "Start-Service -Name '%s'" % name,
                "stop": "Stop-Service -Name '%s' -Force" % name,
                "restart": "Restart-Service -Name '%s' -Force" % name,
                "status": "Get-Service -Name '%s' | Format-List Name,DisplayName,Status,StartType" % name,
            }[verb]
            args = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps]
        else:
            if verb == "status":
                args = ["systemctl", "status", "--no-pager", name]
            else:
                args = ["systemctl", verb, name]
        return _run_cmd(args)
    except subprocess.TimeoutExpired:
        return "FAILED", f"Service action timed out after {EXEC_TIMEOUT}s"
    except Exception as e:
        return "FAILED", f"{type(e).__name__}: {e}"


def _kill_process(pid):
    """Force-terminate a process AND its child tree, then verify it is actually
    gone. Windows uses taskkill /F /T (kills the whole tree); elsewhere psutil
    SIGKILL on children then the parent. Reports the truth - if the process is
    still alive afterwards (e.g. access denied) it returns FAILED, not success."""
    import psutil
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return "FAILED", f"Invalid PID: {pid!r}"
    if pid <= 1:
        return "FAILED", f"Refusing to kill PID {pid}: system process"
    if pid in (os.getpid(), os.getppid()):
        return "FAILED", f"Refusing to kill PID {pid}: that is the monitoring agent itself"
    try:
        name = psutil.Process(pid).name()
    except Exception:
        name = str(pid)
    detail = ""
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                                 capture_output=True, text=True, timeout=25)
            detail = ((out.stdout or "") + (out.stderr or "")).strip()
        else:
            try:
                parent = psutil.Process(pid)
                victims = parent.children(recursive=True) + [parent]
            except psutil.NoSuchProcess:
                victims = []
            for v in victims:
                try:
                    v.kill()
                except Exception:
                    pass
            psutil.wait_procs(victims, timeout=5)
    except subprocess.TimeoutExpired:
        return "FAILED", f"Kill timed out for PID {pid} ({name})"
    except Exception as e:
        return "FAILED", f"{type(e).__name__}: {e}"
    time.sleep(0.4)
    if psutil.pid_exists(pid):
        try:
            if psutil.Process(pid).status() != psutil.STATUS_ZOMBIE:
                msg = f"PID {pid} ({name}) is STILL running after force-kill."
                if "denied" in detail.lower():
                    msg += " Access denied - the agent must run as Administrator/root to end this process."
                elif detail:
                    msg += " " + detail
                return "FAILED", msg
        except psutil.NoSuchProcess:
            pass
    return "COMPLETED", f"Ended process tree for PID {pid} ({name})."


def _diagnose_system():
    """Live, best-effort snapshot of what is stressing the host RIGHT NOW - the
    signals a slow machine shows that averaged dashboard metrics miss: disk I/O,
    pagefile/swap, per-core CPU and the current top consumers. Never raises."""
    import psutil
    lines = []
    try:
        per = psutil.cpu_percent(interval=1.0, percpu=True)
        overall = round(sum(per) / len(per), 1) if per else 0.0
        busiest = round(max(per), 1) if per else 0.0
        lines.append(f"CPU: {overall}% overall across {len(per)} core(s); busiest core {busiest}%")
        if busiest >= 90 and overall < 60:
            lines.append("  -> One core is saturated (a single-threaded task). That app feels "
                         "slow even though total CPU looks low.")
    except Exception as e:
        lines.append(f"CPU: unavailable ({e})")
    try:
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()
        lines.append(f"Memory: {vm.percent}% used, {round(vm.available/1024**3,2)} GB free; "
                     f"pagefile/swap {sm.percent}% used")
        if vm.percent >= 90 or sm.percent >= 50:
            lines.append("  -> Memory pressure: the system is paging to disk, a common cause of "
                         "whole-machine sluggishness.")
    except Exception as e:
        lines.append(f"Memory: unavailable ({e})")
    try:
        d1 = psutil.disk_io_counters()
        time.sleep(1.0)
        d2 = psutil.disk_io_counters()
        if d1 and d2:
            rmb = round((d2.read_bytes - d1.read_bytes)/1024**2, 2)
            wmb = round((d2.write_bytes - d1.write_bytes)/1024**2, 2)
            line = f"Disk I/O: read {rmb} MB/s, write {wmb} MB/s"
            busy = None
            if hasattr(d2, "busy_time") and hasattr(d1, "busy_time"):
                busy = d2.busy_time - d1.busy_time  # ms busy in ~1000 ms
                line += f", ~{min(100, round(busy/10.0))}% active"
            lines.append(line)
            if (busy is not None and busy >= 800) or (rmb + wmb) >= 50:
                lines.append("  -> Disk is a bottleneck: heavy read/write right now. This makes the "
                             "whole machine feel slow even when CPU and RAM look fine (the dashboard "
                             "does not track disk I/O).")
    except Exception as e:
        lines.append(f"Disk I/O: unavailable ({e})")
    try:
        for p in psutil.process_iter(['pid', 'name']):
            try:
                p.cpu_percent(None)
            except Exception:
                pass
        time.sleep(0.6)
        rows = []
        for p in psutil.process_iter(['pid', 'name', 'memory_percent']):
            try:
                rows.append((p.info.get('name') or '?', p.info.get('pid'),
                             round(p.cpu_percent(None), 1),
                             round(p.info.get('memory_percent') or 0.0, 1)))
            except Exception:
                continue
        top_cpu = sorted(rows, key=lambda r: r[2], reverse=True)[:5]
        top_mem = sorted(rows, key=lambda r: r[3], reverse=True)[:5]
        lines.append("Top CPU: " + ", ".join(f"{n} (PID {pid}) {c}%" for n, pid, c, m in top_cpu))
        lines.append("Top RAM: " + ", ".join(f"{n} (PID {pid}) {m}%" for n, pid, c, m in top_mem))
    except Exception as e:
        lines.append(f"Top processes: unavailable ({e})")
    try:
        hung = _not_responding_pids()
        if hung:
            lines.append(f"Not Responding windows: {len(hung)} (PIDs {sorted(hung)[:10]})")
    except Exception:
        pass
    try:
        up = time.time() - psutil.boot_time()
        lines.append(f"Uptime: {int(up//3600)}h {int((up%3600)//60)}m; total processes: {len(psutil.pids())}")
    except Exception:
        pass
    return "COMPLETED", "\n".join(lines)


def _reboot_system():
    try:
        if platform.system() == "Windows":
            subprocess.Popen(["shutdown", "/r", "/t", "5"])
        else:
            subprocess.Popen(["/bin/sh", "-c", "sleep 2; (reboot || shutdown -r now)"])
        return "COMPLETED", "Reboot scheduled on remote host"
    except Exception as e:
        return "FAILED", f"{type(e).__name__}: {e}"


def handle_commands(client, agent_id, commands):
    """Execute commands the server dispatched (returned in the /metrics response)
    and report each result back to /command-result."""
    for c in commands:
        ctype = c.get("type")
        payload = c.get("payload") or {}
        cid = c.get("command_id")
        if ctype == "EXECUTE_SHELL":
            status, output = _exec_shell(payload.get("command_str"))
        elif ctype == "KILL_PROCESS":
            status, output = _kill_process(payload.get("pid"))
        elif ctype == "REBOOT_SYSTEM":
            status, output = _reboot_system()
        elif ctype == "DIAGNOSE_SYSTEM":
            status, output = _diagnose_system()
        elif ctype == "UPDATE_AGENT":
            status, output = _handle_update_command(client, agent_id, cid)
        elif ctype in ("SERVICE_START", "SERVICE_STOP", "SERVICE_RESTART", "SERVICE_STATUS"):
            status, output = _service_action(ctype, payload.get("command_str"))
        else:
            status, output = "FAILED", f"Unknown command type: {ctype}"
        try:
            client.post(f"{SERVER_URL}/command-result",
                        json={"agent_id": agent_id, "command_id": cid,
                              "status": status, "output": output},
                        timeout=15.0)
            print(f"[Command {cid}] {ctype} -> {status}")
        except Exception as e:
            print(f"[Command {cid}] result post failed: {e}")


def run_agent():
    global SERVER_URL
    _start_wol_relay()
    print("==================================================")
    print("      AI-ITMonitor Cross-Platform Agent           ")
    print("==================================================")
    
    with httpx.Client(headers=_agent_headers(load_config().get("agent_token")),
                     verify=_build_ssl_context()) as client:
        config = load_config()
        config.setdefault("original_server_url", SERVER_URL)
        if config.get("server_url"):
            SERVER_URL = config["server_url"]
        agent_id = register_agent(client)

        while not agent_id:
            print("[!] Retrying registration in 5 seconds...")
            time.sleep(5)
            agent_id = register_agent(client)
        config = load_config()  # registration may have saved a new id/token
        config.setdefault("original_server_url", SERVER_URL)

        print(f"[*] Starting telemetry collection loop (Interval: {METRIC_INTERVAL_SECONDS}s)...")
        last_inventory = 0
        last_update_check = time.time()
        
        while True:
            try:
                metrics = collect_metrics()
                payload = {"agent_id": agent_id, **metrics, **collect_extended()}
                
                res = client.post(f"{SERVER_URL}/metrics", json=payload, timeout=10.0)
                res.raise_for_status()
                data = res.json()
                if data.get("agent_token"):  # issued once, when the server first sees a token-capable agent
                    _remember_token(client, data["agent_token"])
                    config["agent_token"] = data["agent_token"]
                _note_request_outcome(config, True)
                status_ack = data.get("machine_status", "UNKNOWN")
                pending = data.get("pending_commands", [])
                if pending:
                    handle_commands(client, agent_id, pending)
                _maybe_update(data.get("latest_agent_version"))
                _migrate_to_https(client, agent_id, config, data.get("https_hint"))
                
                print(f"[Telemetry Sent] CPU: {metrics['cpu_percent']}% | RAM: {metrics['ram_percent']}% | Status: {status_ack}")
            except Exception as e:
                print(f"[!] Error sending telemetry: {e}")
                if _token_rejected(e):
                    print("[!] Server rejected the agent token; registering again")
                    _forget_identity(client)
                    agent_id = None
                    while not agent_id:
                        time.sleep(5)
                        agent_id = register_agent(client)
                    config = load_config()
                    config.setdefault("original_server_url", SERVER_URL)
                    continue
                _note_request_outcome(config, False)
            
            now = time.time()
            if now - last_update_check > UPDATE_CHECK_INTERVAL:
                last_update_check = now
                try:
                    vr = client.get(f"{SERVER_URL}/version", timeout=10.0)
                    if vr.status_code == 200:
                        _maybe_update(vr.json().get("version"))
                except SystemExit:
                    raise
                except Exception:
                    pass
            if now - last_inventory > INVENTORY_INTERVAL:
                try:
                    inv = collect_inventory()
                    client.post(f"{SERVER_URL}/inventory", json={"agent_id": agent_id, **inv}, timeout=30.0)
                    last_inventory = now
                    print(f"[Inventory Sent] {len(inv.get('software', []))} packages")
                except Exception as e:
                    print(f"[!] Inventory send failed: {e}")

            time.sleep(METRIC_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_agent()
