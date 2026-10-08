import time
import json
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

from agent.collectors.metrics import get_system_info, collect_metrics, collect_extended
from agent.collectors.inventory import collect_inventory

CONFIG_FILE = Path(__file__).parent / "agent_config.json"
SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:8000/api/v1/agents")
METRIC_INTERVAL_SECONDS = int(os.getenv("METRIC_INTERVAL", "10"))
INVENTORY_INTERVAL = int(os.getenv("INVENTORY_INTERVAL", "1800"))  # 30 min
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(config: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def register_agent(client: httpx.Client) -> str:
    config = load_config()
    if not config.get("machine_uid"):
        config["machine_uid"] = uuid.uuid4().hex
        save_config(config)
    if config.get("agent_id") and config.get("registered_uid") == config["machine_uid"]:
        return config["agent_id"]

    system_info = get_system_info()
    system_info["machine_uid"] = config["machine_uid"]
    print(f"[*] Registering node '{system_info['hostname']}' ({system_info['os_name']}) uid={config['machine_uid'][:8]} with central server...")
    
    try:
        response = client.post(f"{SERVER_URL}/register", json=system_info, timeout=10.0)
        response.raise_for_status()
        data = response.json()
        agent_id = data["agent_id"]
        config["agent_id"] = agent_id
        config["registered_uid"] = config["machine_uid"]
        config["hostname"] = system_info["hostname"]
        save_config(config)
        print(f"[+] Successfully registered with Agent ID: {agent_id}")
        return agent_id
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

EXEC_TIMEOUT = int(os.getenv("CMD_TIMEOUT", "20"))


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
    try:
        import psutil
        psutil.Process(int(pid)).terminate()
        return "COMPLETED", f"Terminate signal sent to PID {pid}"
    except Exception as e:
        return "FAILED", f"{type(e).__name__}: {e}"


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
    _start_wol_relay()
    print("==================================================")
    print("      AI-ITMonitor Cross-Platform Agent           ")
    print("==================================================")
    
    with httpx.Client(headers={"X-Agent-Key": AGENT_API_KEY} if AGENT_API_KEY else {}) as client:
        agent_id = register_agent(client)
        
        while not agent_id:
            print("[!] Retrying registration in 5 seconds...")
            time.sleep(5)
            agent_id = register_agent(client)

        print(f"[*] Starting telemetry collection loop (Interval: {METRIC_INTERVAL_SECONDS}s)...")
        last_inventory = 0
        
        while True:
            try:
                metrics = collect_metrics()
                payload = {"agent_id": agent_id, **metrics, **collect_extended()}
                
                res = client.post(f"{SERVER_URL}/metrics", json=payload, timeout=10.0)
                res.raise_for_status()
                data = res.json()
                status_ack = data.get("machine_status", "UNKNOWN")
                pending = data.get("pending_commands", [])
                if pending:
                    handle_commands(client, agent_id, pending)
                
                print(f"[Telemetry Sent] CPU: {metrics['cpu_percent']}% | RAM: {metrics['ram_percent']}% | Status: {status_ack}")
            except Exception as e:
                print(f"[!] Error sending telemetry: {e}")
            
            now = time.time()
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
