import importlib.util
import inspect
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

import pytest
import yaml

from agent import wol
from backend.app.core.config import BASE_DIR

LINUX = sys.platform.startswith("linux")


# --- Wake-on-LAN: what the relay will accept ---------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"), ("AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"),
    ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"), ("  00:11:22:33:44:55\n", "00:11:22:33:44:55"), (b"00:11:22:33:44:55", "00:11:22:33:44:55"),
])
def test_valid_mac_addresses_are_normalised(text, expected):
    assert wol.parse_mac(text) == expected


@pytest.mark.parametrize("text", [
    '00:11:22:33:44:5"; Start-Process calc; "', "00:11:22:33:44:55; calc", "00:11:22:33:44:55 00:11:22:33:44:66",
    "00:11:22:33:44", "00:11:22:33:44:55:66", "00:11:22-33:44:55", "GG:11:22:33:44:55", "", "   ", "$(id)",
    "00:11:22:33:44:55\x00", "a" * 200, "0x001122334455", b"\xff\xfe\xfd", None, 12345, "00:11:22:33:44:5é",
])
def test_anything_that_is_not_exactly_one_mac_is_refused(text):
    assert wol.parse_mac(text) is None


def test_the_magic_packet_has_the_standard_shape():
    packet = wol.magic_packet("aa:bb:cc:dd:ee:ff")
    assert len(packet) == 102 and packet[:6] == b"\xff" * 6 and packet[6:] == bytes.fromhex("aabbccddeeff") * 16
    with pytest.raises(ValueError):
        wol.magic_packet("not a mac")


def test_a_broadcast_really_goes_out_on_the_wire():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(2)
    port = receiver.getsockname()[1]
    assert wol.broadcast_magic_packet("aa:bb:cc:dd:ee:ff", ["127.0.0.1"], ports=(port,), repeats=1, pause=0) == 1
    assert receiver.recvfrom(256)[0] == wol.magic_packet("aa:bb:cc:dd:ee:ff")
    receiver.close()


MAC = b"aa:bb:cc:dd:ee:ff"


def test_only_the_server_may_ask_for_a_wake():
    policy = wol.RelayPolicy({"192.0.2.10"})
    assert policy.check("192.0.2.10", MAC, now=0) == "AA:BB:CC:DD:EE:FF"
    assert policy.check("192.0.2.99", MAC, now=0) is None   # any other machine on the LAN
    assert policy.check("127.0.0.1", MAC, now=0) is None


def test_a_malformed_request_is_ignored_even_from_the_server():
    policy = wol.RelayPolicy({"192.0.2.10"})
    assert policy.check("192.0.2.10", b'aa:bb:cc:dd:ee:f"; calc', now=0) is None
    assert policy.check("192.0.2.10", b"", now=0) is None


def test_requests_are_rate_limited_per_source_and_in_total():
    policy = wol.RelayPolicy({"192.0.2.10", "192.0.2.11", "192.0.2.12"}, per_source_per_minute=3, total_per_minute=5)
    assert [bool(policy.check("192.0.2.10", MAC, now=t)) for t in range(4)] == [True, True, True, False]
    assert [bool(policy.check("192.0.2.11", MAC, now=t)) for t in (4, 5)] == [True, True]
    assert policy.check("192.0.2.12", MAC, now=6) is None           # the relay-wide budget is spent
    assert policy.check("192.0.2.12", MAC, now=70) == "AA:BB:CC:DD:EE:FF"   # a minute later it recovers


def test_junk_does_not_use_up_the_budget_of_real_requests():
    policy = wol.RelayPolicy({"192.0.2.10"}, per_source_per_minute=2)
    for _ in range(50):
        policy.check("192.0.2.10", b"junk", now=0)
    assert policy.check("192.0.2.10", MAC, now=1) and policy.check("192.0.2.10", MAC, now=2)


def test_anyone_can_be_allowed_only_by_asking_for_it_and_sources_can_change():
    open_policy = wol.RelayPolicy(None)
    assert open_policy.check("203.0.113.9", MAC, now=0)
    policy = wol.RelayPolicy({"192.0.2.10"})
    policy.update_sources({"192.0.2.77"})
    assert policy.check("192.0.2.10", MAC, now=0) is None and policy.check("192.0.2.77", MAC, now=0)
    assert wol.RelayPolicy(set()).check("192.0.2.10", MAC, now=0) is None   # no known server: nobody is trusted


def test_the_servers_addresses_are_worked_out_from_its_url():
    assert "127.0.0.1" in wol.resolve_sources("http://localhost:8000/api/v1/agents")
    assert wol.resolve_sources("https://192.0.2.10/api/v1/agents") == {"192.0.2.10"}
    assert wol.resolve_sources("https://192.0.2.10/api", "192.0.2.50, 192.0.2.51") == {"192.0.2.10", "192.0.2.50", "192.0.2.51"}
    assert wol.resolve_sources("http://no-such-host.invalid/api") == set()
    assert wol.resolve_sources("") == set()


def test_the_agent_relay_uses_the_policy_instead_of_trusting_every_datagram():
    pytest.importorskip("psutil")
    from agent import main
    source = inspect.getsource(main._start_wol_relay)
    assert "RelayPolicy" in source and "policy.check" in source and "bytes.fromhex" not in source


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, BASE_DIR / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_wol_tool_validates_the_mac_before_doing_anything(capsys):
    tool = load_script("wol_tool")
    assert tool.main(["send", "00:11:22:33:44:5;calc"]) == 2
    assert tool.main(["relay", "nonsense", "--via", "127.0.0.1"]) == 2
    assert "not a MAC address" in capsys.readouterr().err


def test_the_wol_tool_asks_a_relay_with_a_clean_mac(capsys):
    tool = load_script("wol_tool")
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(2)
    port = listener.getsockname()[1]
    assert tool.main(["relay", "aa-bb-cc-dd-ee-ff", "--via", "127.0.0.1", "--port", str(port)]) == 0
    assert listener.recvfrom(64)[0] == b"AA:BB:CC:DD:EE:FF"
    listener.close()


def test_the_unsafe_loose_scripts_are_gone():
    for name in ("test_relay_listener.py", "trigger_relay.py", "test_wol.py"):
        assert not (BASE_DIR / name).exists(), name
    for path in BASE_DIR.glob("*.py"):
        assert "powershell" not in path.read_text(errors="ignore").lower(), path


# --- the development launcher -----------------------------------------------------------------------------------------

SCRIPT = BASE_DIR / "scripts" / "dev_services.sh"


@pytest.fixture
def sandbox(tmp_path):
    env = {**os.environ, "AIM_RUN_DIR": str(tmp_path / "run"), "AIM_LOG_DIR": str(tmp_path / "logs"), "STOP_WAIT": "3"}
    spawned = []

    def spawn(argv0, *command):
        """A process whose command line starts with argv0, in its own session (as the launcher makes them)."""
        proc = subprocess.Popen(["bash", "-c", f'exec -a "{argv0}" "$@"', "x", *command], start_new_session=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        spawned.append(proc)
        time.sleep(0.2)
        return proc

    def write_pid(name, proc):
        (tmp_path / "run").mkdir(exist_ok=True)
        (tmp_path / "run" / f"{name}.pid").write_text(str(proc.pid))

    def run(*args, extra_env=None):
        return subprocess.run(["bash", str(SCRIPT), *args], env={**env, **(extra_env or {})}, capture_output=True, text=True, timeout=60)

    def alive(proc):
        return proc.poll() is None

    class Sandbox:
        pass

    box = Sandbox()
    box.spawn, box.write_pid, box.run, box.alive, box.path, box.env = spawn, write_pid, run, alive, tmp_path, env
    yield box
    for proc in spawned:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.wait()
    # anything the script itself started
    for pidfile in (tmp_path / "run").glob("*.pid") if (tmp_path / "run").exists() else []:
        try:
            os.killpg(int(pidfile.read_text()), signal.SIGKILL)
        except (ValueError, ProcessLookupError, PermissionError):
            pass


linux_only = pytest.mark.skipif(not LINUX, reason="uses /proc and process groups")


@linux_only
def test_stop_ends_the_service_it_started_and_nothing_else(sandbox):
    service = sandbox.spawn("uvicorn backend.app.main:app", "sleep", "300")
    bystander = sandbox.spawn("uvicorn", "sleep", "301")      # another uvicorn on the machine, not ours
    sandbox.write_pid("backend", service)

    result = sandbox.run("stop")
    assert result.returncode == 0 and "backend stopped" in result.stdout
    service.wait(timeout=5)
    assert not sandbox.alive(service)
    assert sandbox.alive(bystander)          # `pkill -f uvicorn` would have killed this too
    assert not (sandbox.path / "run" / "backend.pid").exists()


@linux_only
def test_stop_never_touches_a_process_that_only_reuses_the_pid(sandbox):
    stranger = sandbox.spawn("some-unrelated-program", "sleep", "300")
    sandbox.write_pid("backend", stranger)
    result = sandbox.run("stop")
    assert "stale pid file" in result.stdout and "leaving that process alone" in result.stdout
    assert sandbox.alive(stranger)
    assert not (sandbox.path / "run" / "backend.pid").exists()


@linux_only
def test_stop_takes_down_the_whole_process_group(sandbox):
    parent = sandbox.spawn("uvicorn", "bash", "-c", "sleep 300 & wait")
    child_pids = subprocess.run(["pgrep", "-P", str(parent.pid)], capture_output=True, text=True).stdout.split()
    assert child_pids
    sandbox.write_pid("backend", parent)
    sandbox.run("stop")
    parent.wait(timeout=5)
    time.sleep(0.3)
    assert all(not os.path.exists(f"/proc/{pid}") or open(f"/proc/{pid}/stat").read().split()[2] == "Z" for pid in child_pids)


@linux_only
def test_a_service_that_ignores_sigterm_is_killed_after_the_wait(sandbox):
    stubborn = sandbox.spawn("uvicorn", "bash", "-c", "trap '' TERM; while true; do sleep 1; done")
    sandbox.write_pid("backend", stubborn)
    start = time.monotonic()
    result = sandbox.run("stop", extra_env={"STOP_WAIT": "1"})
    assert "SIGKILL" in result.stdout and time.monotonic() - start < 10
    stubborn.wait(timeout=5)
    assert not sandbox.alive(stubborn)


@linux_only
def test_status_reports_running_and_stopped(sandbox):
    assert sandbox.run("status").returncode == 3
    service = sandbox.spawn("uvicorn", "sleep", "300")
    sandbox.write_pid("backend", service)
    result = sandbox.run("status")
    assert f"backend: running (pid {service.pid})" in result.stdout and "agent: stopped" in result.stdout


@linux_only
def test_start_needs_a_virtualenv_and_a_settings_file(sandbox):
    result = sandbox.run("start", extra_env={"VENV": str(sandbox.path / "nope")})
    assert result.returncode == 1 and "No virtual environment" in result.stderr
    venv = sandbox.path / "venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "uvicorn").write_text("#!/usr/bin/env bash\nexec -a \"uvicorn $*\" sleep 300\n")
    (venv / "uvicorn").chmod(0o755)
    result = sandbox.run("start", extra_env={"VENV": str(sandbox.path / "venv"), "AIM_ENV_FILE": str(sandbox.path / "missing.env")})
    assert result.returncode == 1 and "is missing" in result.stderr


@linux_only
def test_start_runs_the_service_once_and_stop_ends_it(sandbox):
    venv = sandbox.path / "venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "uvicorn").write_text("#!/usr/bin/env bash\nexec -a \"uvicorn $*\" sleep 300\n")
    (venv / "uvicorn").chmod(0o755)
    (sandbox.path / "settings.env").write_text("SECRET_KEY=x\n")
    env = {"VENV": str(sandbox.path / "venv"), "AIM_ENV_FILE": str(sandbox.path / "settings.env"), "WITH_AGENT": "0"}

    first = sandbox.run("start", extra_env=env)
    assert "backend started" in first.stdout, first.stdout + first.stderr
    pid = int((sandbox.path / "run" / "backend.pid").read_text())
    assert os.path.exists(f"/proc/{pid}")

    second = sandbox.run("start", extra_env=env)
    assert "backend already running" in second.stdout and int((sandbox.path / "run" / "backend.pid").read_text()) == pid

    assert "backend stopped" in sandbox.run("stop", extra_env=env).stdout
    time.sleep(0.3)
    assert not os.path.exists(f"/proc/{pid}") or open(f"/proc/{pid}/stat").read().split()[2] == "Z"


def test_the_launchers_do_not_kill_by_name_or_assume_a_home_directory():
    def code_of(text):  # comments may explain what is NOT done, so only real lines count
        return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))

    for name in ("start_all.sh", "stop_all.sh", "scripts/dev_services.sh"):
        text = (BASE_DIR / name).read_text()
        assert "\r" not in text, name
        code = code_of(text)
        assert "pkill" not in code and "killall" not in code, name
        assert "/home/" not in code, name
    code = code_of(SCRIPT.read_text())
    assert "kill -9" not in code and "-KILL" in code  # SIGKILL only after SIGTERM was ignored



def test_the_launchers_are_executable():
    if not LINUX:
        pytest.skip("file modes")
    for name in ("start_all.sh", "stop_all.sh", "scripts/dev_services.sh", "scripts/wol_tool.py"):
        assert os.access(BASE_DIR / name, os.X_OK), name


# --- service, log rotation, CI ------------------------------------------------------------------------------------------

UNIT = (BASE_DIR / "deploy" / "systemd" / "ai-itmonitor-backend.service").read_text()


def unit_values(key):
    return re.findall(rf"^{key}=(.*)$", UNIT, re.M)


def test_the_service_is_sandboxed_and_not_run_as_root():
    for line in ("NoNewPrivileges=true", "PrivateTmp=true", "ProtectSystem=strict", "ProtectHome=read-only",
                 "RestrictSUIDSGID=true", "ProtectKernelTunables=true", "LockPersonality=true", "RestrictNamespaces=true"):
        assert line in UNIT, line
    assert unit_values("User") == ["__SERVICE_USER__"]
    assert unit_values("CapabilityBoundingSet") == ["CAP_NET_RAW"]  # ping, nothing more


def test_the_service_migrates_first_listens_locally_and_restarts_on_failure():
    assert unit_values("ExecStartPre")[0].endswith("python scripts/migrate.py")
    assert "--host 127.0.0.1" in unit_values("ExecStart")[0]
    assert unit_values("Restart") == ["on-failure"]
    assert unit_values("StateDirectory") == ["ai-itmonitor"] and unit_values("Environment").count("OUI_CACHE_DIR=/var/lib/ai-itmonitor") == 1


def test_the_service_template_has_only_the_two_documented_placeholders():
    assert set(re.findall(r"__[A-Z_]+__", UNIT)) == {"__APP_DIR__", "__SERVICE_USER__"}


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed")
def test_systemd_accepts_the_unit(tmp_path):
    (tmp_path / "app" / "venv" / "bin").mkdir(parents=True)
    for name in ("python", "uvicorn"):
        f = tmp_path / "app" / "venv" / "bin" / name
        f.write_text("#!/bin/sh\n")
        f.chmod(0o755)
    unit = tmp_path / "ai-itmonitor-backend.service"
    unit.write_text(UNIT.replace("__APP_DIR__", str(tmp_path / "app")).replace("__SERVICE_USER__", os.environ.get("USER", "root")))
    result = subprocess.run(["systemd-analyze", "verify", str(unit)], capture_output=True, text=True)
    assert result.returncode == 0 and result.stderr.strip() == "", result.stderr


def test_logs_are_rotated():
    text = (BASE_DIR / "deploy" / "logrotate" / "ai-itmonitor").read_text()
    assert "copytruncate" in text and "compress" in text and "rotate 8" in text and "__APP_DIR__/logs/*.log" in text
    compose = yaml.safe_load((BASE_DIR / "docker-compose.yml").read_text())
    for name, service in compose["services"].items():
        assert service["logging"]["driver"] == "json-file" and service["logging"]["options"]["max-size"], name


WORKFLOW = yaml.safe_load((BASE_DIR / ".github" / "workflows" / "ci.yml").read_text())


def steps_text(job):
    return "\n".join(str(s.get("run", "")) + " " + str(s.get("uses", "")) for s in WORKFLOW["jobs"][job]["steps"])


def test_ci_runs_tests_audits_lint_build_and_images():
    assert set(WORKFLOW["jobs"]) == {"backend", "python-audit", "frontend", "containers"}
    assert "pytest" in steps_text("backend") and "requirements-dev.txt" in steps_text("backend")
    assert "pip-audit" in steps_text("python-audit")
    frontend = steps_text("frontend")
    assert "npm ci" in frontend and "npm run lint" in frontend and "npm run build" in frontend and "npm audit" in frontend
    containers = steps_text("containers")
    assert "docker build" in containers and "Dockerfile.backend" in containers and "Dockerfile.frontend" in containers
    assert "compose" in containers and "10001" in containers


def test_ci_has_least_privilege_and_pinned_actions():
    assert WORKFLOW["permissions"] == {"contents": "read"}
    for job in WORKFLOW["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.search(r"@v\d+$", step["uses"]), step["uses"]  # a version, never a moving branch


def test_dependabot_watches_python_javascript_and_the_workflows():
    config = yaml.safe_load((BASE_DIR / ".github" / "dependabot.yml").read_text())
    assert {u["package-ecosystem"] for u in config["updates"]} == {"pip", "npm", "github-actions"}


# --- dead code ---------------------------------------------------------------------------------------------------------------

def test_dead_code_is_gone():
    assert not (BASE_DIR / "backend" / "app" / "schemas").exists()
    assert "_AGENT_BUNDLE" not in (BASE_DIR / "backend" / "app" / "api" / "endpoints" / "agents.py").read_text()


def test_the_run_and_log_directories_are_not_committed():
    ignored = (BASE_DIR / ".gitignore").read_text().splitlines()
    assert "run/" in ignored and "logs/" in ignored
