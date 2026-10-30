import hashlib
import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from agent import bundle as agent_bundle
from agent import signing as agent_side
from backend.app.api.endpoints import agents
from backend.app.core.database import Base, get_db
from backend.app.core.security import create_access_token
from backend.app.models.entities import AgentCommand, AuditLog, Machine, User
from backend.app.services import agent_signing as server_side

KEY = "a-shared-agent-key-long-enough"
BASE = "/api/v1/agents"
SUPPORT = {"X-Agent-Token-Support": "1"}


# --- the two copies of the signing code must agree ----------------------------------------------

def test_agent_and_server_build_the_same_messages_and_signatures():
    payload = {"pid": 42, "command_str": "ünï", "b": [1, 2]}
    assert agent_side.command_message("AGENT-X", 7, "KILL_PROCESS", payload, "2026-10-30T10:00:00Z") == \
        server_side.command_message("AGENT-X", 7, "KILL_PROCESS", payload, "2026-10-30T10:00:00Z")
    assert agent_side.bundle_message("windows", "1.3.0", "ab" * 32) == server_side.bundle_message("windows", "1.3.0", "ab" * 32)
    assert agent_side.hint_message("https://h/api") == server_side.hint_message("https://h/api")
    assert agent_side.sign("m", KEY) == server_side.sign("m", KEY)


def test_payload_key_order_does_not_change_the_signature():
    a = agent_side.command_message("A", 1, "T", {"x": 1, "y": 2}, "e")
    b = agent_side.command_message("A", 1, "T", {"y": 2, "x": 1}, "e")
    assert a == b


def test_verify_rejects_missing_wrong_and_unkeyed():
    sig = agent_side.sign("hello", KEY)
    assert agent_side.verify("hello", sig, KEY)
    assert not agent_side.verify("hello!", sig, KEY)
    assert not agent_side.verify("hello", sig, KEY + "x")
    assert not agent_side.verify("hello", None, KEY)
    assert not agent_side.verify("hello", "", KEY)
    assert not agent_side.verify("hello", sig, "")
    assert agent_side.sign("hello", "") is None


# --- the update bundle check -----------------------------------------------------------------------

def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def signed(content, version="1.3.0", os_name="windows", key=KEY):
    digest = hashlib.sha256(content).hexdigest()
    return {"x-bundle-version": version, "x-bundle-sha256": digest,
            "x-bundle-signature": agent_side.sign(agent_side.bundle_message(os_name, version, digest), key)}


def check(content, headers, os_name="windows", current="1.2.1", key=KEY, url="http://server/api/v1/agents"):
    return agent_bundle.verify_bundle(content, headers, os_name, current, key, url)


def test_a_correctly_signed_newer_bundle_is_accepted():
    content = make_zip({"agent/main.py": "x"})
    assert check(content, signed(content)) == (True, "ok")


def test_a_bundle_changed_after_signing_is_refused():
    content = make_zip({"agent/main.py": "x"})
    headers = signed(content)
    tampered = make_zip({"agent/main.py": "import os; os.system('evil')"})
    ok, reason = check(tampered, headers)
    assert not ok and "hash" in reason


def test_a_bundle_whose_hash_was_replaced_too_is_still_refused():
    evil = make_zip({"agent/main.py": "evil"})
    headers = {"x-bundle-version": "9.9.9", "x-bundle-sha256": hashlib.sha256(evil).hexdigest(),
               "x-bundle-signature": "0" * 64}
    assert not check(evil, headers)[0]


def test_a_bundle_signed_with_another_key_is_refused():
    content = make_zip({"agent/main.py": "x"})
    assert not check(content, signed(content, key="someone-elses-key-entirely-123"))[0]


def test_a_bundle_signed_for_another_os_is_refused():
    content = make_zip({"agent/main.py": "x"})
    assert not check(content, signed(content, os_name="linux"), os_name="windows")[0]


def test_a_missing_signature_is_refused_when_a_key_is_configured():
    content = make_zip({"agent/main.py": "x"})
    headers = signed(content)
    del headers["x-bundle-signature"]
    assert not check(content, headers)[0]
    assert not check(content, {})[0]


@pytest.mark.parametrize("version", ["1.2.1", "1.2.0", "0.9.0"])
def test_an_old_signed_bundle_cannot_downgrade_the_agent(version):
    content = make_zip({"agent/main.py": "x"})
    ok, reason = check(content, signed(content, version=version), current="1.2.1")
    assert not ok and "not newer" in reason


def test_without_a_key_only_https_is_trusted():
    content = make_zip({"agent/main.py": "x"})
    headers = {"x-bundle-version": "1.3.0"}
    assert not check(content, headers, key="", url="http://server/api")[0]
    assert check(content, headers, key="", url="https://server/api")[0]


# --- unpacking ---------------------------------------------------------------------------------------

def test_only_the_agent_folder_is_unpacked(tmp_path):
    content = make_zip({"agent/main.py": "m", "agent/collectors/metrics.py": "c", "run.bat": "bat", "README.txt": "r"})
    assert agent_bundle.safe_extract(content, tmp_path) == 2
    assert (tmp_path / "agent" / "collectors" / "metrics.py").read_text() == "c"
    assert not (tmp_path / "run.bat").exists()


def test_local_state_is_never_replaced_by_an_update(tmp_path):
    content = make_zip({"agent/main.py": "m", "agent/agent_config.json": '{"agent_token": "stolen"}'})
    agent_bundle.safe_extract(content, tmp_path)
    assert not (tmp_path / "agent" / "agent_config.json").exists()


@pytest.mark.parametrize("name", ["../evil.py", "agent/../../evil.py", "/etc/cron.d/x", "C:/Windows/evil.dll",
                                  "agent/..\\..\\evil.py"])
def test_paths_that_escape_the_folder_are_refused(tmp_path, name):
    dest = tmp_path / "staging"
    dest.mkdir()
    with pytest.raises(ValueError):
        agent_bundle.safe_extract(make_zip({"agent/main.py": "m", name: "evil"}), dest)
    assert not (tmp_path / "evil.py").exists()


def test_links_are_refused(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("agent/link")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    with pytest.raises(ValueError):
        agent_bundle.safe_extract(buf.getvalue(), tmp_path)


def test_oversized_bundles_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_bundle, "MAX_TOTAL_BYTES", 100)
    with pytest.raises(ValueError):
        agent_bundle.safe_extract(make_zip({"agent/big.bin": "x" * 500}), tmp_path)
    monkeypatch.setattr(agent_bundle, "MAX_FILES", 2)
    with pytest.raises(ValueError):
        agent_bundle.safe_extract(make_zip({f"agent/{i}.py": "x" for i in range(3)}), tmp_path)


# --- the agent's own decisions -----------------------------------------------------------------------

@pytest.fixture
def agent_main():
    pytest.importorskip("psutil")
    from agent import main
    return main


def test_a_hint_to_the_same_host_is_followed(agent_main, monkeypatch):
    monkeypatch.setattr(agent_main, "SERVER_URL", "http://monitor.corp:8000/api/v1/agents")
    assert agent_main._hint_allowed("https://monitor.corp/api/v1/agents", None, {})
    assert agent_main._hint_allowed("https://monitor.corp:8443/api/v1/agents", None, {})


def test_a_hint_to_another_host_needs_the_servers_signature(agent_main, monkeypatch):
    monkeypatch.setattr(agent_main, "SERVER_URL", "http://monitor.corp:8000/api/v1/agents")
    monkeypatch.setattr(agent_main, "AGENT_API_KEY", KEY)
    other = "https://evil.example/api/v1/agents"
    assert not agent_main._hint_allowed(other, None, {})
    assert not agent_main._hint_allowed(other, "0" * 64, {})
    assert agent_main._hint_allowed(other, agent_side.sign(agent_side.hint_message(other), KEY), {})


def test_a_signature_for_one_hint_does_not_cover_another(agent_main, monkeypatch):
    monkeypatch.setattr(agent_main, "SERVER_URL", "http://monitor.corp/api")
    monkeypatch.setattr(agent_main, "AGENT_API_KEY", KEY)
    sig = agent_side.sign(agent_side.hint_message("https://new.corp/api"), KEY)
    assert not agent_main._hint_allowed("https://evil.example/api", sig, {})


@pytest.mark.parametrize("hint", ["http://monitor.corp/api", "ftp://monitor.corp/api",
                                  "https://user:pw@monitor.corp/api", "https:///api", "javascript:alert(1)"])
def test_unusable_hints_are_refused_even_for_the_known_host(agent_main, monkeypatch, hint):
    monkeypatch.setattr(agent_main, "SERVER_URL", "http://monitor.corp/api")
    assert not agent_main._hint_allowed(hint, None, {})


def test_hosts_can_be_allowed_by_the_operator(agent_main, monkeypatch):
    monkeypatch.setattr(agent_main, "SERVER_URL", "http://monitor.corp/api")
    monkeypatch.setenv("AGENT_ALLOWED_HOSTS", "new.corp, other.corp")
    assert agent_main._hint_allowed("https://new.corp/api", None, {})
    assert not agent_main._hint_allowed("https://third.corp/api", None, {})


def test_the_original_server_still_counts_after_a_switch(agent_main, monkeypatch):
    monkeypatch.setattr(agent_main, "SERVER_URL", "https://monitor.corp/api")
    assert agent_main._hint_allowed("https://old.corp/api", None, {"original_server_url": "http://old.corp:8000/api"})


def test_unsigned_commands_are_not_run_when_a_key_is_configured(agent_main, monkeypatch):
    monkeypatch.setattr(agent_main, "AGENT_API_KEY", KEY)
    cmd = {"command_id": 5, "type": "EXECUTE_SHELL", "payload": {"command_str": "id"}, "expires_at": "2026-10-30T10:00:00Z"}
    assert not agent_main._command_is_authentic("AGENT-A", cmd)
    cmd["signature"] = agent_side.sign(agent_side.command_message(
        "AGENT-A", 5, "EXECUTE_SHELL", {"command_str": "id"}, "2026-10-30T10:00:00Z"), KEY)
    assert agent_main._command_is_authentic("AGENT-A", cmd)
    assert not agent_main._command_is_authentic("AGENT-B", cmd)  # meant for another agent
    assert not agent_main._command_is_authentic("AGENT-A", {**cmd, "payload": {"command_str": "rm -rf /"}})
    assert not agent_main._command_is_authentic("AGENT-A", {**cmd, "type": "REBOOT_SYSTEM"})
    assert not agent_main._command_is_authentic("AGENT-A", {**cmd, "command_id": 6})


def test_without_a_key_commands_are_accepted_as_before(agent_main, monkeypatch):
    monkeypatch.setattr(agent_main, "AGENT_API_KEY", "")
    assert agent_main._command_is_authentic("AGENT-A", {"command_id": 1, "type": "REBOOT_SYSTEM"})


# --- the server ---------------------------------------------------------------------------------------

@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def client(db, monkeypatch):
    from backend.app.main import app

    monkeypatch.setattr(agents.settings, "AGENT_API_KEY", KEY)
    monkeypatch.setattr(agents.settings, "REQUIRE_AGENT_TOKEN", False)
    monkeypatch.setattr(server_side.settings, "AGENT_API_KEY", KEY)

    def override():
        yield db

    app.dependency_overrides[get_db] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


AGENT = {"X-Agent-Key": KEY, **SUPPORT}


def make_user(db, email, role="ADMIN", permissions=None):
    db.add(User(email=email, hashed_password="x", role=role, permissions=permissions or []))
    db.commit()
    return {"Authorization": f"Bearer {create_access_token(email)}"}


def enrol(client):
    r = client.post(f"{BASE}/register", json={"hostname": "PC1", "os_name": "Linux", "machine_uid": "aabbccddeeff"}, headers=AGENT)
    assert r.status_code == 200, r.text
    return r.json()


def test_dispatched_commands_carry_a_signature_the_agent_accepts(client, db, monkeypatch):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    mid = db.query(Machine).one().id
    client.post(f"{BASE}/machines/{mid}/remote-action", json={"command_type": "EXECUTE_SHELL", "command_str": "uptime"}, headers=admin)

    body = {"agent_id": e["agent_id"], "cpu_percent": 1, "ram_percent": 1, "ram_used_gb": 1, "ram_total_gb": 2,
            "disk_percent": 1, "disk_used_gb": 1, "disk_total_gb": 2}
    r = client.post(f"{BASE}/metrics", json=body, headers={**AGENT, "X-Agent-Token": e["agent_token"]})
    cmd = r.json()["pending_commands"][0]

    message = agent_side.command_message(e["agent_id"], cmd["command_id"], cmd["type"], cmd["payload"], cmd["expires_at"])
    assert agent_side.verify(message, cmd["signature"], KEY)
    assert cmd["expires_at"].endswith("Z")
    assert not agent_side.verify(message.replace("uptime", "id"), cmd["signature"], KEY)


def test_the_https_hint_is_signed(client, db, monkeypatch):
    monkeypatch.setattr(agents.settings, "PUBLIC_HTTPS_BASE_URL", "https://monitor.corp/api/v1/agents")
    e = enrol(client)
    body = {"agent_id": e["agent_id"], "cpu_percent": 1, "ram_percent": 1, "ram_used_gb": 1, "ram_total_gb": 2,
            "disk_percent": 1, "disk_used_gb": 1, "disk_total_gb": 2}
    data = client.post(f"{BASE}/metrics", json=body, headers={**AGENT, "X-Agent-Token": e["agent_token"]}).json()
    assert agent_side.verify(agent_side.hint_message(data["https_hint"]), data["https_hint_sig"], KEY)


def test_without_a_key_nothing_is_signed(client, db, monkeypatch):
    monkeypatch.setattr(agents.settings, "AGENT_API_KEY", "")
    monkeypatch.setattr(server_side.settings, "AGENT_API_KEY", "")
    monkeypatch.setattr(agents.settings, "PUBLIC_HTTPS_BASE_URL", "")
    e = client.post(f"{BASE}/register", json={"hostname": "PC1", "os_name": "L"}, headers=SUPPORT).json()
    body = {"agent_id": e["agent_id"], "cpu_percent": 1, "ram_percent": 1, "ram_used_gb": 1, "ram_total_gb": 2,
            "disk_percent": 1, "disk_used_gb": 1, "disk_total_gb": 2}
    data = client.post(f"{BASE}/metrics", json=body, headers={"X-Agent-Token": e["agent_token"]}).json()
    assert data["https_hint_sig"] is None


@pytest.fixture
def agent_tree(tmp_path, monkeypatch):
    """A copy of the agent folder with a leftover config file and key material in it, as happens on a
    server where an agent has ever been run from the same checkout."""
    src = tmp_path / "agent"
    (src / "collectors").mkdir(parents=True)
    (src / "main.py").write_text("print('agent')")
    (src / "version.py").write_text('AGENT_VERSION = "1.2.1"\n')
    (src / "collectors" / "metrics.py").write_text("x = 1")
    (src / "agent_config.json").write_text('{"agent_id": "AGENT-SECRET", "agent_token": "agt_secret"}')
    (src / "server.key").write_text("-----BEGIN PRIVATE KEY-----")
    (src / ".env").write_text("AGENT_API_KEY=secret")
    monkeypatch.setattr(agents, "_AGENT_SRC", str(src))
    return src


def test_downloading_needs_credentials(client, agent_tree):
    r = client.get(f"{BASE}/download?os=windows")
    assert r.status_code == 401
    assert client.get(f"{BASE}/download?os=windows", headers={"X-Agent-Key": "wrong"}).status_code == 401
    assert client.get(f"{BASE}/download?os=windows", headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_a_user_without_agents_manage_cannot_download(client, db, agent_tree):
    viewer = make_user(db, "viewer@example.com", role="VIEWER")
    assert client.get(f"{BASE}/download?os=windows", headers=viewer).status_code == 403


def test_an_admin_can_download_and_it_is_audited(client, db, agent_tree):
    admin = make_user(db, "admin@example.com")
    r = client.get(f"{BASE}/download?os=windows", headers=admin)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    entry = db.query(AuditLog).filter(AuditLog.action == "agent.download").one()
    assert entry.actor_email == "admin@example.com" and entry.target == "windows"


def test_an_agent_can_download_with_the_shared_key_and_it_is_not_audited(client, db, agent_tree):
    r = client.get(f"{BASE}/download?os=windows", headers={"X-Agent-Key": KEY})
    assert r.status_code == 200
    assert db.query(AuditLog).count() == 0


def test_the_bundle_never_contains_local_state_or_key_material(client, db, agent_tree):
    r = client.get(f"{BASE}/download?os=linux", headers={"X-Agent-Key": KEY})
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert "agent/main.py" in names and "agent/collectors/metrics.py" in names
    assert not any(n.endswith(("agent_config.json", "server.key", ".env")) for n in names)
    assert b"AGENT-SECRET" not in r.content and b"agt_secret" not in r.content


def test_the_download_is_signed_and_the_agent_accepts_it(client, db, agent_tree):
    r = client.get(f"{BASE}/download?os=windows", headers={"X-Agent-Key": KEY})
    headers = {k.lower(): v for k, v in r.headers.items()}
    assert headers["x-bundle-version"] == "1.2.1"
    # An agent already running 1.2.0 takes it ...
    assert agent_bundle.verify_bundle(r.content, headers, "windows", "1.2.0", KEY, "http://s/api") == (True, "ok")
    # ... but not as a replacement for the same version, nor for the wrong OS, nor with the wrong key.
    assert not agent_bundle.verify_bundle(r.content, headers, "windows", "1.2.1", KEY, "http://s/api")[0]
    assert not agent_bundle.verify_bundle(r.content, headers, "linux", "1.2.0", KEY, "http://s/api")[0]
    assert not agent_bundle.verify_bundle(r.content, headers, "windows", "1.2.0", "another-key-of-sufficient-len", "http://s/api")[0]
    assert r.headers["cache-control"] == "no-store"


def test_the_bundle_delivered_unpacks_cleanly(client, db, agent_tree, tmp_path):
    r = client.get(f"{BASE}/download?os=windows", headers={"X-Agent-Key": KEY})
    dest = tmp_path / "staging"
    dest.mkdir()
    assert agent_bundle.safe_extract(r.content, dest) >= 3
    assert (dest / "agent" / "main.py").exists() and not (dest / "agent" / "agent_config.json").exists()
