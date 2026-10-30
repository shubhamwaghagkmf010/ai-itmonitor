from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import agents
from backend.app.core.database import Base, get_db
from backend.app.core.security import create_access_token
from backend.app.models.entities import AgentCommand, AuditLog, Machine, User
from backend.app.services import agent_commands as ac

BASE = "/api/v1/agents"
SUPPORT = {"X-Agent-Token-Support": "1"}


# --- the pure rules ----------------------------------------------------------------------------

def test_tokens_are_random_and_only_the_hash_is_kept():
    a, b = ac.new_agent_token(), ac.new_agent_token()
    assert a != b and a.startswith("agt_") and len(a) > 40
    assert ac.hash_agent_token(a) != a
    assert ac.token_matches(a, ac.hash_agent_token(a))
    assert not ac.token_matches(b, ac.hash_agent_token(a))
    assert not ac.token_matches(None, ac.hash_agent_token(a))
    assert not ac.token_matches(a, None)


@pytest.mark.parametrize("pid", [0, 1, -5, ac.MAX_PID + 1, "12", None, True, 3.5])
def test_unusable_pids_are_refused(pid):
    with pytest.raises(ac.CommandRejected):
        ac.validate_pid(pid)


def test_a_normal_pid_is_accepted():
    assert ac.validate_pid(4242) == 4242


@pytest.mark.parametrize("ctype", ["UPDATE_AGENT", "rm -rf /", "", "KILL", "SERVICE_DELETE", "EXECUTE_SHELL; reboot"])
def test_only_listed_actions_can_be_queued(ctype):
    with pytest.raises(ac.CommandRejected):
        ac.validate_remote_action(ctype, "x", 100)


def test_action_names_are_normalised():
    assert ac.validate_remote_action(" reboot_system ", None, None) == ("REBOOT_SYSTEM", {})


def test_shell_commands_are_trimmed_and_bounded():
    assert ac.validate_remote_action("EXECUTE_SHELL", "  uptime  ", None) == ("EXECUTE_SHELL", {"command_str": "uptime"})
    for bad in ["", "   ", None, "x" * (ac.MAX_SHELL_LENGTH + 1), "ls\x00"]:
        with pytest.raises(ac.CommandRejected):
            ac.validate_remote_action("EXECUTE_SHELL", bad, None)


@pytest.mark.parametrize("name", ["nginx", "ssh.service", "Spooler", "user@1000.service", "My Service"])
def test_ordinary_service_names_are_accepted(name):
    assert ac.validate_remote_action("SERVICE_RESTART", name, None)[1] == {"command_str": name}


@pytest.mark.parametrize("name", ["", "nginx; rm -rf /", "a|b", "$(id)", "a`b`", "x" * 129, "a\nb", "a&b"])
def test_service_names_cannot_carry_shell_syntax(name):
    with pytest.raises(ac.CommandRejected):
        ac.validate_remote_action("SERVICE_STOP", name, None)


def test_kill_needs_a_valid_pid_and_ignores_other_fields():
    assert ac.validate_remote_action("KILL_PROCESS", "ignored", 777) == ("KILL_PROCESS", {"pid": 777})
    with pytest.raises(ac.CommandRejected):
        ac.validate_remote_action("KILL_PROCESS", None, None)


# --- the application, against an in-memory database --------------------------------------------

@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    session = Session()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def client(db, monkeypatch):
    from backend.app.main import app

    monkeypatch.setattr(agents.settings, "AGENT_API_KEY", "")
    monkeypatch.setattr(agents.settings, "REQUIRE_AGENT_TOKEN", False)

    def override():
        yield db

    app.dependency_overrides[get_db] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def make_user(db, email, role="ADMIN", permissions=None):
    db.add(User(email=email, hashed_password="x", role=role, permissions=permissions or []))
    db.commit()
    return {"Authorization": f"Bearer {create_access_token(email)}"}


def enrol(client, hostname="PC1", uid="aabbccddeeff", headers=SUPPORT):
    r = client.post(f"{BASE}/register", json={"hostname": hostname, "os_name": "Linux", "machine_uid": uid}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def metrics(client, agent_id, token=None, headers=None):
    h = dict(headers or {})
    if token:
        h["X-Agent-Token"] = token
    body = {"agent_id": agent_id, "cpu_percent": 1, "ram_percent": 1, "ram_used_gb": 1, "ram_total_gb": 2,
            "disk_percent": 1, "disk_used_gb": 1, "disk_total_gb": 2}
    return client.post(f"{BASE}/metrics", json=body, headers=h)


def machine_id(db, agent_id):
    return db.query(Machine).filter(Machine.agent_id == agent_id).one().id


# --- enrolment and tokens -----------------------------------------------------------------------

def test_a_token_capable_agent_gets_a_token_that_is_stored_hashed(client, db):
    data = enrol(client)
    token = data["agent_token"]
    stored = db.query(Machine).one().agent_token_hash
    assert stored == ac.hash_agent_token(token) and token not in stored


def test_an_agent_without_token_support_gets_none_and_keeps_working(client, db):
    data = enrol(client, headers={})
    assert "agent_token" not in data
    assert db.query(Machine).one().agent_token_hash is None
    r = metrics(client, data["agent_id"])
    assert r.status_code == 200 and "agent_token" not in r.json()


def test_knowing_the_agent_id_is_not_enough_once_a_token_exists(client):
    data = enrol(client)
    assert metrics(client, data["agent_id"]).status_code == 401
    assert metrics(client, data["agent_id"], token="agt_wrong").status_code == 401
    assert metrics(client, data["agent_id"], token=data["agent_token"]).status_code == 200


def test_a_legacy_machine_is_given_a_token_once_the_agent_can_keep_one(client, db):
    data = enrol(client, headers={})
    r = metrics(client, data["agent_id"], headers=SUPPORT)
    token = r.json()["agent_token"]
    assert metrics(client, data["agent_id"]).status_code == 401
    r2 = metrics(client, data["agent_id"], token=token)
    assert r2.status_code == 200 and "agent_token" not in r2.json()


def test_tokens_can_be_made_mandatory(client, monkeypatch):
    monkeypatch.setattr(agents.settings, "REQUIRE_AGENT_TOKEN", True)
    assert client.post(f"{BASE}/register", json={"hostname": "H", "os_name": "L"}).status_code == 401
    data = enrol(client)
    assert metrics(client, data["agent_id"], token=data["agent_token"]).status_code == 200


def test_requiring_tokens_refuses_a_legacy_machine_that_cannot_get_one(client, monkeypatch):
    data = enrol(client, headers={})
    monkeypatch.setattr(agents.settings, "REQUIRE_AGENT_TOKEN", True)
    assert metrics(client, data["agent_id"]).status_code == 401
    assert metrics(client, data["agent_id"], headers=SUPPORT).status_code == 200


def test_a_live_machine_cannot_be_taken_over_by_registering_again(client):
    first = enrol(client)
    again = client.post(f"{BASE}/register", json={"hostname": "PC1", "os_name": "Linux", "machine_uid": "aabbccddeeff"},
                        headers=SUPPORT)
    assert again.status_code == 409
    assert metrics(client, first["agent_id"], token=first["agent_token"]).status_code == 200


def test_the_real_agent_can_register_again_with_its_token_and_gets_a_new_one(client):
    first = enrol(client)
    r = client.post(f"{BASE}/register", json={"hostname": "PC1", "os_name": "Linux", "machine_uid": "aabbccddeeff"},
                    headers={**SUPPORT, "X-Agent-Token": first["agent_token"]})
    assert r.status_code == 200 and r.json()["agent_token"] != first["agent_token"]
    assert metrics(client, first["agent_id"], token=first["agent_token"]).status_code == 401


def test_a_silent_machine_can_be_enrolled_again_after_a_reinstall(client, db):
    first = enrol(client)
    m = db.query(Machine).one()
    m.last_heartbeat = datetime.now(timezone.utc) - ac.REENROLL_AFTER - timedelta(seconds=5)
    db.commit()
    r = client.post(f"{BASE}/register", json={"hostname": "PC1", "os_name": "Linux", "machine_uid": "aabbccddeeff"},
                    headers=SUPPORT)
    assert r.status_code == 200
    assert metrics(client, first["agent_id"], token=first["agent_token"]).status_code == 401
    assert metrics(client, first["agent_id"], token=r.json()["agent_token"]).status_code == 200


def test_the_shared_key_is_still_required_when_configured(client, monkeypatch):
    monkeypatch.setattr(agents.settings, "AGENT_API_KEY", "an-agent-key-long-enough")
    assert client.post(f"{BASE}/register", json={"hostname": "H", "os_name": "L"}, headers=SUPPORT).status_code == 401


def test_oversized_bodies_and_lists_are_refused(client):
    big = client.post(f"{BASE}/register", json={"hostname": "H", "os_name": "L"}, headers={"Content-Length": "999999"})
    assert big.status_code == 413
    data = enrol(client)
    procs = [{"pid": i, "name": "p", "cpu_percent": 0, "memory_percent": 0} for i in range(201)]
    body = {"agent_id": data["agent_id"], "cpu_percent": 1, "ram_percent": 1, "ram_used_gb": 1, "ram_total_gb": 2,
            "disk_percent": 1, "disk_used_gb": 1, "disk_total_gb": 2, "top_processes": procs}
    r = client.post(f"{BASE}/metrics", json=body, headers={"X-Agent-Token": data["agent_token"]})
    assert r.status_code == 422


# --- queuing commands ----------------------------------------------------------------------------

def queue(client, mid, headers, **body):
    return client.post(f"{BASE}/machines/{mid}/remote-action", json=body, headers=headers)


def audit_actions(db):
    db.expire_all()
    return [(a.action, a.result, a.actor_email) for a in db.query(AuditLog).order_by(AuditLog.id)]


def test_a_queued_action_is_stored_with_requester_and_expiry_and_audited(client, db):
    admin = make_user(db, "admin@example.com")
    mid = machine_id(db, enrol(client)["agent_id"])

    r = queue(client, mid, admin, command_type="EXECUTE_SHELL", command_str="uptime")
    assert r.status_code == 200
    cmd = db.query(AgentCommand).one()
    assert cmd.requested_by == "admin@example.com" and cmd.status == "PENDING"
    assert cmd.payload_json == {"command_str": "uptime"}
    assert cmd.expires_at is not None
    assert ("remote_action", "QUEUED", "admin@example.com") in audit_actions(db)
    entry = db.query(AuditLog).filter(AuditLog.action == "remote_action").one()
    assert entry.details["command_str"] == "uptime" and entry.details["command_id"] == cmd.id


def test_a_rejected_action_is_not_queued_but_is_audited(client, db):
    admin = make_user(db, "admin@example.com")
    mid = machine_id(db, enrol(client)["agent_id"])

    r = queue(client, mid, admin, command_type="FORMAT_DISK", command_str="C:")
    assert r.status_code == 400
    assert db.query(AgentCommand).count() == 0
    assert ("remote_action", "DENIED", "admin@example.com") in audit_actions(db)


@pytest.mark.parametrize("pid", [0, 1, -3, 99999999])
def test_kill_process_validates_the_pid_server_side(client, db, pid):
    admin = make_user(db, "admin@example.com")
    mid = machine_id(db, enrol(client)["agent_id"])
    r = client.post(f"{BASE}/machines/{mid}/kill-process?pid={pid}", headers=admin)
    assert r.status_code == 400 and db.query(AgentCommand).count() == 0
    assert ("process.kill", "DENIED", "admin@example.com") in audit_actions(db)


def test_kill_process_is_queued_and_audited(client, db):
    admin = make_user(db, "admin@example.com")
    mid = machine_id(db, enrol(client)["agent_id"])
    r = client.post(f"{BASE}/machines/{mid}/kill-process?pid=4321", headers=admin)
    assert r.status_code == 200 and r.json()["command_id"]
    assert db.query(AgentCommand).one().payload_json == {"pid": 4321}
    assert ("process.kill", "QUEUED", "admin@example.com") in audit_actions(db)


def test_the_queue_for_one_machine_is_bounded(client, db):
    admin = make_user(db, "admin@example.com")
    mid = machine_id(db, enrol(client)["agent_id"])
    for _ in range(agents.MAX_OPEN_COMMANDS_PER_MACHINE):
        assert queue(client, mid, admin, command_type="REBOOT_SYSTEM").status_code == 200
    assert queue(client, mid, admin, command_type="REBOOT_SYSTEM").status_code == 429


def test_the_audit_ip_is_the_connection_not_a_forwarded_header(client, db):
    admin = make_user(db, "admin@example.com")
    mid = machine_id(db, enrol(client)["agent_id"])
    queue(client, mid, {**admin, "X-Forwarded-For": "10.9.9.9"}, command_type="REBOOT_SYSTEM")
    assert db.query(AuditLog).filter(AuditLog.action == "remote_action").one().ip_address != "10.9.9.9"


def test_a_user_without_the_permission_cannot_queue_anything(client, db):
    viewer = make_user(db, "viewer@example.com", role="VIEWER")
    mid = machine_id(db, enrol(client)["agent_id"])
    assert queue(client, mid, viewer, command_type="REBOOT_SYSTEM").status_code == 403
    assert db.query(AgentCommand).count() == 0


# --- delivery, expiry and results ----------------------------------------------------------------

def test_a_command_is_delivered_once_and_marked_dispatched(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    queue(client, machine_id(db, e["agent_id"]), admin, command_type="REBOOT_SYSTEM")

    first = metrics(client, e["agent_id"], token=e["agent_token"]).json()["pending_commands"]
    second = metrics(client, e["agent_id"], token=e["agent_token"]).json()["pending_commands"]
    assert [c["type"] for c in first] == ["REBOOT_SYSTEM"] and second == []
    assert db.query(AgentCommand).one().status == "DISPATCHED"


def test_a_command_that_waited_too_long_is_never_delivered(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    queue(client, machine_id(db, e["agent_id"]), admin, command_type="REBOOT_SYSTEM")
    cmd = db.query(AgentCommand).one()
    cmd.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()

    assert metrics(client, e["agent_id"], token=e["agent_token"]).json()["pending_commands"] == []
    db.expire_all()
    cmd = db.query(AgentCommand).one()
    assert cmd.status == "EXPIRED" and "not delivered" in cmd.result_output.lower()


def test_commands_from_before_expiry_existed_age_from_their_creation(client, db):
    e = enrol(client)
    mid = machine_id(db, e["agent_id"])
    db.add(AgentCommand(machine_id=mid, command_type="REBOOT_SYSTEM", payload_json={}, status="PENDING",
                        created_at=datetime.now(timezone.utc) - timedelta(hours=3)))
    db.commit()
    assert metrics(client, e["agent_id"], token=e["agent_token"]).json()["pending_commands"] == []
    assert db.query(AgentCommand).one().status == "EXPIRED"


def test_a_delivered_command_that_never_reports_times_out(client, db):
    e = enrol(client)
    mid = machine_id(db, e["agent_id"])
    now = datetime.now(timezone.utc)
    db.add(AgentCommand(machine_id=mid, command_type="REBOOT_SYSTEM", payload_json={}, status="DISPATCHED",
                        expires_at=now - ac.RESULT_GRACE - timedelta(minutes=1)))
    db.commit()
    metrics(client, e["agent_id"], token=e["agent_token"])
    db.expire_all()
    assert db.query(AgentCommand).one().status == "TIMEOUT"


def test_polling_the_output_of_a_stale_command_closes_it(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    mid = machine_id(db, e["agent_id"])
    queue(client, mid, admin, command_type="REBOOT_SYSTEM")
    cmd = db.query(AgentCommand).one()
    cmd.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    r = client.get(f"{BASE}/machines/{mid}/command-output/{cmd.id}", headers=admin)
    assert r.json()["status"] == "EXPIRED"


def test_a_waiting_command_can_be_cancelled_and_then_is_never_delivered(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    mid = machine_id(db, e["agent_id"])
    cid = queue(client, mid, admin, command_type="REBOOT_SYSTEM").json()["command_id"]

    assert client.post(f"{BASE}/machines/{mid}/commands/{cid}/cancel", headers=admin).status_code == 200
    assert metrics(client, e["agent_id"], token=e["agent_token"]).json()["pending_commands"] == []
    assert client.post(f"{BASE}/machines/{mid}/commands/{cid}/cancel", headers=admin).status_code == 409
    assert ("remote_action.cancel", "SUCCESS", "admin@example.com") in audit_actions(db)


def report(client, agent, cid, status="COMPLETED", output="done", token=None):
    h = {"X-Agent-Token": token} if token else {}
    return client.post(f"{BASE}/command-result",
                       json={"agent_id": agent, "command_id": cid, "status": status, "output": output}, headers=h)


def deliver(client, db, admin, enrolment, **action):
    mid = machine_id(db, enrolment["agent_id"])
    cid = queue(client, mid, admin, **action).json()["command_id"]
    metrics(client, enrolment["agent_id"], token=enrolment["agent_token"])
    return cid


def test_an_agent_reports_the_result_of_its_own_command(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    cid = deliver(client, db, admin, e, command_type="EXECUTE_SHELL", command_str="uptime")

    assert report(client, e["agent_id"], cid, output="up 3 days", token=e["agent_token"]).status_code == 200
    db.expire_all()
    cmd = db.query(AgentCommand).one()
    assert cmd.status == "COMPLETED" and cmd.result_output == "up 3 days" and cmd.executed_at is not None
    assert (f"remote_action.result", "COMPLETED", f"agent:{e['agent_id']}") in audit_actions(db)


def test_one_agent_cannot_answer_for_another_agents_command(client, db):
    admin = make_user(db, "admin@example.com")
    victim = enrol(client, "VICTIM", "111111111111")
    attacker = enrol(client, "ATTACKER", "222222222222")
    cid = deliver(client, db, admin, victim, command_type="EXECUTE_SHELL", command_str="uptime")

    r = report(client, attacker["agent_id"], cid, output="forged", token=attacker["agent_token"])
    assert r.status_code == 404
    assert db.query(AgentCommand).one().status == "DISPATCHED"
    assert db.query(AgentCommand).one().result_output is None


def test_a_result_needs_the_agents_own_token(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    cid = deliver(client, db, admin, e, command_type="REBOOT_SYSTEM")
    assert report(client, e["agent_id"], cid).status_code == 401
    assert report(client, e["agent_id"], cid, token="agt_guess").status_code == 401
    assert db.query(AgentCommand).one().status == "DISPATCHED"


def test_a_result_is_accepted_once_and_only_after_delivery(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    mid = machine_id(db, e["agent_id"])
    cid = queue(client, mid, admin, command_type="REBOOT_SYSTEM").json()["command_id"]

    assert report(client, e["agent_id"], cid, token=e["agent_token"]).status_code == 409  # not delivered yet
    metrics(client, e["agent_id"], token=e["agent_token"])
    assert report(client, e["agent_id"], cid, output="first", token=e["agent_token"]).status_code == 200
    assert report(client, e["agent_id"], cid, output="second", token=e["agent_token"]).status_code == 409
    assert db.query(AgentCommand).one().result_output == "first"


@pytest.mark.parametrize("status", ["PENDING", "EXPIRED", "anything", ""])
def test_an_agent_can_only_report_completed_or_failed(client, db, status):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    cid = deliver(client, db, admin, e, command_type="REBOOT_SYSTEM")
    assert report(client, e["agent_id"], cid, status=status, token=e["agent_token"]).status_code == 400


def test_reported_output_is_capped(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    cid = deliver(client, db, admin, e, command_type="EXECUTE_SHELL", command_str="yes")
    report(client, e["agent_id"], cid, output="x" * (ac.MAX_OUTPUT_LENGTH + 5000), token=e["agent_token"])
    assert len(db.query(AgentCommand).one().result_output) == ac.MAX_OUTPUT_LENGTH


# --- machine management ----------------------------------------------------------------------------

def test_deleting_updating_and_changing_a_mac_need_agents_manage(client, db):
    e = enrol(client)
    mid = machine_id(db, e["agent_id"])
    wol_only = make_user(db, "wol@example.com", role="CUSTOM", permissions=["telemetry.view", "wol.manage"])

    assert client.delete(f"{BASE}/machines/{mid}", headers=wol_only).status_code == 403
    assert client.post(f"{BASE}/push-update", headers=wol_only).status_code == 403
    assert client.post(f"{BASE}/machines/{mid}/set-mac", json={"mac_address": "AA:BB:CC:DD:EE:FF"},
                       headers=wol_only).status_code == 403
    assert db.query(Machine).count() == 1


def test_machine_management_is_audited(client, db):
    admin = make_user(db, "admin@example.com")
    e = enrol(client)
    mid = machine_id(db, e["agent_id"])

    assert client.post(f"{BASE}/machines/{mid}/set-mac", json={"mac_address": "aa-bb-cc-dd-ee-ff"}, headers=admin).status_code == 200
    assert client.post(f"{BASE}/push-update", headers=admin).json()["agents"] == 1
    assert client.post(f"{BASE}/push-update", headers=admin).json()["agents"] == 0  # one is already waiting
    assert client.delete(f"{BASE}/machines/{mid}", headers=admin).status_code == 200

    done = [a for a, _r, who in audit_actions(db) if who == "admin@example.com"]
    assert done == ["machine.set_mac", "agents.push_update", "agents.push_update", "machine.delete"]
    deleted = db.query(AuditLog).filter(AuditLog.action == "machine.delete").one()
    assert deleted.details["agent_id"] == e["agent_id"]


def test_pushed_update_commands_expire_and_record_who_asked(client, db):
    admin = make_user(db, "admin@example.com")
    enrol(client)
    client.post(f"{BASE}/push-update", headers=admin)
    cmd = db.query(AgentCommand).one()
    assert cmd.command_type == "UPDATE_AGENT" and cmd.requested_by == "admin@example.com"
    assert cmd.expires_at is not None


def test_the_migration_gives_agents_manage_to_users_who_could_manage_wol():
    import importlib.util
    from backend.app.core.config import BASE_DIR

    path = next((BASE_DIR / "backend" / "alembic" / "versions").glob("b8c9d0e1f2a3_*.py"))
    spec = importlib.util.spec_from_file_location("migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.down_revision == "a8b9c0d1e2f3"
