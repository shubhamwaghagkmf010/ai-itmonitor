import importlib.util
import inspect
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.ai import ollama_service
from backend.app.api.endpoints import agents, network
from backend.app.core.config import BASE_DIR, settings
from backend.app.core.database import Base, get_db
from backend.app.core.security import create_access_token, get_password_hash, verify_password
from backend.app.models.entities import (
    AgentCommand, AIAnalysis, AuditLog, ExtendedMetric, Incident, IncidentSeverity, IncidentStatus, Machine,
    MachineMetric, MachineStatus, NetworkDevice, ProcessSnapshot, User,
)
from backend.app.services import anomaly, incident_automation, report_generator, retention

BASE = "/api/v1/agents"
REAL_CLIENT = httpx.Client
SUPPORT = {"X-Agent-Token-Support": "1"}


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    session.bind_engine = engine
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


def make_admin(db, email="admin@example.com"):
    db.add(User(email=email, hashed_password="x", role="ADMIN", permissions=[]))
    db.commit()
    return {"Authorization": f"Bearer {create_access_token(email)}"}


def enrol(client, hostname="PC1", uid="aabbccddeeff"):
    r = client.post(f"{BASE}/register", json={"hostname": hostname, "os_name": "Linux", "machine_uid": uid}, headers=SUPPORT)
    assert r.status_code == 200, r.text
    return {"agent_id": r.json()["agent_id"], "token": r.json()["agent_token"]}


def send(client, agent, cpu=10, ram=10, disk=10, processes=None, **extra):
    body = {"agent_id": agent["agent_id"], "cpu_percent": cpu, "ram_percent": ram, "ram_used_gb": 1, "ram_total_gb": 8,
            "disk_percent": disk, "disk_used_gb": 1, "disk_total_gb": 100, "top_processes": processes or [], **extra}
    return client.post(f"{BASE}/metrics", json=body, headers={"X-Agent-Token": agent["token"]})


def proc(name="worker", pid=4242, cpu=50.0, mem=5.0):
    return {"pid": pid, "name": name, "cpu_percent": cpu, "memory_percent": mem, "status": "running"}


# --- the status badge ------------------------------------------------------------------------------------

@pytest.mark.parametrize("cpu,ram,disk,expected", [
    (10, 10, 10, MachineStatus.HEALTHY), (84.9, 84.9, 89.9, MachineStatus.HEALTHY),
    (85, 10, 10, MachineStatus.WARNING), (10, 85, 10, MachineStatus.WARNING), (10, 10, 90, MachineStatus.WARNING),
    (95, 10, 10, MachineStatus.CRITICAL), (10, 99, 10, MachineStatus.CRITICAL), (10, 10, 100, MachineStatus.CRITICAL),
])
def test_status_follows_the_numbers(cpu, ram, disk, expected):
    assert anomaly.classify_status(cpu, ram, disk) == expected


def test_a_reporting_machine_is_no_longer_always_healthy(client, db):
    agent = enrol(client)
    for cpu, expected in [(20, "HEALTHY"), (88, "WARNING"), (99, "CRITICAL"), (20, "HEALTHY")]:
        assert send(client, agent, cpu=cpu).json()["machine_status"] == expected
        db.expire_all()
        assert db.query(Machine).one().status.value == expected


# --- anomaly detection ----------------------------------------------------------------------------------------

def add_samples(db, machine_id, cpus, ram=30.0, disk=30.0, start=None, step=10):
    start = start or datetime.now(timezone.utc) - timedelta(seconds=step * len(cpus))
    rows = []
    for i, cpu in enumerate(cpus):
        m = MachineMetric(machine_id=machine_id, cpu_percent=cpu, ram_percent=ram, ram_used_gb=1, ram_total_gb=8,
                          disk_percent=disk, disk_used_gb=1, disk_total_gb=100, timestamp=start + timedelta(seconds=step * i))
        db.add(m)
        rows.append(m)
    db.commit()
    return rows


def test_a_spike_is_judged_against_history_without_itself(db):
    db.add(Machine(agent_id="A", hostname="h", os_name="L"))
    db.commit()
    add_samples(db, 1, [20, 22, 19, 21, 20, 23, 18, 21, 20, 22])
    spike = add_samples(db, 1, [60])[0]
    current = {"cpu_percent": 60, "ram_percent": 30, "disk_percent": 30}

    with_self = anomaly.detect_metric_anomalies(db, 1, current)
    without = anomaly.detect_metric_anomalies(db, 1, current, exclude_metric_id=spike.id)
    assert "CPU" in without["anomalies_detected"] and without["z_scores"]["cpu_z"] > with_self["z_scores"]["cpu_z"]


def test_fixed_limits_apply_even_without_history(db):
    db.add(Machine(agent_id="A", hostname="h", os_name="L"))
    db.commit()
    r = anomaly.detect_metric_anomalies(db, 1, {"cpu_percent": 96, "ram_percent": 10, "disk_percent": 91})
    assert r["anomalies_detected"] == ["CPU", "Disk"] and r["severity"] == "CRITICAL"
    quiet = anomaly.detect_metric_anomalies(db, 1, {"cpu_percent": 10, "ram_percent": 10, "disk_percent": 10})
    assert quiet == {"has_anomaly": False, "anomalies_detected": [], "severity": "LOW", "z_scores": {}}


# --- incidents raised from telemetry --------------------------------------------------------------------------------

def incidents(db):
    db.expire_all()
    return db.query(Incident).order_by(Incident.id).all()


def test_a_sustained_overload_raises_one_incident(client, db):
    agent = enrol(client)
    for _ in range(2):
        send(client, agent, cpu=97, processes=[proc("runaway", 777, cpu=91.2)])
    assert incidents(db) == []  # two samples are not yet "sustained"
    send(client, agent, cpu=97, processes=[proc("runaway", 777, cpu=91.2)])

    (inc,) = incidents(db)
    assert inc.category == "CPU" and inc.severity == IncidentSeverity.CRITICAL and inc.status == IncidentStatus.OPEN
    assert "PC1" in inc.title and "runaway" in inc.description and "777" in inc.description
    assert inc.incident_code.startswith("INC-1-")

    for _ in range(5):
        send(client, agent, cpu=97)
    assert len(incidents(db)) == 1  # still the same open incident


def test_one_spike_or_a_flapping_value_is_not_an_incident(client, db):
    agent = enrol(client)
    for cpu in (97, 20, 97, 97, 20, 97, 97, 20):
        send(client, agent, cpu=cpu)
    assert incidents(db) == []


def test_samples_spread_over_hours_are_not_consecutive(client, db):
    agent = enrol(client)
    mid = db.query(Machine).one().id
    add_samples(db, mid, [97, 97], start=datetime.now(timezone.utc) - timedelta(hours=3))
    send(client, agent, cpu=97)
    assert incidents(db) == []


def test_each_resource_gets_its_own_incident_with_the_right_severity(client, db):
    agent = enrol(client)
    for _ in range(3):
        send(client, agent, cpu=10, ram=88, disk=92)
    by_category = {i.category: i for i in incidents(db)}
    assert set(by_category) == {"MEMORY", "STORAGE"}
    assert by_category["MEMORY"].severity == IncidentSeverity.HIGH
    assert "Memory usage" in by_category["MEMORY"].description


def test_a_fresh_incident_is_not_opened_straight_after_one_was_closed(client, db):
    agent = enrol(client)
    for _ in range(3):
        send(client, agent, cpu=97)
    inc = incidents(db)[0]
    inc.status, inc.resolved_at = IncidentStatus.RESOLVED, datetime.now(timezone.utc)
    db.commit()

    for _ in range(3):
        send(client, agent, cpu=97)
    assert len(incidents(db)) == 1  # cool-down

    inc = incidents(db)[0]
    inc.resolved_at = datetime.now(timezone.utc) - incident_automation.REOPEN_COOLDOWN - timedelta(minutes=1)
    db.commit()
    send(client, agent, cpu=97)
    assert len(incidents(db)) == 2


def test_an_incident_from_the_diagnostic_scan_is_not_duplicated(client, db):
    agent = enrol(client)
    mid = db.query(Machine).one().id
    db.add(Incident(incident_code="INC-SCAN", title="CPU saturated", description="d", category="CPU",
                    severity=IncidentSeverity.HIGH, status=IncidentStatus.IN_PROGRESS, machine_id=mid))
    db.commit()
    for _ in range(4):
        send(client, agent, cpu=97)
    assert [i.incident_code for i in incidents(db)] == ["INC-SCAN"]


def test_a_failure_while_raising_incidents_never_loses_the_telemetry(client, db, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("incident logic is broken")
    monkeypatch.setattr(agents, "raise_incidents_for_sample", boom)
    agent = enrol(client)
    r = send(client, agent, cpu=97, processes=[proc()])
    assert r.status_code == 200
    db.expire_all()
    assert db.query(MachineMetric).count() == 1 and db.query(ProcessSnapshot).count() == 1


def test_a_quiet_sample_costs_no_incident_queries(db):
    m = Machine(agent_id="A", hostname="h", os_name="L")
    db.add(m)
    db.flush()
    metric = MachineMetric(machine_id=m.id, cpu_percent=10, ram_percent=10, ram_used_gb=1, ram_total_gb=8,
                           disk_percent=10, disk_used_gb=1, disk_total_gb=100)
    statements = []
    from sqlalchemy import event
    event.listen(db.bind_engine, "before_cursor_execute", lambda *a: statements.append(a[2]))
    assert incident_automation.raise_incidents_for_sample(db, m, metric) == []
    assert statements == []


# --- what ingestion stores --------------------------------------------------------------------------------------------

def test_extended_telemetry_is_one_row_per_machine_refreshed_once_a_minute(client, db):
    agent = enrol(client)
    send(client, agent, services=[{"name": "ssh", "state": "running"}])
    send(client, agent, services=[{"name": "ssh", "state": "stopped"}])  # within a minute: ignored
    db.expire_all()
    row = db.query(ExtendedMetric).one()
    assert row.services == [{"name": "ssh", "state": "running"}]

    row.timestamp = datetime.now(timezone.utc) - timedelta(seconds=61)
    db.commit()
    send(client, agent, services=[{"name": "ssh", "state": "stopped"}], gpu={"name": "x"})
    db.expire_all()
    row = db.query(ExtendedMetric).one()  # updated in place, not another row
    assert row.services == [{"name": "ssh", "state": "stopped"}] and row.gpu == {"name": "x"}

    viewer = make_admin(db)
    shown = client.get(f"{BASE}/machines/1/extended", headers=viewer).json()
    assert shown["services"] == [{"name": "ssh", "state": "stopped"}]


def test_empty_extended_telemetry_stores_nothing(client, db):
    agent = enrol(client)
    send(client, agent)
    assert db.query(ExtendedMetric).count() == 0


def test_the_process_list_is_replaced_not_accumulated(client, db):
    agent = enrol(client)
    send(client, agent, processes=[proc("a", 1), proc("b", 2), proc("c", 3)])
    send(client, agent, processes=[proc("d", 4)])
    db.expire_all()
    assert [p.name for p in db.query(ProcessSnapshot).all()] == ["d"]
    assert db.query(MachineMetric).count() == 2


# --- the fallback analysis -----------------------------------------------------------------------------------------------

def flatten(rca):
    return " ".join(str(v) for v in rca.values())


def test_the_fallback_does_not_invent_a_process_or_numbers():
    rca = ollama_service.generate_fallback_rca({"hostname": "PC1", "cpu_percent": 93.0, "ram_percent": 40.0, "disk_percent": 50.0})
    text = flatten(rca)
    assert "9412" not in text and "91.2" not in text and "unbounded" not in text
    assert "no per-process data" in rca["probable_cause"]
    assert rca["confidence_score"] <= 0.2 and "unavailable" in rca["model_name"]


def test_the_fallback_names_the_real_busiest_process():
    rca = ollama_service.generate_fallback_rca({
        "hostname": "PC1", "cpu_percent": 93.0, "ram_percent": 40.0, "disk_percent": 50.0,
        "top_processes": [{"pid": 11, "name": "small", "cpu_percent": 5, "memory_percent": 1},
                          {"pid": 22, "name": "hog", "cpu_percent": 71.5, "memory_percent": 2}]})
    assert "'hog'" in rca["probable_cause"] and "PID 22" in flatten(rca) and "72%" in flatten(rca)
    assert "small" not in rca["probable_cause"]


def test_the_fallback_is_not_always_about_cpu():
    rca = ollama_service.generate_fallback_rca({
        "hostname": "PC1", "cpu_percent": 10.0, "ram_percent": 96.0, "disk_percent": 50.0,
        "top_processes": [{"pid": 1, "name": "busy", "cpu_percent": 60, "memory_percent": 5},
                          {"pid": 2, "name": "leaky", "cpu_percent": 1, "memory_percent": 80}]})
    assert rca["probable_cause"].startswith("RAM") and "'leaky'" in rca["probable_cause"]
    assert "busy" not in rca["probable_cause"]


def test_the_fallback_copes_with_missing_data():
    for context in ({}, {"hostname": None, "cpu_percent": None}, {"cpu_percent": "n/a", "top_processes": [{}]}):
        rca = ollama_service.generate_fallback_rca(context)
        assert rca["observed_facts"] and rca["recommended_actions"] and 0 < rca["confidence_score"] <= 0.2
        assert "None" not in rca["probable_cause"]


def test_an_unreachable_model_falls_back_to_the_honest_summary(monkeypatch):
    def refuse(*args, **kwargs):
        raise httpx.ConnectError("no ollama")
    monkeypatch.setattr(ollama_service.httpx, "Client", refuse)
    rca = ollama_service.analyze_incident_with_ai({"hostname": "PC1", "cpu_percent": 90, "ram_percent": 10})
    assert "unavailable" in rca["model_name"] and "9412" not in flatten(rca)


# --- the PDF report ---------------------------------------------------------------------------------------------------------

HOSTILE = '<b>unclosed & <font size="99">oops</para> <img src="file:///etc/passwd"/> &#x41; <a href="http://x">x</a>'


def hostile_incident(db):
    m = Machine(agent_id="A", hostname="host <i>&</i>", os_name="L")
    db.add(m)
    db.flush()
    inc = Incident(incident_code="INC-1-<X>", title=HOSTILE, description=HOSTILE, category="CPU",
                   severity=IncidentSeverity.HIGH, status=IncidentStatus.OPEN, machine_id=m.id,
                   resolution_notes=HOSTILE, created_at=datetime(2026, 10, 1, 12, 0, 0))
    db.add(inc)
    db.flush()
    rca = AIAnalysis(incident_id=inc.id, observed_facts=[HOSTILE], probable_cause=HOSTILE, evidence=[HOSTILE],
                     recommended_actions=[HOSTILE], preventive_actions=[], confidence_score=0.0, model_name=HOSTILE)
    db.add(rca)
    db.commit()
    return inc, rca


def test_markup_in_incident_text_is_printed_not_interpreted(db, monkeypatch):
    inc, rca = hostile_incident(db)
    seen = []
    real = report_generator.Paragraph
    monkeypatch.setattr(report_generator, "Paragraph", lambda t, *a, **k: seen.append(t) or real(t, *a, **k))

    pdf = report_generator.generate_incident_pdf(inc, rca)  # raised a parse error before the text was escaped
    assert pdf.read(5) == b"%PDF-"
    joined = "\n".join(seen)
    assert "&lt;b&gt;unclosed &amp;" in joined and '<font size="99">' not in joined and "<img" not in joined


def test_a_report_without_analysis_or_dates_still_builds(db):
    inc = Incident(incident_code="INC-2", title="t", description="d", category="CPU", severity=IncidentSeverity.LOW,
                   status=IncidentStatus.OPEN, machine_id=1, created_at=datetime(2026, 1, 1))
    pdf = report_generator.generate_incident_pdf(inc, None)
    assert pdf.read(5) == b"%PDF-"


def test_the_report_makes_no_claim_that_a_person_reviewed_it(db):
    source = inspect.getsource(report_generator)
    assert "SRE Lead" not in source and "has not been reviewed by a person" in source


def test_exporting_through_the_api_works_for_hostile_text(client, db):
    admin = make_admin(db)
    hostile_incident(db)
    r = client.get("/api/v1/incidents/1/export-pdf", headers=admin)
    assert r.status_code == 200 and r.content.startswith(b"%PDF-")


# --- retention -------------------------------------------------------------------------------------------------------------------

def factory_for(db):
    return lambda: sessionmaker(bind=db.bind_engine, autoflush=False)()


def test_retention_deletes_old_rows_in_batches_and_keeps_new_and_unfinished_ones(db, monkeypatch):
    monkeypatch.setattr(settings, "METRIC_RETENTION_DAYS", 30)
    monkeypatch.setattr(retention, "BATCH_SIZE", 7)
    db.add(Machine(agent_id="A", hostname="h", os_name="L"))
    db.commit()
    old = datetime.now(timezone.utc) - timedelta(days=40)
    new = datetime.now(timezone.utc) - timedelta(days=1)
    add_samples(db, 1, [10] * 20, start=old - timedelta(hours=1), step=1)
    add_samples(db, 1, [10] * 3, start=new, step=1)
    for status, when in [("COMPLETED", old), ("FAILED", old), ("EXPIRED", old), ("CANCELLED", old), ("TIMEOUT", old),
                         ("PENDING", old), ("DISPATCHED", old), ("COMPLETED", new)]:
        db.add(AgentCommand(machine_id=1, command_type="REBOOT_SYSTEM", payload_json={}, status=status, created_at=when))
    db.add(AuditLog(actor_email="a@b.c", action="X", result="SUCCESS", timestamp=old))
    db.commit()

    result = retention.purge_old_data(factory_for(db))
    assert result["deleted"]["machine_metrics"] == 20 and result["deleted"]["agent_commands"] == 5
    db.expire_all()
    assert db.query(MachineMetric).count() == 3
    assert sorted(c.status for c in db.query(AgentCommand).all()) == ["COMPLETED", "DISPATCHED", "PENDING"]
    assert db.query(AuditLog).count() == 1  # the audit trail is not retention's to delete


def test_retention_can_be_switched_off(db, monkeypatch):
    monkeypatch.setattr(settings, "METRIC_RETENTION_DAYS", 0)
    assert retention.purge_old_data(factory_for(db)) == {"skipped": True, "reason": "retention disabled"}


def test_the_daily_cleanup_runs_off_the_event_loop():
    from backend.app import main
    assert "asyncio.to_thread(purge_old_data)" in inspect.getsource(main._schedule_retention)


# --- scans mark vanished devices offline ----------------------------------------------------------------------------------------------

def test_a_device_that_stops_answering_is_marked_offline(client, db, monkeypatch):
    admin = make_admin(db)
    for ip in ("192.168.77.1", "192.168.77.2", "192.168.99.5"):
        db.add(NetworkDevice(ip_address=ip, hostname=f"h-{ip}", is_online=True))
    db.commit()
    monkeypatch.setattr(network, "scan_subnet", lambda subnet=None: {
        "subnet": "192.168.77.0/30", "count": 1, "devices": [{
            "ip": "192.168.77.1", "mac": None, "hostname": "h-192.168.77.1", "vendor": "v", "device_type": "t",
            "os_guess": "o", "open_ports": "", "is_online": True}]})
    assert client.post("/api/v1/network/scan", json={}, headers=admin).status_code == 200
    db.expire_all()
    state = {d.ip_address: d.is_online for d in db.query(NetworkDevice).all()}
    assert state == {"192.168.77.1": True, "192.168.77.2": False, "192.168.99.5": True}  # outside the range: untouched
    assert db.query(AuditLog).filter(AuditLog.action == "network.scan").one().details["marked_offline"] == 1


def test_a_device_that_comes_back_is_online_again(client, db, monkeypatch):
    admin = make_admin(db)
    db.add(NetworkDevice(ip_address="192.168.77.2", hostname="h", is_online=False))
    db.commit()
    monkeypatch.setattr(network, "scan_subnet", lambda subnet=None: {
        "subnet": "192.168.77.0/30", "count": 1, "devices": [{
            "ip": "192.168.77.2", "mac": None, "hostname": "h", "vendor": "v", "device_type": "t",
            "os_guess": "o", "open_ports": "", "is_online": True}]})
    client.post("/api/v1/network/scan", json={}, headers=admin)
    db.expire_all()
    assert db.query(NetworkDevice).one().is_online is True


# --- the seed script ----------------------------------------------------------------------------------------------------------------

def load_script(name):
    spec = importlib.util.spec_from_file_location(name, BASE_DIR / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def seed(db, monkeypatch):
    for var in ("ADMIN_PASSWORD", "OPERATOR_PASSWORD", "ENGINEER_PASSWORD", "ADMIN_EMAIL", "OPERATOR_EMAIL", "SEED_OPERATOR"):
        monkeypatch.delenv(var, raising=False)
    module = load_script("seed_users")
    return lambda: module.seed_users(lambda: sessionmaker(bind=db.bind_engine, autoflush=False)()), module


def test_the_seed_script_creates_working_accounts_instead_of_crashing(seed, db, monkeypatch, capsys):
    run, _ = seed
    monkeypatch.setenv("ADMIN_PASSWORD", "Quiet-river-lantern-4821")
    monkeypatch.setenv("OPERATOR_PASSWORD", "Copper-meadow-violin-9037")
    run()
    out = capsys.readouterr().out
    db.expire_all()
    admin = db.query(User).filter(User.email == "admin@ai-itmonitor.local").one()
    operator = db.query(User).filter(User.email == "engineer@ai-itmonitor.local").one()
    assert (admin.role, operator.role) == ("ADMIN", "OPERATOR")  # UserRole.ENGINEER never existed
    assert admin.must_change_password and operator.must_change_password
    assert verify_password("Quiet-river-lantern-4821", admin.hashed_password)
    assert "ai_chat.use" in operator.permissions and "completed successfully" in out
    assert "Quiet-river" not in out and "Copper-meadow" not in out  # a password given by the operator is never echoed


def test_without_a_given_password_a_random_one_is_made_and_shown_once(seed, db, capsys):
    run, _ = seed
    run()
    out = capsys.readouterr().out
    assert out.count("One-time password") == 2
    passwords = [line.split(": ", 1)[1].strip() for line in out.splitlines() if "One-time password" in line]
    assert len(set(passwords)) == 2 and all(len(p) >= 15 for p in passwords)
    admin = db.query(User).filter(User.role == "ADMIN").one()
    assert verify_password(passwords[0], admin.hashed_password)
    for default in ("ChangeMe#Admin1", "ChangeMe#Eng1"):
        assert not verify_password(default, admin.hashed_password)


def test_the_seed_script_never_changes_existing_accounts(seed, db, monkeypatch, capsys):
    run, _ = seed
    db.add(User(email="Admin@ai-itmonitor.local", hashed_password=get_password_hash("Original-passphrase-1"), role="ADMIN"))
    db.commit()
    monkeypatch.setenv("SEED_OPERATOR", "0")
    run()
    db.expire_all()
    assert db.query(User).count() == 1
    assert verify_password("Original-passphrase-1", db.query(User).one().hashed_password)
    assert "already exists" in capsys.readouterr().out


def test_a_weak_password_in_the_environment_is_an_error(seed, db, monkeypatch):
    run, _ = seed
    monkeypatch.setenv("ADMIN_PASSWORD", "password123")
    with pytest.raises(SystemExit, match="ADMIN_PASSWORD"):
        run()
    assert db.query(User).count() == 0


# --- the demo script ---------------------------------------------------------------------------------------------------------------------

def run_demo(monkeypatch, handler, capsys, env=None):
    demo = load_script("demo_incident_simulator")
    monkeypatch.setattr(demo.httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    code = demo.trigger_demo()
    return code, capsys.readouterr().out


def test_the_demo_does_not_claim_success_when_the_server_refuses_it(monkeypatch, capsys):
    code, out = run_demo(monkeypatch, lambda req: httpx.Response(401, json={"detail": "Invalid or missing agent key"}), capsys)
    assert code == 1 and "SUCCESS" not in out and "401" in out


def test_the_demo_only_claims_success_after_finding_the_incident(monkeypatch, capsys):
    def handler(req):
        path = req.url.path
        if path.endswith("/register"):
            return httpx.Response(200, json={"agent_id": "AGENT-X", "agent_token": "agt_t"})
        if path.endswith("/metrics"):
            return httpx.Response(200, json={"machine_status": "CRITICAL"})
        if path.endswith("/auth/login"):
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(200, json=[{"machine_hostname": "PROD-APP-02", "status": "OPEN", "incident_code": "INC-1-ABC", "title": "High CPU"}])

    code, out = run_demo(monkeypatch, handler, capsys)
    assert code == 0 and "SUCCESS" not in out and "Not verified" in out

    code, out = run_demo(monkeypatch, handler, capsys, {"DEMO_EMAIL": "a@b.c", "DEMO_PASSWORD": "x"})
    assert code == 0 and "[SUCCESS] 1 incident(s)" in out

    def no_incident(req):
        return httpx.Response(200, json=[]) if req.url.path.endswith("/incidents/") else handler(req)
    code, out = run_demo(monkeypatch, no_incident, capsys, {"DEMO_EMAIL": "a@b.c", "DEMO_PASSWORD": "x"})
    assert code == 1 and "SUCCESS" not in out
