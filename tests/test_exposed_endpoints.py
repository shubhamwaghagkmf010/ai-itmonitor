import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import ai_chat, assets, network
from backend.app.core import netutil
from backend.app.core.config import settings
from backend.app.core.csv_safe import csv_safe, csv_safe_row
from backend.app.core.database import Base, get_db
from backend.app.core.ratelimit import SlidingWindowLimiter
from backend.app.core.security import create_access_token
from backend.app.models.entities import Asset, AuditLog, Machine, NetworkDevice, ScanRange, User
from backend.app.services import netscan


# --- who is calling ------------------------------------------------------------------------------

def fake_request(peer, forwarded=None):
    headers = {"x-forwarded-for": forwarded} if forwarded is not None else {}
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers)


@pytest.fixture
def proxies(monkeypatch):
    def set_proxies(*entries):
        monkeypatch.setattr(settings, "TRUSTED_PROXIES", list(entries))
    return set_proxies


def test_a_forwarded_header_is_ignored_unless_the_peer_is_a_trusted_proxy(proxies):
    proxies("10.0.0.2/32")
    assert netutil.client_ip(fake_request("192.168.40.20", "10.9.9.9")) == "192.168.40.20"
    assert netutil.client_ip(fake_request("10.0.0.2", "192.168.40.20")) == "192.168.40.20"


def test_the_address_our_proxy_appended_wins_over_what_the_client_wrote(proxies):
    proxies("10.0.0.2/32")
    # The client claims to be 10.1.1.1; the proxy appended the address it really saw.
    assert netutil.client_ip(fake_request("10.0.0.2", "10.1.1.1, 192.168.40.20")) == "192.168.40.20"


def test_a_chain_of_trusted_proxies_is_walked_from_the_right(proxies):
    proxies("10.0.0.0/24")
    assert netutil.client_ip(fake_request("10.0.0.2", "192.168.40.20, 10.0.0.7")) == "192.168.40.20"


def test_a_malformed_forwarded_header_falls_back_to_the_peer(proxies):
    proxies("10.0.0.2/32")
    assert netutil.client_ip(fake_request("10.0.0.2", "not-an-ip")) == "10.0.0.2"
    assert netutil.client_ip(fake_request("10.0.0.2", "")) == "10.0.0.2"


def test_loopback_is_trusted_by_default_and_a_typo_trusts_nothing(proxies):
    assert netutil.client_ip(fake_request("127.0.0.1", "192.168.40.20")) == "192.168.40.20"
    proxies("garbage", "10.0.0.2/99")
    assert netutil.client_ip(fake_request("10.0.0.2", "192.168.40.20")) == "10.0.0.2"


@pytest.mark.parametrize("ip,internal", [("192.168.1.5", True), ("10.0.0.1", True), ("172.20.5.87", True),
                                         ("127.0.0.1", True), ("8.8.8.8", False), ("172.32.0.1", False),
                                         ("", False), ("testclient", False)])
def test_internal_addresses(ip, internal):
    assert netutil.is_internal_address(ip) is internal


# --- what may be scanned ---------------------------------------------------------------------------

def test_a_normal_subnet_and_ranges_expand():
    hosts, label = netutil.parse_scan_target("192.168.1.0/24", 1024)
    assert len(hosts) == 254 and hosts[0] == "192.168.1.1" and hosts[-1] == "192.168.1.254" and label == "192.168.1.0/24"
    assert netutil.parse_scan_target("192.168.1.10-192.168.1.12", 1024)[0] == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    assert netutil.parse_scan_target("192.168.1.10-12", 1024)[0] == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    assert netutil.parse_scan_target("192.168.1.12-10", 1024)[0][0] == "192.168.1.10"
    assert netutil.parse_scan_target("192.168.1.7/32", 1024)[0] == ["192.168.1.7"]
    assert netutil.parse_scan_target("192.168.1.0/31", 1024)[0] == ["192.168.1.0", "192.168.1.1"]


def test_a_huge_range_is_refused_before_anything_is_built():
    start = time.monotonic()
    for spec in ["10.0.0.0/8", "0.0.0.0/0", "10.0.0.0-10.255.255.255", "172.16.0.0/12"]:
        with pytest.raises(ValueError, match="limit is 1024"):
            netutil.parse_scan_target(spec, 1024)
    assert time.monotonic() - start < 1


def test_the_size_limit_is_exact():
    assert len(netutil.parse_scan_target("192.168.0.0/22", 1022)[0]) == 1022
    with pytest.raises(ValueError):
        netutil.parse_scan_target("192.168.0.0/22", 1021)


@pytest.mark.parametrize("spec", ["8.8.8.0/30", "1.1.1.1", "172.15.255.250-172.16.0.5", "192.168.255.250-192.169.0.5"])
def test_addresses_outside_the_private_ranges_are_refused(spec):
    if "/" not in spec and "-" not in spec:
        spec += "/32"
    with pytest.raises(ValueError, match="private"):
        netutil.parse_scan_target(spec, 1024)


def test_public_scanning_can_be_switched_on_but_never_for_special_addresses():
    assert netutil.parse_scan_target("8.8.8.0/30", 1024, allow_public=True)[0] == ["8.8.8.1", "8.8.8.2"]
    for spec in ["127.0.0.0/30", "169.254.169.254/32", "224.0.0.0/30", "0.0.0.0/32", "255.255.255.255/32"]:
        with pytest.raises(ValueError, match="cannot be scanned"):
            netutil.parse_scan_target(spec, 1024, allow_public=True)


@pytest.mark.parametrize("spec", ["", "   ", "abc", "300.1.1.1/24", "::1/128", "10.0.0.0/33", "10.0.0.1-", "a-b", "1" * 200])
def test_garbage_targets_are_refused(spec):
    with pytest.raises(ValueError):
        netutil.parse_scan_target(spec, 1024)


def test_the_scanner_uses_the_same_rules(monkeypatch):
    monkeypatch.setattr(netscan, "_ping", lambda ip: pytest.fail("must not probe a refused range"))
    assert "limit is 1024" in netscan.scan_subnet("10.0.0.0/8")["error"]
    assert "not a private address" in netscan.scan_subnet("8.8.8.0/30")["error"]


# --- spreadsheet formulas -----------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["=1+1", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\t=x", "\r=x"])
def test_formula_cells_become_text(value):
    assert csv_safe(value) == "'" + value


@pytest.mark.parametrize("value", ["PC-01", "hello=world", "", "1.5", 42, None, "a@b.com"])
def test_ordinary_cells_are_left_alone(value):
    assert csv_safe(value) == value


def test_a_row_is_cleaned_cell_by_cell():
    assert csv_safe_row(["ok", "=evil()", 3]) == ["ok", "'=evil()", 3]


# --- the limiter --------------------------------------------------------------------------------------

def test_the_limiter_allows_a_burst_then_refuses_then_recovers():
    lim = SlidingWindowLimiter(3, 60)
    assert [lim.allow("a", now=t) for t in (0, 1, 2)] == [True] * 3
    assert lim.allow("a", now=3) is False
    assert lim.allow("b", now=3) is True  # another caller is unaffected
    assert lim.allow("a", now=61) is True  # the oldest hit has aged out


def test_the_limiter_forgets_idle_keys():
    lim = SlidingWindowLimiter(1, 10, max_keys=5)
    for i in range(10):
        lim.allow(f"k{i}", now=0)
    lim.allow("new", now=100)
    assert len(lim._hits) < 10


# --- the application ----------------------------------------------------------------------------------

class FromAddress:
    """Presents requests as coming from a given address (the test client always says 'testclient')."""
    def __init__(self, app, host):
        self.app, self.host = app, host

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = dict(scope, client=(self.host, 50000))
        await self.app(scope, receive, send)


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def make_client(db):
    from backend.app.main import app

    def override():
        yield db

    app.dependency_overrides[get_db] = override
    assets._self_read_limit.reset()
    assets._self_write_limit.reset()
    ai_chat._chat_limit.reset()

    def build(host="192.168.40.20"):
        return TestClient(FromAddress(app, host))

    yield build
    app.dependency_overrides.clear()


@pytest.fixture
def client(make_client):
    return make_client()


def make_user(db, email, role="ADMIN", permissions=None):
    db.add(User(email=email, hashed_password="x", role=role, permissions=permissions or []))
    db.commit()
    return {"Authorization": f"Bearer {create_access_token(email)}"}


def actions(db):
    db.expire_all()
    return [(a.action, a.actor_email) for a in db.query(AuditLog).order_by(AuditLog.id)]


def add_machine(db, ip="192.168.40.20", hostname="PC-ALICE"):
    m = Machine(agent_id=f"AGENT-{hostname}", hostname=hostname, ip_address=ip, os_name="Windows")
    db.add(m)
    db.commit()
    return m


# --- self-service -------------------------------------------------------------------------------------

def test_self_service_only_serves_internal_addresses(make_client, db):
    add_machine(db, ip="8.8.8.8")
    outside = make_client("8.8.8.8")
    assert outside.get("/api/v1/assets/self").status_code == 403
    assert outside.post("/api/v1/assets/self", json={"owned_by_emp_name": "x"}).status_code == 403
    assert db.query(Asset).count() == 0


def test_a_forged_forwarded_header_cannot_pick_another_computer(make_client, db):
    victim = add_machine(db, ip="192.168.40.99", hostname="PC-VICTIM")
    attacker = make_client("192.168.40.20")  # a known-nothing address, not a trusted proxy
    r = attacker.post("/api/v1/assets/self", json={"owned_by_emp_name": "Mallory"},
                      headers={"X-Forwarded-For": "192.168.40.99"})
    assert r.status_code == 404
    assert db.query(Asset).count() == 0


def test_a_forwarded_header_from_our_own_proxy_is_believed(make_client, db, proxies):
    add_machine(db, ip="192.168.40.99", hostname="PC-BOB")
    proxies("10.0.0.2/32")
    via_proxy = make_client("10.0.0.2")
    r = via_proxy.post("/api/v1/assets/self", json={"owned_by_emp_name": "Bob"}, headers={"X-Forwarded-For": "192.168.40.99"})
    assert r.status_code == 200
    assert db.query(Asset).one().owned_by_emp_name == "Bob"


def test_an_unknown_computer_creates_nothing(client, db):
    assert client.get("/api/v1/assets/self").json()["found"] is False
    r = client.post("/api/v1/assets/self", json={"owned_by_emp_name": "Eve"})
    assert r.status_code == 404 and db.query(Asset).count() == 0


def test_a_known_computer_can_record_its_owner_and_it_is_audited(client, db):
    add_machine(db)
    r = client.post("/api/v1/assets/self", json={"owned_by_emp_id": " E42 ", "owned_by_emp_name": "Alice",
                                                  "make": "ignored", "license_key": "ignored"})
    assert r.status_code == 200
    a = db.query(Asset).one()
    assert (a.owned_by_emp_id, a.owned_by_emp_name) == ("E42", "Alice")
    assert a.make is None and a.license_key is None  # technical fields are not editable here
    assert ("asset.self_update", "self-service:192.168.40.20") in actions(db)
    shown = client.get("/api/v1/assets/self").json()
    assert shown["found"] and shown["owned_by_emp_name"] == "Alice" and "license_key" not in shown


def test_self_service_values_are_length_limited(client, db):
    add_machine(db)
    assert client.post("/api/v1/assets/self", json={"owned_by_emp_name": "x" * 161}).status_code == 422
    assert client.post("/api/v1/assets/self", json={"allocation_purpose": "x" * 256}).status_code == 422


def test_self_service_writes_are_rate_limited_per_address(make_client, db):
    add_machine(db)
    c = make_client("192.168.40.20")
    codes = [c.post("/api/v1/assets/self", json={"owned_by_emp_name": f"n{i}"}).status_code for i in range(12)]
    assert codes[:10] == [200] * 10 and codes[10:] == [429, 429]
    assert make_client("192.168.40.77").post("/api/v1/assets/self", json={}).status_code == 404  # another address is not blocked


# --- the asset register -----------------------------------------------------------------------------------

def test_the_register_needs_assets_view_and_shows_viewers_masked_keys(client, db):
    db.add(Asset(host_name="PC1", license_key="AAAAA-BBBBB-CCCCC"))
    db.commit()
    viewer = make_user(db, "viewer@example.com", role="VIEWER")
    nothing = make_user(db, "none@example.com", role="CUSTOM", permissions=["telemetry.view"])
    admin = make_user(db, "admin@example.com")

    assert client.get("/api/v1/assets", headers=nothing).status_code == 403
    assert client.get("/api/v1/assets").status_code == 401
    seen = client.get("/api/v1/assets", headers=viewer).json()
    assert seen[0]["license_key"] == assets.MASKED and "AAAAA" not in str(seen)
    assert client.get("/api/v1/assets", headers=admin).json()[0]["license_key"] == "AAAAA-BBBBB-CCCCC"


def test_changing_the_register_needs_assets_manage(client, db):
    db.add(Asset(host_name="PC1"))
    db.commit()
    viewer = make_user(db, "viewer@example.com", role="VIEWER")
    operator = make_user(db, "op@example.com", role="OPERATOR")
    for who in (viewer, operator):
        assert client.post("/api/v1/assets", json={"host_name": "X"}, headers=who).status_code == 403
        assert client.patch("/api/v1/assets/1", json={"make": "X"}, headers=who).status_code == 403
        assert client.delete("/api/v1/assets/1", headers=who).status_code == 403
        assert client.post("/api/v1/assets/sync", headers=who).status_code == 403
        assert client.get("/api/v1/assets/export", headers=who).status_code == 403
    assert db.query(Asset).one().make is None


def test_managers_can_maintain_the_register_and_every_change_is_audited(client, db):
    manager = make_user(db, "mgr@example.com", role="MANAGER")
    r = client.post("/api/v1/assets", json={"host_name": "PC1", "license_key": "SECRET-KEY-123"}, headers=manager)
    assert r.status_code == 200
    aid = r.json()["id"]
    assert client.patch(f"/api/v1/assets/{aid}", json={"license_key": "ANOTHER-SECRET"}, headers=manager).status_code == 200
    assert client.get("/api/v1/assets/export", headers=manager).status_code == 200
    assert client.post("/api/v1/assets/sync", headers=manager).status_code == 200
    assert client.delete(f"/api/v1/assets/{aid}", headers=manager).status_code == 200

    done = [a for a, who in actions(db) if who == "mgr@example.com"]
    assert done == ["asset.create", "asset.update", "asset.export", "asset.sync", "asset.delete"]
    logged = " ".join(str(a.details) for a in db.query(AuditLog).all())
    assert "SECRET-KEY-123" not in logged and "ANOTHER-SECRET" not in logged  # fields are named, values are not


def test_register_fields_are_length_limited(client, db):
    admin = make_user(db, "admin@example.com")
    assert client.post("/api/v1/assets", json={"asset_no": "x" * 81}, headers=admin).status_code == 422
    assert client.post("/api/v1/assets", json={"host_name": "x" * 256}, headers=admin).status_code == 422
    assert client.post("/api/v1/assets", json={"host_name": "x" * 255}, headers=admin).status_code == 200


def test_the_asset_export_cannot_carry_a_spreadsheet_formula(client, db):
    db.add(Asset(host_name="=HYPERLINK(\"http://evil\",\"x\")", owned_by_emp_name="@SUM(A1:A9)", make="Dell"))
    db.commit()
    admin = make_user(db, "admin@example.com")
    body = client.get("/api/v1/assets/export", headers=admin).text
    assert "'=HYPERLINK" in body and "'@SUM" in body and "Dell" in body
    assert ",=HYPERLINK" not in body


def test_syncing_long_agent_values_does_not_break_the_commit(client, db):
    from backend.app.models.entities import MachineInventory
    m = add_machine(db)
    db.add(MachineInventory(machine_id=m.id, hardware={"manufacturer": "M" * 500, "product": "P" * 500}))
    db.commit()
    admin = make_user(db, "admin@example.com")
    assert client.post("/api/v1/assets/sync", headers=admin).status_code == 200
    a = db.query(Asset).one()
    assert len(a.make) == 120 and len(a.model) == 160


# --- network scans ------------------------------------------------------------------------------------------

@pytest.fixture
def quiet_network(monkeypatch):
    monkeypatch.setattr(netscan, "_ping", lambda ip: None)
    monkeypatch.setattr(netscan, "_neighbours", lambda: {})
    monkeypatch.setattr(netscan, "_load_oui", lambda: {})


def test_scanning_needs_network_manage(client, db, quiet_network):
    for role in ("VIEWER", "OPERATOR", "MANAGER"):
        who = make_user(db, f"{role}@example.com", role=role)
        assert client.post("/api/v1/network/scan", json={"subnet": "192.168.77.0/30"}, headers=who).status_code == 403
        assert client.post("/api/v1/network/ranges", json={"name": "n", "target": "192.168.77.0/30"}, headers=who).status_code == 403
    assert client.post("/api/v1/network/scan", json={"subnet": "192.168.77.0/30"}).status_code == 401


def test_an_admin_scan_runs_and_is_audited(client, db, quiet_network):
    admin = make_user(db, "admin@example.com")
    r = client.post("/api/v1/network/scan", json={"subnet": "192.168.77.0/30"}, headers=admin)
    assert r.status_code == 200 and r.json()["subnet"] == "192.168.77.0/30"
    assert ("network.scan", "admin@example.com") in actions(db)


@pytest.mark.parametrize("subnet", ["10.0.0.0/8", "8.8.8.0/24", "127.0.0.0/30", "169.254.169.254/32", "nonsense"])
def test_dangerous_or_pointless_targets_are_refused_and_logged(client, db, monkeypatch, subnet):
    monkeypatch.setattr(netscan, "_ping", lambda ip: pytest.fail("a refused target must not be probed"))
    admin = make_user(db, "admin@example.com")
    r = client.post("/api/v1/network/scan", json={"subnet": subnet}, headers=admin)
    assert r.status_code == 400
    entry = db.query(AuditLog).filter(AuditLog.action == "network.scan").one()
    assert entry.result == "DENIED"


def test_only_one_scan_runs_at_a_time(client, db, quiet_network):
    admin = make_user(db, "admin@example.com")
    assert network._scan_lock.acquire(blocking=False)
    try:
        r = client.post("/api/v1/network/scan", json={"subnet": "192.168.77.0/30"}, headers=admin)
        assert r.status_code == 409
    finally:
        network._scan_lock.release()
    assert client.post("/api/v1/network/scan", json={"subnet": "192.168.77.0/30"}, headers=admin).status_code == 200


def test_the_lock_is_released_after_a_refused_scan(client, db):
    admin = make_user(db, "admin@example.com")
    assert client.post("/api/v1/network/scan", json={"subnet": "10.0.0.0/8"}, headers=admin).status_code == 400
    assert network._scan_lock.acquire(blocking=False)
    network._scan_lock.release()


def test_saved_ranges_are_validated_audited_and_capped(client, db):
    admin = make_user(db, "admin@example.com")
    assert client.post("/api/v1/network/ranges", json={"name": "Everything", "target": "10.0.0.0/8"}, headers=admin).status_code == 400
    assert client.post("/api/v1/network/ranges", json={"name": "Public", "target": "8.8.8.0/24"}, headers=admin).status_code == 400
    assert client.post("/api/v1/network/ranges", json={"name": "  ", "target": "192.168.1.0/24"}, headers=admin).status_code == 400
    assert db.query(ScanRange).count() == 0

    r = client.post("/api/v1/network/ranges", json={"name": "Office", "target": "192.168.1.0/24"}, headers=admin)
    assert r.status_code == 200
    assert client.delete(f"/api/v1/network/ranges/{r.json()['id']}", headers=admin).status_code == 200
    assert [a for a, _ in actions(db)] == ["network.range.add", "network.range.delete"]

    for i in range(network.MAX_SAVED_RANGES):
        db.add(ScanRange(name=f"r{i}", target="192.168.1.0/24"))
    db.commit()
    assert client.post("/api/v1/network/ranges", json={"name": "one more", "target": "192.168.1.0/24"}, headers=admin).status_code == 400


def test_the_device_export_cannot_carry_a_spreadsheet_formula(client, db):
    db.add(NetworkDevice(ip_address="192.168.1.5", hostname="=cmd|' /C calc'!A0", vendor="@evil"))
    db.commit()
    viewer = make_user(db, "viewer@example.com", role="VIEWER")
    body = client.get("/api/v1/network/devices/export", headers=viewer).text
    assert "'=cmd" in body and "'@evil" in body


def test_scan_results_with_over_long_text_still_save(client, db, monkeypatch):
    monkeypatch.setattr(network, "scan_subnet", lambda subnet=None: {
        "subnet": "192.168.1.0/24", "count": 1, "devices": [{
            "ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "h" * 400, "vendor": "v" * 400,
            "device_type": "t" * 100, "os_guess": "o" * 100, "open_ports": "22/SSH", "is_online": True}]})
    admin = make_user(db, "admin@example.com")
    assert client.post("/api/v1/network/scan", json={}, headers=admin).status_code == 200
    d = db.query(NetworkDevice).one()
    assert len(d.hostname) == 255 and len(d.vendor) == 120 and len(d.device_type) == 60


# --- the AI assistant ---------------------------------------------------------------------------------------

@pytest.fixture
def fake_ai(monkeypatch):
    monkeypatch.setattr(ai_chat, "stream_ai_assistant", lambda message, db, ctx: iter([f"echo: {message}"]))


def test_chat_needs_the_ai_chat_permission(client, db, fake_ai):
    viewer = make_user(db, "viewer@example.com", role="VIEWER")
    operator = make_user(db, "op@example.com", role="OPERATOR")
    custom = make_user(db, "custom@example.com", role="CUSTOM", permissions=["telemetry.view"])
    assert client.post("/api/v1/ai/chat", json={"message": "hi"}).status_code == 401
    assert client.post("/api/v1/ai/chat", json={"message": "hi"}, headers=viewer).status_code == 403
    assert client.post("/api/v1/ai/chat", json={"message": "hi"}, headers=custom).status_code == 403
    r = client.post("/api/v1/ai/chat", json={"message": "hi"}, headers=operator)
    assert r.status_code == 200 and r.text == "echo: hi"


def test_chat_input_is_bounded(client, db, fake_ai):
    admin = make_user(db, "admin@example.com")
    for body in [{"message": ""}, {"message": "x" * (ai_chat.MAX_MESSAGE_LENGTH + 1)},
                 {"message": "ok", "machine_context": {"blob": "x" * ai_chat.MAX_CONTEXT_BYTES}}]:
        assert client.post("/api/v1/ai/chat", json=body, headers=admin).status_code == 422
    assert client.post("/api/v1/ai/chat", json={"message": "x" * ai_chat.MAX_MESSAGE_LENGTH}, headers=admin).status_code == 200


def test_chat_is_rate_limited_per_user(client, db, fake_ai):
    a = make_user(db, "a@example.com")
    b = make_user(db, "b@example.com")
    codes = [client.post("/api/v1/ai/chat", json={"message": "hi"}, headers=a).status_code for _ in range(22)]
    assert codes[:20] == [200] * 20 and codes[20:] == [429, 429]
    assert client.post("/api/v1/ai/chat", json={"message": "hi"}, headers=b).status_code == 200


# --- permissions as stored ---------------------------------------------------------------------------------------

def test_default_roles_get_the_new_permissions_they_should():
    from backend.app.models.entities import DEFAULT_PERMISSIONS as P
    assert {"assets.view", "assets.manage", "network.manage"} <= set(P["ADMIN"])
    assert {"assets.view", "assets.manage"} <= set(P["MANAGER"]) and "network.manage" not in P["MANAGER"]
    assert "assets.view" in P["OPERATOR"] and "assets.manage" not in P["OPERATOR"]
    assert "assets.view" in P["VIEWER"] and "assets.manage" not in P["VIEWER"]
    assert all("network.manage" not in P[r] for r in ("MANAGER", "OPERATOR", "VIEWER"))


def test_the_permission_migration_keeps_existing_access():
    import importlib.util
    import json
    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from backend.app.core.config import BASE_DIR

    path = next((BASE_DIR / "backend" / "alembic" / "versions").glob("c9d0e1f2a3b4_*.py"))
    spec = importlib.util.spec_from_file_location("m", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.down_revision == "b8c9d0e1f2a3"

    e = sa.create_engine("sqlite://")
    with e.begin() as c:
        c.execute(sa.text("create table users (id integer primary key, permissions json)"))
        c.execute(sa.text("insert into users values (1, :a), (2, :b), (3, NULL), (4, :c)"),
                  {"a": json.dumps(["telemetry.view", "wol.manage"]), "b": json.dumps(["telemetry.view"]),
                   "c": json.dumps(["incidents.view"])})
        with Operations.context(MigrationContext.configure(c)):
            m.upgrade()
        rows = {r[0]: json.loads(r[1]) if r[1] else None for r in c.execute(sa.text("select id, permissions from users"))}
    assert set(rows[1]) >= {"assets.view", "assets.manage", "network.manage"}
    assert "assets.view" in rows[2] and "assets.manage" not in rows[2]
    assert rows[3] is None and rows[4] == ["incidents.view"]
