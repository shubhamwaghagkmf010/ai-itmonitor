from datetime import datetime, timedelta, timezone

import bcrypt
import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import admin, auth
from backend.app.core import security
from backend.app.core.config import settings
from backend.app.core.database import Base, get_db
from backend.app.core.security import check_password_policy, create_access_token, get_password_hash, verify_password
from backend.app.models.entities import AuditLog, User

PASSWORD = "Correct-horse-battery-9"
BASE = "/api/v1"


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch):
    """Four rounds instead of twelve: the tests hash and check passwords hundreds of times."""
    real = bcrypt.gensalt
    monkeypatch.setattr(security.bcrypt, "gensalt", lambda rounds=4, prefix=b"2b": real(rounds=4, prefix=prefix))
    auth._dummy_hash = None


# --- password rules ---------------------------------------------------------------------------------

@pytest.mark.parametrize("password", ["short", "123456789", "a" * 9])
def test_short_passwords_are_refused(password):
    assert "at least 10" in check_password_policy(password)


@pytest.mark.parametrize("password", ["password123", "Password123", "1234567890", "administrator", "ChangeMe#Admin1",
                                      "qwertyuiop", "Welcome123", "password-password"])
def test_obvious_passwords_are_refused(password):
    assert check_password_policy(password)


def test_repetitive_and_over_long_passwords_are_refused():
    assert "different characters" in check_password_policy("aaaaaaaaaaaa")
    assert "at most 72" in check_password_policy("x1" * 40)
    assert check_password_policy("é" * 40)  # 80 bytes


def test_a_password_containing_the_user_name_is_refused():
    assert "user name" in check_password_policy("jsmith-Winter2026!", "jsmith@example.com")
    assert check_password_policy("jsmith-Winter2026!", "x@example.com") is None  # short names are too common to match


def test_a_good_passphrase_is_accepted():
    assert check_password_policy("correct horse battery staple") is None
    assert check_password_policy("Tr0ub4dor&3-and-more") is None


def test_unusable_passwords_fail_verification_instead_of_crashing():
    h = get_password_hash("A-good-password-1")
    assert verify_password("A-good-password-1", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x" * 100, h)  # more than bcrypt accepts
    assert not verify_password("anything", "not-a-hash")
    assert not verify_password("anything", "")


def test_tokens_carry_expiry_issue_time_and_version():
    claims = jose_jwt.decode(create_access_token("a@b.c", token_version=3), settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert claims["sub"] == "a@b.c" and claims["tv"] == 3 and "exp" in claims and "iat" in claims


# --- the application -------------------------------------------------------------------------------------

@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def client(db):
    from backend.app.main import app

    def override():
        yield db

    app.dependency_overrides[get_db] = override
    for limiter in (auth._login_ip_limit, auth._login_user_limit, auth._password_change_limit):
        limiter.reset()
    yield TestClient(app)
    app.dependency_overrides.clear()


def make_user(db, email, password=PASSWORD, role="ADMIN", permissions=None, **extra):
    u = User(email=email, hashed_password=get_password_hash(password), role=role, permissions=permissions or [], **extra)
    db.add(u)
    db.commit()
    return u


def login(client, email, password=PASSWORD):
    return client.post(f"{BASE}/auth/login", data={"username": email, "password": password})


def bearer(client, email, password=PASSWORD):
    r = login(client, email, password)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def actions(db):
    db.expire_all()
    return [(a.action, a.actor_email, a.result) for a in db.query(AuditLog).order_by(AuditLog.id)]


# --- logging in ---------------------------------------------------------------------------------------------

def test_a_correct_login_returns_a_token_and_profile(client, db):
    make_user(db, "alice@example.com", failed_login_attempts=3)
    r = login(client, "alice@example.com")
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["email"] == "alice@example.com" and body["user"]["role"] == "ADMIN"
    assert client.get(f"{BASE}/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}).status_code == 200
    db.expire_all()
    assert db.query(User).one().failed_login_attempts == 0


def test_the_email_is_matched_without_regard_to_case_and_spaces(client, db):
    make_user(db, "Alice@Example.com")
    assert login(client, "  alice@example.COM ").status_code == 200


def test_wrong_password_and_unknown_user_are_indistinguishable(client, db):
    make_user(db, "alice@example.com")
    a = login(client, "alice@example.com", "wrong-password-1")
    b = login(client, "nobody@example.com", "wrong-password-1")
    assert (a.status_code, a.json()) == (b.status_code, b.json()) == (401, {"detail": "Incorrect email or password"})


def test_an_unknown_user_still_costs_a_password_check(client, db, monkeypatch):
    calls = []
    real = auth.verify_password
    monkeypatch.setattr(auth, "verify_password", lambda p, h: calls.append(h) or real(p, h))
    login(client, "nobody@example.com", "whatever-it-is")
    assert len(calls) == 1 and calls[0].startswith("$2")  # compared against a real hash, so the time matches


def test_an_over_long_password_is_a_failed_login_not_a_server_error(client, db):
    make_user(db, "alice@example.com")
    assert login(client, "alice@example.com", "x" * 500).status_code == 401


def test_five_failures_lock_the_account_and_the_lock_is_not_extended(client, db):
    make_user(db, "alice@example.com")
    for _ in range(5):
        assert login(client, "alice@example.com", "wrong-password-1").status_code == 401
    db.expire_all()
    u = db.query(User).one()
    assert u.failed_login_attempts == 5 and u.locked_until is not None
    locked_until = u.locked_until

    # Even the right password is refused while locked, and neither attempt changes the lock or the count.
    assert login(client, "alice@example.com").status_code == 403
    assert login(client, "alice@example.com", "wrong-password-1").status_code == 403
    db.expire_all()
    u = db.query(User).one()
    assert u.locked_until == locked_until and u.failed_login_attempts == 5


def test_after_the_lock_runs_out_counting_starts_again(client, db):
    u = make_user(db, "alice@example.com", failed_login_attempts=5,
                  locked_until=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert login(client, "alice@example.com", "wrong-password-1").status_code == 401
    db.expire_all()
    u = db.query(User).one()
    assert u.failed_login_attempts == 1 and u.locked_until is None  # not locked again by a single typo
    assert login(client, "alice@example.com").status_code == 200


def test_a_lock_does_not_end_a_session_that_already_exists(client, db):
    make_user(db, "alice@example.com")
    headers = bearer(client, "alice@example.com")
    for _ in range(5):
        login(client, "alice@example.com", "wrong-password-1")  # someone else guessing
    assert client.get(f"{BASE}/auth/me", headers=headers).status_code == 200


def test_a_disabled_account_cannot_log_in_but_learns_nothing_without_the_password(client, db):
    make_user(db, "alice@example.com", is_active=False)
    assert login(client, "alice@example.com").status_code == 403
    assert login(client, "alice@example.com", "wrong-password-1").status_code == 401


def test_login_attempts_are_rate_limited_per_account(client, db):
    make_user(db, "alice@example.com")
    codes = [login(client, "alice@example.com", f"wrong-password-{i}").status_code for i in range(12)]
    assert 429 in codes
    r = login(client, "alice@example.com")  # the right password does not get past the limiter either
    assert r.status_code in (403, 429)
    assert r.status_code == 429 or db.query(User).one().locked_until is not None
    assert ("LOGIN_RATE_LIMITED", "alice@example.com", "DENIED") in actions(db)


def test_login_attempts_are_rate_limited_per_address(client, db):
    codes = [login(client, f"user{i}@example.com", "wrong-password-1").status_code for i in range(35)]
    assert codes[:30] == [401] * 30 and codes[30:] == [429] * 5


# --- sessions end when they should --------------------------------------------------------------------------

def test_changing_the_password_ends_other_sessions_and_keeps_this_one(client, db):
    make_user(db, "alice@example.com")
    old = bearer(client, "alice@example.com")
    r = client.post(f"{BASE}/auth/change-password", headers=old,
                    json={"current_password": PASSWORD, "new_password": "A-brand-new-passphrase-7"})
    assert r.status_code == 200
    assert client.get(f"{BASE}/auth/me", headers=old).status_code == 401
    fresh = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get(f"{BASE}/auth/me", headers=fresh).status_code == 200
    assert login(client, "alice@example.com").status_code == 401
    assert login(client, "alice@example.com", "A-brand-new-passphrase-7").status_code == 200
    assert ("PASSWORD_CHANGED", "alice@example.com", "SUCCESS") in actions(db)


def test_password_change_checks_the_current_password_and_the_policy(client, db):
    make_user(db, "alice@example.com", must_change_password=True)
    h = bearer(client, "alice@example.com")
    post = lambda cur, new: client.post(f"{BASE}/auth/change-password", headers=h, json={"current_password": cur, "new_password": new})
    assert post("wrong", "A-brand-new-passphrase-7").status_code == 400
    assert post(PASSWORD, "short").status_code == 400
    assert post(PASSWORD, "password123").status_code == 400
    assert post(PASSWORD, "alice-and-more-letters").status_code == 400  # contains the user name
    assert post(PASSWORD, PASSWORD).status_code == 400  # not a change
    assert db.query(User).one().must_change_password is True
    assert post(PASSWORD, "A-brand-new-passphrase-7").status_code == 200
    db.expire_all()
    assert db.query(User).one().must_change_password is False
    assert ("PASSWORD_CHANGE_FAILED", "alice@example.com", "FAILED") in actions(db)


def test_guessing_the_current_password_through_a_stolen_token_is_throttled(client, db):
    make_user(db, "alice@example.com")
    h = bearer(client, "alice@example.com")
    codes = [client.post(f"{BASE}/auth/change-password", headers=h,
                         json={"current_password": f"guess-{i}", "new_password": "A-brand-new-passphrase-7"}).status_code
             for i in range(7)]
    assert codes[:5] == [400] * 5 and codes[5:] == [429, 429]


def test_logging_out_everywhere_ends_every_session(client, db):
    make_user(db, "alice@example.com")
    laptop, phone = bearer(client, "alice@example.com"), bearer(client, "alice@example.com")
    assert client.post(f"{BASE}/auth/logout-all", headers=laptop).status_code == 200
    assert client.get(f"{BASE}/auth/me", headers=laptop).status_code == 401
    assert client.get(f"{BASE}/auth/me", headers=phone).status_code == 401
    assert login(client, "alice@example.com").status_code == 200  # a new login works


def test_tokens_from_before_versions_existed_keep_working_until_revoked(client, db):
    u = make_user(db, "alice@example.com")
    legacy = jose_jwt.encode({"sub": "alice@example.com", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                             settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    h = {"Authorization": f"Bearer {legacy}"}
    assert client.get(f"{BASE}/auth/me", headers=h).status_code == 200
    u.token_version = 1
    db.commit()
    assert client.get(f"{BASE}/auth/me", headers=h).status_code == 401


def test_a_token_without_an_expiry_or_subject_is_refused(client, db):
    make_user(db, "alice@example.com")
    no_exp = jose_jwt.encode({"sub": "alice@example.com"}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    no_sub = jose_jwt.encode({"exp": datetime.now(timezone.utc) + timedelta(hours=1)}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    expired = jose_jwt.encode({"sub": "alice@example.com", "exp": datetime.now(timezone.utc) - timedelta(seconds=5)},
                              settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    forged = jose_jwt.encode({"sub": "alice@example.com", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                             "some-other-signing-key-entirely-123456", algorithm=settings.ALGORITHM)
    for token in (no_exp, no_sub, expired, forged, "garbage"):
        assert client.get(f"{BASE}/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


# --- administering users ----------------------------------------------------------------------------------------

def new_user_body(**over):
    body = {"email": "Bob@Example.com", "full_name": "Bob", "password": "Temporary-pass-phrase-1", "role": "OPERATOR"}
    body.update(over)
    return body


def test_a_created_user_must_choose_their_own_password(client, db):
    make_user(db, "admin@example.com")
    h = bearer(client, "admin@example.com")
    r = client.post(f"{BASE}/admin/users", json=new_user_body(), headers=h)
    assert r.status_code == 201
    bob = db.query(User).filter(User.email == "bob@example.com").one()  # stored lower case
    assert bob.must_change_password is True and bob.role == "OPERATOR"
    assert "ai_chat.use" in bob.permissions
    me = login(client, "bob@example.com", "Temporary-pass-phrase-1").json()["user"]
    assert me["must_change_password"] is True
    entry = db.query(AuditLog).filter(AuditLog.action == "USER_CREATED").one()
    assert entry.details["role"] == "OPERATOR" and "permissions" in entry.details


def test_user_creation_is_validated(client, db):
    make_user(db, "admin@example.com")
    h = bearer(client, "admin@example.com")
    post = lambda **o: client.post(f"{BASE}/admin/users", json=new_user_body(**o), headers=h)
    assert post(password="short").status_code == 400
    assert post(password="password123").status_code == 400
    assert post(role="SUPERUSER").status_code == 422
    assert post(permissions=["root.everything"]).status_code == 422
    assert post(widget_permissions={"nonsense": True}).status_code == 422
    assert post(email="not-an-email").status_code == 422
    assert post(full_name="x" * 256).status_code == 422
    assert post().status_code == 201
    assert post(email="BOB@example.com").status_code == 400  # same address, different case
    assert db.query(User).count() == 2


def delegate(db, permissions=None):
    return make_user(db, "delegate@example.com", role="CUSTOM",
                     permissions=permissions or ["admin.users_manage", "telemetry.view", "dashboard.view"])


def test_a_delegate_cannot_create_administrators_or_hand_out_what_they_lack(client, db):
    delegate(db)
    h = bearer(client, "delegate@example.com")
    post = lambda **o: client.post(f"{BASE}/admin/users", json=new_user_body(**o), headers=h)

    assert post(role="ADMIN").status_code == 403
    assert post(role="MANAGER").status_code == 403  # the MANAGER defaults include permissions the delegate lacks
    assert post(role="CUSTOM", permissions=["telemetry.view", "agents.manage"]).status_code == 403
    assert post(role="CUSTOM", permissions=["telemetry.view"]).status_code == 201
    denied = [a for a in actions(db) if a[2] == "DENIED"]
    assert len(denied) == 3 and all(who == "delegate@example.com" for _a, who, _r in denied)


def test_a_delegate_cannot_touch_administrators_or_their_own_rights(client, db):
    admin_user = make_user(db, "admin@example.com")
    me = delegate(db)
    h = bearer(client, "delegate@example.com")

    assert client.post(f"{BASE}/admin/users/{admin_user.id}/reset-password", json={"new_password": "Another-long-passphrase-2"}, headers=h).status_code == 403
    assert client.patch(f"{BASE}/admin/users/{admin_user.id}", json={"is_active": False}, headers=h).status_code == 403
    assert client.patch(f"{BASE}/admin/users/{admin_user.id}", json={"password": "Another-long-passphrase-2"}, headers=h).status_code == 403
    # Giving themselves more is exactly the escalation to prevent.
    assert client.patch(f"{BASE}/admin/users/{me.id}", json={"role": "ADMIN"}, headers=h).status_code in (400, 403)
    assert client.patch(f"{BASE}/admin/users/{me.id}", json={"permissions": ["admin.users_manage", "agents.manage"]}, headers=h).status_code in (400, 403)
    db.expire_all()
    assert db.get(User, me.id).role == "CUSTOM" and db.get(User, admin_user.id).is_active is True
    assert verify_password(PASSWORD, db.get(User, admin_user.id).hashed_password)


def test_an_administrator_cannot_demote_or_disable_themselves(client, db):
    me = make_user(db, "admin@example.com")
    make_user(db, "other@example.com")  # another admin exists, so this is about self-service, not the last admin
    h = bearer(client, "admin@example.com")
    for body in ({"role": "VIEWER"}, {"is_active": False}):
        assert client.patch(f"{BASE}/admin/users/{me.id}", json=body, headers=h).status_code == 400
    assert client.patch(f"{BASE}/admin/users/{me.id}", json={"full_name": "New Name"}, headers=h).status_code == 200
    # Saving the edit form unchanged (as the dashboard does) is fine.
    assert client.patch(f"{BASE}/admin/users/{me.id}", json={"role": "ADMIN", "full_name": "New Name", "widget_permissions": {"kpiCards": True}}, headers=h).status_code == 200
    db.expire_all()
    assert db.get(User, me.id).role == "ADMIN" and db.get(User, me.id).is_active


def test_the_last_active_administrator_is_kept(client, db, monkeypatch):
    make_user(db, "admin@example.com")
    target = make_user(db, "other@example.com")
    h = bearer(client, "admin@example.com")
    monkeypatch.setattr(admin, "_active_admins_other_than", lambda db_, uid: 0)
    assert client.patch(f"{BASE}/admin/users/{target.id}", json={"role": "VIEWER"}, headers=h).status_code == 400
    assert client.patch(f"{BASE}/admin/users/{target.id}", json={"is_active": False}, headers=h).status_code == 400
    db.expire_all()
    assert db.get(User, target.id).role == "ADMIN" and db.get(User, target.id).is_active


def test_an_administrator_can_demote_another_when_one_remains(client, db):
    make_user(db, "admin@example.com")
    target = make_user(db, "other@example.com")
    h = bearer(client, "admin@example.com")
    assert client.patch(f"{BASE}/admin/users/{target.id}", json={"role": "VIEWER"}, headers=h).status_code == 200
    db.expire_all()
    assert db.get(User, target.id).role == "VIEWER"
    entry = db.query(AuditLog).filter(AuditLog.action == "USER_UPDATED").one()
    assert entry.details["role"] == {"from": "ADMIN", "to": "VIEWER"}
    assert entry.details["permissions"]["removed"]  # the audit says what was taken away


def test_disabling_an_account_signs_it_out_at_once(client, db):
    make_user(db, "admin@example.com")
    victim = make_user(db, "victim@example.com", role="OPERATOR")
    vh = bearer(client, "victim@example.com")
    ah = bearer(client, "admin@example.com")
    assert client.patch(f"{BASE}/admin/users/{victim.id}", json={"is_active": False}, headers=ah).status_code == 200
    assert client.get(f"{BASE}/auth/me", headers=vh).status_code == 401


def test_resetting_a_password_signs_the_user_out_and_forces_a_new_one(client, db):
    make_user(db, "admin@example.com")
    user = make_user(db, "user@example.com", role="OPERATOR", failed_login_attempts=5,
                     locked_until=datetime.now(timezone.utc) + timedelta(minutes=10))
    ah = bearer(client, "admin@example.com")
    uh = {"Authorization": f"Bearer {create_access_token('user@example.com')}"}
    assert client.get(f"{BASE}/auth/me", headers=uh).status_code == 200

    assert client.post(f"{BASE}/admin/users/{user.id}/reset-password", json={"new_password": "weak"}, headers=ah).status_code == 400
    assert client.post(f"{BASE}/admin/users/{user.id}/reset-password", json={"new_password": "Reset-by-admin-passphrase-3"}, headers=ah).status_code == 200
    assert client.get(f"{BASE}/auth/me", headers=uh).status_code == 401
    db.expire_all()
    u = db.get(User, user.id)
    assert u.must_change_password is True and u.locked_until is None and u.failed_login_attempts == 0
    assert login(client, "user@example.com", "Reset-by-admin-passphrase-3").json()["user"]["must_change_password"] is True
    assert ("PASSWORD_RESET_BY_ADMIN", "admin@example.com", "SUCCESS") in actions(db)


def test_setting_a_password_through_user_update_follows_the_same_rules(client, db):
    make_user(db, "admin@example.com")
    user = make_user(db, "user@example.com", role="OPERATOR")
    h = bearer(client, "admin@example.com")
    assert client.patch(f"{BASE}/admin/users/{user.id}", json={"password": "123456"}, headers=h).status_code == 400
    assert client.patch(f"{BASE}/admin/users/{user.id}", json={"password": "Via-the-edit-form-passphrase-4"}, headers=h).status_code == 200
    db.expire_all()
    assert db.get(User, user.id).must_change_password is True


def test_unknown_users_are_a_404(client, db):
    make_user(db, "admin@example.com")
    h = bearer(client, "admin@example.com")
    assert client.patch(f"{BASE}/admin/users/999", json={"full_name": "x"}, headers=h).status_code == 404
    assert client.post(f"{BASE}/admin/users/999/reset-password", json={"new_password": "Long-enough-passphrase-5"}, headers=h).status_code == 404


# --- the audit log and retention ---------------------------------------------------------------------------------

def test_the_audit_log_page_size_is_bounded(client, db):
    make_user(db, "admin@example.com")
    h = bearer(client, "admin@example.com")
    for i in range(30):
        db.add(AuditLog(actor_email="x@example.com", action=f"A{i}", result="SUCCESS"))
    db.commit()
    assert client.get(f"{BASE}/admin/audit-logs?limit=1000000", headers=h).status_code == 422
    assert client.get(f"{BASE}/admin/audit-logs?limit=0", headers=h).status_code == 422
    assert client.get(f"{BASE}/admin/audit-logs?offset=-1", headers=h).status_code == 422
    first = client.get(f"{BASE}/admin/audit-logs?limit=10", headers=h).json()
    second = client.get(f"{BASE}/admin/audit-logs?limit=10&offset=10", headers=h).json()
    assert len(first) == 10 and len(second) == 10
    assert not {e["id"] for e in first} & {e["id"] for e in second}
    assert client.get(f"{BASE}/admin/audit-logs?limit=1000", headers=h).status_code == 200


def test_running_retention_by_hand_is_audited(client, db, monkeypatch):
    monkeypatch.setattr(admin, "purge_old_data", lambda: {"retention_days": 30, "deleted": {"machine_metrics": 12}})
    make_user(db, "admin@example.com")
    h = bearer(client, "admin@example.com")
    assert client.post(f"{BASE}/admin/retention/run", headers=h).json()["deleted"] == {"machine_metrics": 12}
    entry = db.query(AuditLog).filter(AuditLog.action == "RETENTION_RUN").one()
    assert entry.actor_email == "admin@example.com" and entry.details["deleted"] == {"machine_metrics": 12}


def test_the_token_version_migration_starts_everyone_at_zero():
    import importlib.util
    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from backend.app.core.config import BASE_DIR

    path = next((BASE_DIR / "backend" / "alembic" / "versions").glob("d0e1f2a3b4c5_*.py"))
    spec = importlib.util.spec_from_file_location("m", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.down_revision == "c9d0e1f2a3b4"

    e = sa.create_engine("sqlite://")
    with e.begin() as c:
        c.execute(sa.text("create table users (id integer primary key)"))
        c.execute(sa.text("insert into users values (1), (2)"))
        with Operations.context(MigrationContext.configure(c)):
            m.upgrade()
        assert [r[0] for r in c.execute(sa.text("select token_version from users"))] == [0, 0]
