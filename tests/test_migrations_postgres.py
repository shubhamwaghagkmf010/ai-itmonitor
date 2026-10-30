"""Runs the Alembic chain against a real PostgreSQL server.

The migrations contain PostgreSQL-specific steps (the users.role enum, ALTER ... USING), which SQLite
cannot exercise. These tests start a private, throwaway cluster in a temporary directory on a free port;
they are skipped where the PostgreSQL server programs (initdb, pg_ctl) are not installed."""
import glob
import json
import os
import shutil
import socket
import subprocess
import sys

import pytest

from backend.app.core.config import BASE_DIR


def _pg_bin():
    found = shutil.which("initdb")
    if found:
        return os.path.dirname(found)
    for candidate in sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True):
        if os.path.exists(os.path.join(candidate, "initdb")):
            return candidate
    return None


PG_BIN = _pg_bin()
pytestmark = pytest.mark.skipif(PG_BIN is None, reason="PostgreSQL server programs (initdb) are not installed")

HEAD = "d0e1f2a3b4c5"
LAST_OLD_REVISION = "a7b8c9d0e1f2"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def pg(tmp_path):
    data, port = tmp_path / "data", _free_port()
    run = lambda *a, **k: subprocess.run([os.path.join(PG_BIN, a[0]), *a[1:]], check=True, capture_output=True, text=True, **k)
    run("initdb", "-D", str(data), "-U", "migtest", "--auth=trust")
    run("pg_ctl", "-D", str(data), "-o", f"-p {port} -k {tmp_path} -c listen_addresses=127.0.0.1",
        "-l", str(tmp_path / "log"), "-w", "start")
    run("createdb", "-h", "127.0.0.1", "-p", str(port), "-U", "migtest", "migtest")
    env = {**os.environ, "PYTHONPATH": str(BASE_DIR), "ENVIRONMENT": "development", "SECRET_KEY": "m" * 48,
           "POSTGRES_SERVER": "127.0.0.1", "POSTGRES_PORT": str(port), "POSTGRES_USER": "migtest",
           "POSTGRES_PASSWORD": "migration-test-only", "POSTGRES_DB": "migtest"}

    class Db:
        def alembic(self, *args):
            r = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=BASE_DIR, env=env, capture_output=True, text=True)
            assert r.returncode == 0, r.stdout + r.stderr
            return r.stdout + r.stderr

        def script(self, relative_path):
            r = subprocess.run([sys.executable, relative_path], cwd=BASE_DIR, env=env, capture_output=True, text=True)
            assert r.returncode == 0, r.stdout + r.stderr
            return r.stdout + r.stderr

        def python(self, code):
            r = subprocess.run([sys.executable, "-c", code], cwd=BASE_DIR, env=env, capture_output=True, text=True)
            assert r.returncode == 0, r.stdout + r.stderr

        def sql(self, statement):
            r = run("psql", "-h", "127.0.0.1", "-p", str(port), "-U", "migtest", "-d", "migtest", "-At", "-c", statement)
            return r.stdout.strip()

    try:
        yield Db()
    finally:
        subprocess.run([os.path.join(PG_BIN, "pg_ctl"), "-D", str(data), "-m", "immediate", "stop"], capture_output=True)


def test_an_empty_database_reaches_the_current_schema_and_can_step_back(pg):
    pg.alembic("upgrade", "head")
    assert HEAD in pg.alembic("current")

    # What a fresh database built from migrations alone used to lack:
    assert pg.sql("select data_type from information_schema.columns where table_name='users' and column_name='role'") == "character varying"
    for table in ("audit_logs", "wol_requests"):
        assert pg.sql(f"select to_regclass('{table}')") == table
    for table, column in [("users", "permissions"), ("users", "must_change_password"), ("users", "token_version"),
                          ("machines", "agent_token_hash"), ("machines", "mac_address"), ("agent_commands", "expires_at")]:
        assert pg.sql(f"select count(*) from information_schema.columns where table_name='{table}' and column_name='{column}'") == "1", (table, column)

    # The roles the application uses can be stored (the old enum only allowed ADMIN and ENGINEER).
    pg.sql("insert into users (email, hashed_password, role, is_active, created_at) values ('m@x.y', 'h', 'MANAGER', true, now())")

    pg.alembic("downgrade", "-3")
    pg.alembic("upgrade", "head")
    assert HEAD in pg.alembic("current")


def test_an_existing_production_database_is_upgraded_with_its_data_intact(pg):
    """A database made by create_all() with the models before this work, stamped at the last old revision."""
    pg.python("from backend.app.core.database import Base, engine; import backend.app.models; Base.metadata.create_all(bind=engine)")
    pg.sql("alter table machines drop column agent_token_hash; alter table agent_commands drop column expires_at; "
           "alter table agent_commands drop column requested_by; alter table users drop column token_version")
    pg.sql("insert into users (email, hashed_password, role, is_active, must_change_password, failed_login_attempts, created_at, permissions) values "
           "('boss@x.y','h','CUSTOM',true,false,0,now(),'[\"telemetry.view\",\"wol.manage\",\"admin.users_manage\"]'),"
           "('viewer@x.y','h','CUSTOM',true,false,0,now(),'[\"telemetry.view\"]'),"
           "('default@x.y','h','OPERATOR',true,false,0,now(),null)")
    pg.alembic("stamp", LAST_OLD_REVISION)

    pg.alembic("upgrade", "head")
    assert HEAD in pg.alembic("current")
    rows = {r.split("|")[0]: r.split("|") for r in pg.sql("select email||'|'||token_version||'|'||coalesce(permissions::text,'null') from users").splitlines()}
    boss = json.loads(rows["boss@x.y"][2])
    assert set(boss) >= {"agents.manage", "assets.view", "assets.manage", "network.manage", "admin.users_manage"}
    assert json.loads(rows["viewer@x.y"][2]) == ["telemetry.view", "assets.view"]
    assert rows["default@x.y"][2] == "null"  # role defaults apply; nothing written
    assert {r[1] for r in rows.values()} == {"0"}


def test_a_legacy_engineer_user_becomes_an_operator_whatever_the_column_type(pg):
    """The old role enum had ENGINEER; a database made by create_all has a text column that can still hold it."""
    pg.python("from backend.app.core.database import Base, engine; import backend.app.models; Base.metadata.create_all(bind=engine)")
    # A database from before token_version existed: take that column away so the insert below looks like old data.
    pg.sql("alter table machines drop column agent_token_hash; alter table agent_commands drop column expires_at; "
           "alter table agent_commands drop column requested_by; alter table users drop column token_version")
    pg.sql("insert into users (email, hashed_password, role, is_active, must_change_password, failed_login_attempts, created_at, permissions) values "
           "('eng@x.y','h','ENGINEER',true,false,0,now(),null), ('adm@x.y','h','ADMIN',true,false,0,now(),null)")
    pg.alembic("stamp", LAST_OLD_REVISION)
    pg.alembic("upgrade", "head")
    assert pg.sql("select email||'='||role from users order by id") == "eng@x.y=OPERATOR\nadm@x.y=ADMIN"


def test_a_fresh_install_that_used_create_all_can_be_stamped_and_upgraded(pg):
    pg.python("from backend.app.core.database import Base, engine; import backend.app.models; Base.metadata.create_all(bind=engine)")
    pg.alembic("stamp", "head")
    pg.alembic("upgrade", "head")
    assert HEAD in pg.alembic("current")


def test_migrating_a_create_all_database_from_an_old_stamp_does_not_fail_on_existing_columns(pg):
    """The models already contain this work's columns, so a database created from them must not choke on them."""
    pg.python("from backend.app.core.database import Base, engine; import backend.app.models; Base.metadata.create_all(bind=engine)")
    pg.alembic("stamp", LAST_OLD_REVISION)
    pg.alembic("upgrade", "head")
    assert HEAD in pg.alembic("current")


# --- scripts/migrate.py, which the container runs at start-up --------------------------------------------------------

def test_the_startup_script_builds_an_empty_database_and_is_safe_to_run_again(pg):
    assert "(built)" in pg.script("scripts/migrate.py")
    assert HEAD in pg.alembic("current")
    assert "(upgraded)" in pg.script("scripts/migrate.py")
    assert HEAD in pg.alembic("current")


def test_the_startup_script_adopts_a_database_that_has_no_migration_history(pg):
    """What every installation made with create_all() looks like: tables and data, no alembic_version."""
    pg.python("from backend.app.core.database import Base, engine; import backend.app.models; Base.metadata.create_all(bind=engine)")
    pg.sql("alter table machines drop column agent_token_hash; alter table agent_commands drop column expires_at; "
           "alter table agent_commands drop column requested_by; alter table users drop column token_version")
    pg.sql("insert into users (email, hashed_password, role, is_active, must_change_password, failed_login_attempts, created_at, permissions) values "
           "('boss@x.y','h','CUSTOM',true,false,0,now(),'[\"telemetry.view\",\"wol.manage\"]')")
    assert pg.sql("select to_regclass('alembic_version')") == ""

    assert "(adopted)" in pg.script("scripts/migrate.py")
    assert HEAD in pg.alembic("current")
    assert pg.sql("select count(*) from users") == "1"  # the data is still there
    assert "agents.manage" in pg.sql("select permissions::text from users")
    assert "(upgraded)" in pg.script("scripts/migrate.py")


def test_the_startup_script_creates_tables_a_hand_made_database_is_missing(pg):
    pg.python("from backend.app.core.database import Base, engine; import backend.app.models; Base.metadata.create_all(bind=engine)")
    pg.sql("drop table wol_requests; drop table audit_logs")
    assert "(adopted)" in pg.script("scripts/migrate.py")
    assert pg.sql("select to_regclass('audit_logs')") == "audit_logs"
    assert pg.sql("select to_regclass('wol_requests')") == "wol_requests"
