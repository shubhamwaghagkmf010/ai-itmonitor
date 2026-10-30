import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.app.api.endpoints import agents
from backend.app.core.config import BASE_DIR, Settings, check_settings
from backend.app.core.security import secure_equals


# --- constant-time comparison ----------------------------------------------------------------

def test_secure_equals_accepts_only_the_exact_secret():
    assert secure_equals("s3cret-value", "s3cret-value")
    assert not secure_equals("s3cret-valuE", "s3cret-value")
    assert not secure_equals("s3cret", "s3cret-value")
    assert not secure_equals("s3cret-value-and-more", "s3cret-value")
    assert not secure_equals("", "s3cret-value")


def test_secure_equals_rejects_a_missing_value():
    assert not secure_equals(None, "s3cret-value")


def test_secure_equals_handles_non_ascii_secrets():
    assert secure_equals("pässwörd-密码", "pässwörd-密码")
    assert not secure_equals("passwörd-密码", "pässwörd-密码")


# --- the agent key check ---------------------------------------------------------------------

@pytest.fixture
def agent_key(monkeypatch):
    def set_key(value):
        monkeypatch.setattr(agents.settings, "AGENT_API_KEY", value)
    return set_key


def test_the_right_agent_key_is_accepted(agent_key):
    agent_key("an-agent-key-long-enough")
    assert agents.verify_agent_key("an-agent-key-long-enough") is True


@pytest.mark.parametrize("sent", [None, "", "wrong", "an-agent-key-long-enougH", "an-agent-key-long-enough "])
def test_a_wrong_or_missing_agent_key_is_refused(agent_key, sent):
    agent_key("an-agent-key-long-enough")
    with pytest.raises(HTTPException) as exc:
        agents.verify_agent_key(sent)
    assert exc.value.status_code == 401


def test_without_a_configured_key_enrolment_is_open(agent_key):
    agent_key("")
    assert agents.verify_agent_key(None) is True
    assert agents.verify_agent_key("anything") is True


# --- scripts/init_env.py ---------------------------------------------------------------------

def _load_init_env():
    spec = importlib.util.spec_from_file_location("init_env", BASE_DIR / "scripts" / "init_env.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def project(tmp_path):
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / ".env.example").write_text(
        (BASE_DIR / "backend" / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def read_env(path: Path) -> dict:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            values[k] = v.strip().strip('"')
    return values


def test_the_example_file_ships_no_usable_secret():
    values = read_env(BASE_DIR / "backend" / ".env.example")
    assert values["SECRET_KEY"] == ""
    assert values["AGENT_API_KEY"] == ""


def test_init_env_writes_a_valid_private_file(project):
    init_env = _load_init_env()

    assert init_env.main([], root=project) == 0

    target = project / "backend" / ".env"
    values = read_env(target)
    assert len(values["SECRET_KEY"]) >= 32
    assert values["AGENT_API_KEY"] == ""
    assert values["POSTGRES_DB"] == "ai_itmonitor_db"  # the rest of the example is kept
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    settings = Settings(_env_file=None, SECRET_KEY=values["SECRET_KEY"], POSTGRES_PASSWORD="a-strong-password-1",
                        AGENT_API_KEY="an-agent-key-long-enough")
    assert check_settings(settings, None).errors == []


def test_init_env_does_not_print_the_secrets(project, capsys):
    init_env = _load_init_env()
    init_env.main(["--with-agent-key"], root=project)
    values = read_env(project / "backend" / ".env")
    out = capsys.readouterr()
    assert values["SECRET_KEY"] not in out.out + out.err
    assert values["AGENT_API_KEY"] not in out.out + out.err


def test_init_env_can_also_make_an_agent_key(project):
    init_env = _load_init_env()
    init_env.main(["--with-agent-key"], root=project)
    assert len(read_env(project / "backend" / ".env")["AGENT_API_KEY"]) >= 32


def test_init_env_refuses_to_overwrite_without_force(project, capsys):
    init_env = _load_init_env()
    target = project / "backend" / ".env"
    target.write_text("SECRET_KEY=keep-me\n")

    assert init_env.main([], root=project) == 1
    assert target.read_text() == "SECRET_KEY=keep-me\n"
    assert "already exists" in capsys.readouterr().err

    assert init_env.main(["--force"], root=project) == 0
    assert "keep-me" not in target.read_text()


def test_two_runs_make_different_keys(project):
    init_env = _load_init_env()
    init_env.main([], root=project)
    first = read_env(project / "backend" / ".env")["SECRET_KEY"]
    init_env.main(["--force"], root=project)
    assert read_env(project / "backend" / ".env")["SECRET_KEY"] != first


def test_init_env_reports_a_missing_example(tmp_path, capsys):
    init_env = _load_init_env()
    (tmp_path / "backend").mkdir()
    assert init_env.main([], root=tmp_path) == 1
    assert "Cannot find" in capsys.readouterr().err


# --- through the real application ------------------------------------------------------------

def test_the_register_endpoint_refuses_a_wrong_agent_key_over_http(agent_key):
    from fastapi.testclient import TestClient
    from backend.app.main import app

    agent_key("an-agent-key-long-enough")
    client = TestClient(app)  # without `with`, so start-up tasks (the retention loop) do not run
    body = {"hostname": "h1", "os_name": "Linux"}

    assert client.post("/api/v1/agents/register", json=body, headers={"X-Agent-Key": "nope"}).status_code == 401
    assert client.post("/api/v1/agents/register", json=body).status_code == 401
    assert client.post("/api/v1/agents/metrics", json={"agent_id": "x"}, headers={"X-Agent-Key": "nope"}).status_code == 401
    assert client.post("/api/v1/agents/command-result", json={"agent_id": "x", "command_id": 1, "status": "COMPLETED"},
                       headers={"X-Agent-Key": "nope"}).status_code == 401
