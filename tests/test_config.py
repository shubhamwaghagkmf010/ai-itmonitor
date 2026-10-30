import os
import subprocess
import sys
from pathlib import Path

import pytest

from backend.app.core.config import (
    BASE_DIR,
    ENV_FILE,
    ConfigError,
    Settings,
    apply_settings_check,
    check_settings,
)

STRONG_KEY = "k" * 48


def make(**overrides) -> Settings:
    """Settings that pass every check, with the given values changed. Ignores any real .env file."""
    values = dict(
        ENVIRONMENT="development",
        SECRET_KEY=STRONG_KEY,
        POSTGRES_PASSWORD="a-strong-database-password",
        AGENT_API_KEY="an-agent-key-long-enough",
        CORS_ORIGINS=["http://dashboard.example"],
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)


def report(settings: Settings, env_file=None):
    return check_settings(settings, env_file)


def test_a_complete_configuration_has_no_findings():
    r = report(make(ENVIRONMENT="production"))
    assert r.errors == []
    assert r.warnings == []


# --- SECRET_KEY ------------------------------------------------------------------------------

@pytest.mark.parametrize("placeholder", [
    "replace_this_with_a_secure_random_string_for_production",
    "REPLACE_THIS_WITH_A_SECURE_RANDOM_STRING_FOR_PRODUCTION",
    "changeme",
    "secret",
    "  change_me  ",
    "replace_this_but_with_a_longer_text_appended_to_it_1234567890",
])
def test_a_placeholder_signing_key_is_refused_in_every_environment(placeholder):
    for env in ("development", "production"):
        r = report(make(ENVIRONMENT=env, SECRET_KEY=placeholder))
        assert any("placeholder" in e for e in r.errors), (env, placeholder)


def test_a_short_signing_key_is_refused():
    r = report(make(SECRET_KEY="a-real-looking-but-short-key"))
    assert any("at least 32" in e for e in r.errors)


def test_a_signing_key_of_exactly_the_minimum_length_is_accepted():
    assert report(make(SECRET_KEY="x" * 32)).errors == []


def test_an_empty_signing_key_is_a_warning_in_development_and_an_error_in_production():
    dev = report(make(SECRET_KEY=""))
    assert dev.errors == [] and any("SECRET_KEY is not set" in w for w in dev.warnings)

    prod = report(make(ENVIRONMENT="production", SECRET_KEY=""))
    assert any("SECRET_KEY is not set" in e for e in prod.errors)


def test_the_environment_name_is_not_case_sensitive():
    assert make(ENVIRONMENT=" Production ").is_production
    assert not make(ENVIRONMENT="staging").is_production


# --- database password -----------------------------------------------------------------------

@pytest.mark.parametrize("weak", ["change_me", "change_me_strong_password", "ai_itmonitor_password", "Password", "postgres"])
def test_a_default_database_password_is_flagged(weak):
    dev = report(make(POSTGRES_PASSWORD=weak))
    assert dev.errors == [] and any("POSTGRES_PASSWORD" in w for w in dev.warnings)
    prod = report(make(ENVIRONMENT="production", POSTGRES_PASSWORD=weak))
    assert any("POSTGRES_PASSWORD" in e for e in prod.errors)


# --- agent key -------------------------------------------------------------------------------

def test_open_agent_enrolment_is_a_warning_in_development_and_an_error_in_production():
    dev = report(make(AGENT_API_KEY=""))
    assert dev.errors == [] and any("AGENT_API_KEY is empty" in w for w in dev.warnings)
    prod = report(make(ENVIRONMENT="production", AGENT_API_KEY=""))
    assert any("AGENT_API_KEY is empty" in e for e in prod.errors)


def test_a_short_agent_key_is_only_a_warning():
    r = report(make(ENVIRONMENT="production", AGENT_API_KEY="short"))
    assert r.errors == [] and any("shorter than 16" in w for w in r.warnings)


# --- CORS ------------------------------------------------------------------------------------

def test_a_wildcard_origin_is_only_flagged_in_production():
    assert report(make(CORS_ORIGINS=["*"])).warnings == []
    prod = report(make(ENVIRONMENT="production", CORS_ORIGINS=["*"]))
    assert prod.errors == [] and any("CORS_ORIGINS" in w for w in prod.warnings)


# --- the settings file -----------------------------------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="file modes are a POSIX notion")
def test_a_settings_file_readable_by_others_is_flagged(tmp_path):
    env = tmp_path / ".env"
    env.write_text("X=1\n")

    env.chmod(0o644)
    r = report(make(), env)
    assert any("chmod 600" in w for w in r.warnings)

    env.chmod(0o600)
    assert report(make(), env).warnings == []


def test_a_missing_settings_file_is_not_a_finding(tmp_path):
    assert report(make(), tmp_path / "absent.env").warnings == []


def test_the_settings_file_is_found_from_the_code_not_from_the_working_directory(tmp_path):
    assert ENV_FILE.is_absolute()
    assert ENV_FILE == BASE_DIR / "backend" / ".env"
    assert Settings.model_config["env_file"] == str(ENV_FILE)

    out = subprocess.run(
        [sys.executable, "-c", "from backend.app.core.config import ENV_FILE; print(ENV_FILE)"],
        cwd=tmp_path, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(BASE_DIR), "SECRET_KEY": STRONG_KEY},
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == str(ENV_FILE)


# --- stopping the process --------------------------------------------------------------------

def test_apply_raises_with_every_error_and_the_fix(capsys):
    s = make(ENVIRONMENT="production", SECRET_KEY="changeme", AGENT_API_KEY="", POSTGRES_PASSWORD="postgres")
    with pytest.raises(ConfigError) as exc:
        apply_settings_check(s, None)
    message = str(exc.value)
    assert "Refusing to start" in message
    assert "init_env.py" in message
    assert "AGENT_API_KEY" in message and "POSTGRES_PASSWORD" in message


def test_apply_prints_warnings_and_carries_on(capsys):
    r = apply_settings_check(make(AGENT_API_KEY=""), None)
    assert r.errors == []
    assert "[WARN] AGENT_API_KEY is empty" in capsys.readouterr().err


def test_starting_the_server_with_the_published_placeholder_key_fails():
    out = subprocess.run(
        [sys.executable, "-c", "import backend.app.core.config"],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(BASE_DIR),
             "SECRET_KEY": "replace_this_with_a_secure_random_string_for_production"},
    )
    assert out.returncode != 0
    assert "Refusing to start" in out.stderr
    assert "placeholder" in out.stderr
