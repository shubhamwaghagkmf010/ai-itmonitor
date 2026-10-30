"""Checks on the files that decide how the application is installed and run. They are static (nothing is
built or started), so they run anywhere; the compose check is skipped where the docker CLI is absent."""
import os
import re
import shutil
import subprocess

import pytest
import yaml

from backend.app.core.config import BASE_DIR

DOCKERFILE = (BASE_DIR / "docker" / "Dockerfile.backend").read_text()
FRONTEND_DOCKERFILE = (BASE_DIR / "docker" / "Dockerfile.frontend").read_text()
NGINX = (BASE_DIR / "docker" / "nginx.conf").read_text()
COMPOSE = yaml.safe_load((BASE_DIR / "docker-compose.yml").read_text())
COMPOSE_TEXT = (BASE_DIR / "docker-compose.yml").read_text()
IGNORE = [l.strip() for l in (BASE_DIR / ".dockerignore").read_text().splitlines() if l.strip() and not l.startswith("#")]


# --- the backend image --------------------------------------------------------------------------------------

def test_the_backend_does_not_run_as_root():
    lines = [l.strip() for l in DOCKERFILE.splitlines()]
    assert "USER app" in lines
    assert lines.index("USER app") > max(i for i, l in enumerate(lines) if l.startswith("RUN "))  # after everything that needs root
    assert "useradd" in DOCKERFILE and "--uid 10001" in DOCKERFILE


def test_the_backend_image_carries_no_compiler_or_curl():
    assert "build-essential" not in DOCKERFILE and "libpq-dev" not in DOCKERFILE
    assert not re.search(r"\bcurl\b", DOCKERFILE.replace("# ", ""))


def test_the_backend_has_a_healthcheck_and_runs_migrations_first():
    assert "HEALTHCHECK" in DOCKERFILE and "ENTRYPOINT" in DOCKERFILE
    entrypoint = (BASE_DIR / "docker" / "entrypoint.sh").read_text()
    assert "\r" not in entrypoint  # a CRLF script fails with "not found" inside a Linux container
    assert entrypoint.index("scripts/migrate.py") < entrypoint.index('exec "$@"')
    assert "RUN_MIGRATIONS" in entrypoint and "set -e" in entrypoint


def test_the_image_gets_a_writable_place_for_the_oui_cache():
    assert "OUI_CACHE_DIR=/data" in DOCKERFILE and "chown app:app /data" in DOCKERFILE


def test_the_oui_cache_location_follows_the_environment(monkeypatch, tmp_path):
    import importlib
    from backend.app.services import netscan

    monkeypatch.setenv("OUI_CACHE_DIR", str(tmp_path))
    try:
        assert importlib.reload(netscan).OUI_CACHE == tmp_path / "oui_cache.csv"
        monkeypatch.delenv("OUI_CACHE_DIR")
        assert importlib.reload(netscan).OUI_CACHE.name == "oui_cache.csv"
        assert importlib.reload(netscan).OUI_CACHE.parent == (BASE_DIR / "backend" / "app" / "services")
    finally:
        importlib.reload(netscan)


# --- what is kept out of images ------------------------------------------------------------------------------

@pytest.mark.parametrize("pattern", [".env", "**/.env", "*.pem", "*.key", "certs/", ".git", "agent/agent_config.json",
                                     "**/agent_config.json", "tests/", "**/node_modules/", "**/__pycache__/"])
def test_dockerignore_keeps_secrets_and_state_out_of_images(pattern):
    assert pattern in IGNORE


def test_the_example_settings_file_is_still_available():
    assert "!**/.env.example" in IGNORE


def test_the_backend_image_copies_no_settings_file():
    copies = [l for l in DOCKERFILE.splitlines() if l.startswith("COPY ")]
    assert not any(".env" in l for l in copies)


# --- compose ----------------------------------------------------------------------------------------------------

def test_the_database_password_is_not_written_in_the_compose_file():
    assert "ai_itmonitor_password" not in COMPOSE_TEXT
    for service in ("postgres", "backend"):
        value = COMPOSE["services"][service]["environment"]["POSTGRES_PASSWORD"]
        assert value.startswith("${POSTGRES_PASSWORD:?"), service  # compose refuses to start without one


def test_the_backend_reads_the_settings_file_that_init_env_creates():
    assert COMPOSE["services"]["backend"]["env_file"] == ["backend/.env"]


def test_the_backend_is_locked_down_and_waits_for_a_healthy_database():
    backend = COMPOSE["services"]["backend"]
    assert "no-new-privileges:true" in backend["security_opt"]
    assert backend["cap_drop"] == ["ALL"] and backend["cap_add"] == ["NET_RAW"]
    assert backend["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert "healthcheck" in COMPOSE["services"]["postgres"]
    assert backend["restart"] == "unless-stopped"


def test_the_api_and_database_ports_are_bound_to_this_machine_by_default():
    assert COMPOSE["services"]["postgres"]["ports"] == ["127.0.0.1:5432:5432"]
    (port,) = COMPOSE["services"]["backend"]["ports"]
    assert port == "${BACKEND_PUBLISH:-127.0.0.1:8000}:8000"


def test_only_the_web_server_container_is_trusted_to_forward_addresses():
    import json
    backend_env = COMPOSE["services"]["backend"]["environment"]
    trusted = json.loads(backend_env["TRUSTED_PROXIES"])
    frontend_ip = COMPOSE["services"]["frontend"]["networks"]["monitor"]["ipv4_address"]
    assert trusted == [f"{frontend_ip}/32"]
    subnet = COMPOSE["networks"]["monitor"]["ipam"]["config"][0]["subnet"]
    import ipaddress
    assert ipaddress.ip_address(frontend_ip) in ipaddress.ip_network(subnet)
    assert ipaddress.ip_address(frontend_ip) != ipaddress.ip_network(subnet).network_address + 1  # not the gateway (the host)


def test_all_services_share_the_private_network():
    for name, service in COMPOSE["services"].items():
        networks = service["networks"]
        assert "monitor" in networks, name


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")
def test_docker_compose_accepts_the_file_and_refuses_to_run_without_a_password(tmp_path):
    settings = BASE_DIR / "backend" / ".env"
    if settings.exists():
        pytest.skip("a real backend/.env exists; not touching it")
    probe = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip("docker compose plugin not available")
    try:
        settings.write_text("POSTGRES_PASSWORD=a-test-only-password\nSECRET_KEY=x\n")
        ok = subprocess.run(["docker", "compose", "--env-file", str(settings), "config"], cwd=BASE_DIR, capture_output=True, text=True)
        assert ok.returncode == 0, ok.stderr
        assert "a-test-only-password" in ok.stdout

        settings.write_text("SECRET_KEY=x\n")
        refused = subprocess.run(["docker", "compose", "--env-file", str(settings), "config"], cwd=BASE_DIR, capture_output=True, text=True)
        assert refused.returncode != 0 and "POSTGRES_PASSWORD" in refused.stderr
    finally:
        settings.unlink(missing_ok=True)


# --- the web server --------------------------------------------------------------------------------------------------

def test_nginx_hides_its_version_and_discards_a_visitors_own_forwarded_header():
    assert "server_tokens off;" in NGINX
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in NGINX
    assert "$proxy_add_x_forwarded_for" not in NGINX


def test_nginx_allows_the_largest_agent_upload_and_no_more_than_needed():
    assert "client_max_body_size 10m;" in NGINX  # the inventory limit in the API is 8 MB


def test_the_frontend_image_installs_exactly_what_the_lock_file_says():
    assert "npm ci" in FRONTEND_DOCKERFILE and "npm install" not in FRONTEND_DOCKERFILE


# --- dependencies ----------------------------------------------------------------------------------------------------------

REQUIREMENTS = [l.strip() for l in (BASE_DIR / "backend" / "requirements.txt").read_text().splitlines()
                if l.strip() and not l.startswith("#")]


def test_every_dependency_is_pinned_to_one_version():
    assert all("==" in l for l in REQUIREMENTS), [l for l in REQUIREMENTS if "==" not in l]


@pytest.mark.parametrize("name", ["python-jose", "ecdsa", "passlib", "pandas", "scikit-learn", "psutil"])
def test_unmaintained_or_unused_libraries_are_gone(name):
    assert not any(l.lower().startswith(name) for l in REQUIREMENTS)


def test_libraries_with_published_advisories_are_at_fixed_versions():
    def version(name):
        line = next(l for l in REQUIREMENTS if l.lower().startswith(name.lower()))
        return tuple(int(p) for p in line.split("==")[1].split(".")[:3])

    assert version("PyJWT") >= (2, 15, 0)
    assert version("python-multipart") >= (0, 0, 31)
    assert version("python-dotenv") >= (1, 2, 2)


def test_the_code_no_longer_imports_the_removed_libraries():
    offenders = []
    for path in list((BASE_DIR / "backend").rglob("*.py")) + list((BASE_DIR / "scripts").glob("*.py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"^\s*(from|import)\s+(jose|passlib|pandas|sklearn)\b", text, re.M):
            offenders.append(str(path))
    assert offenders == []

