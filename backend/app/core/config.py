import os
import secrets
import sys
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL as DatabaseURL

# The repository root, found from this file rather than from the working directory, so the
# settings file is read no matter where the server is started from. (In the container the
# code lives in /app, which gives /app/backend/.env as before.)
BASE_DIR = Path(__file__).resolve().parents[3]
ENV_FILE = BASE_DIR / "backend" / ".env"

MIN_SECRET_KEY_LENGTH = 32

# Values that ship in example files or are what people type first. A signing key (or database
# password) that anyone can read in a public repository protects nothing.
PLACEHOLDER_SECRETS = {
    "replace_this_with_a_secure_random_string_for_production",
    "change_me", "changeme", "change-me", "secret", "secretkey", "secret_key",
    "your-secret-key", "your_secret_key", "default", "password", "test", "dev",
}
WEAK_DB_PASSWORDS = {
    "change_me", "change_me_strong_password", "changeme", "ai_itmonitor_password",
    "password", "postgres", "admin", "123456",
}


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-ITMonitor"
    API_V1_STR: str = "/api/v1"

    # "production" turns the warnings below into startup errors.
    ENVIRONMENT: str = "development"

    # No signing secret is compiled in. Set SECRET_KEY in backend/.env (scripts/init_env.py makes
    # one). When it is left empty a random key is generated for each start, which ends every
    # session on restart; a placeholder or a short key is refused outright.
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "ai_itmonitor_user"
    POSTGRES_PASSWORD: str = "change_me"
    POSTGRES_DB: str = "ai_itmonitor_db"
    POSTGRES_PORT: int = 5432

    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2:1b"

    # Allowed browser origins. A wildcard keeps LAN access easy but disables credentialed
    # CORS (see main.py); list explicit origins in production.
    CORS_ORIGINS: List[str] = ["*"]

    # Shared key an agent must send (X-Agent-Key) to register and push metrics. Empty means
    # open enrollment (development only); set AGENT_API_KEY in .env to require it.
    AGENT_API_KEY: str = ""

    # Delete metrics/logs older than this many days (0 disables cleanup).
    METRIC_RETENTION_DAYS: int = 30

    # The HTTPS address agents should migrate to (server pushes this in every
    # heartbeat as a hint; an agent only switches after it verifies the address
    # actually works). Update this ONE value - via PUBLIC_HTTPS_BASE_URL in .env -
    # when a real domain is ready, and the whole fleet migrates again automatically.
    PUBLIC_HTTPS_BASE_URL: str = ""  # set the real value in .env - never hardcode an IP/domain here

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.strip().lower() == "production"

    @computed_field
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        # Built with SQLAlchemy's URL helper (not an f-string) so the source never
        # contains a literal "user:password@" substring, and special characters in
        # the password are escaped correctly. hide_password=False because this
        # string is the real value create_engine() connects with.
        return DatabaseURL.create(
            drivername="postgresql",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB,
        ).render_as_string(hide_password=False)

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@dataclass
class SettingsReport:
    """What is wrong with a configuration: errors stop the server, warnings are printed."""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ConfigError(RuntimeError):
    """The configuration is unsafe to start with."""


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered in PLACEHOLDER_SECRETS or "replace_this" in lowered or lowered.startswith("changeme")


def check_settings(s: Settings, env_file: Optional[Path] = ENV_FILE) -> SettingsReport:
    """Looks for configuration that would leave the system open. Pure: it reads nothing but its
    arguments (and the mode of the settings file), so it can be tested without starting anything."""
    report = SettingsReport()
    prod = s.is_production

    def problem(message: str) -> None:
        (report.errors if prod else report.warnings).append(message)

    # --- token signing key ------------------------------------------------------------------
    key = s.SECRET_KEY
    if key:
        if _is_placeholder(key):
            report.errors.append(
                "SECRET_KEY is a placeholder that is published in the example settings file, so anyone "
                "could sign a valid administrator token with it. Generate a real one: python scripts/init_env.py"
            )
        elif len(key) < MIN_SECRET_KEY_LENGTH:
            report.errors.append(
                f"SECRET_KEY is only {len(key)} characters; use at least {MIN_SECRET_KEY_LENGTH} random ones "
                "(python scripts/init_env.py makes one)."
            )
    else:
        problem("SECRET_KEY is not set: a random key is generated on every start, so every session ends "
                "on restart and several workers would each use a different key.")

    # --- database ---------------------------------------------------------------------------
    if s.POSTGRES_PASSWORD.strip().lower() in WEAK_DB_PASSWORDS:
        problem("POSTGRES_PASSWORD is a default or well-known value. Set a strong one in backend/.env.")

    # --- agents -----------------------------------------------------------------------------
    if not s.AGENT_API_KEY:
        problem("AGENT_API_KEY is empty, so anyone who can reach the API can register an agent and "
                "send it metrics. Set a key and give the same one to every agent.")
    elif len(s.AGENT_API_KEY) < 16:
        report.warnings.append("AGENT_API_KEY is shorter than 16 characters.")

    # --- browser access ---------------------------------------------------------------------
    if prod and "*" in s.CORS_ORIGINS:
        report.warnings.append("CORS_ORIGINS allows every origin; list the dashboard's address instead.")

    # --- the settings file itself -----------------------------------------------------------
    if env_file is not None and os.name == "posix":
        try:
            mode = stat.S_IMODE(env_file.stat().st_mode)
        except OSError:
            mode = None
        if mode is not None and mode & 0o077:
            report.warnings.append(
                f"{env_file} can be read by other users on this machine (mode {mode:o}); run: chmod 600 {env_file}"
            )

    return report


def apply_settings_check(s: Settings, env_file: Optional[Path] = ENV_FILE) -> SettingsReport:
    """Stops the process on an unsafe configuration; prints warnings otherwise."""
    report = check_settings(s, env_file)
    for warning in report.warnings:
        print(f"[WARN] {warning}", file=sys.stderr, flush=True)
    if report.errors:
        raise ConfigError(
            "Refusing to start with an unsafe configuration:\n  - " + "\n  - ".join(report.errors)
        )
    return report


settings = Settings()
apply_settings_check(settings)

if not settings.SECRET_KEY:
    settings.SECRET_KEY = secrets.token_urlsafe(48)
