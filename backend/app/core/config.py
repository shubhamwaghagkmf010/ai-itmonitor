import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import computed_field
from sqlalchemy.engine import URL as DatabaseURL
from typing import List


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-ITMonitor"
    API_V1_STR: str = "/api/v1"

    # No signing secret is compiled in. Set SECRET_KEY in backend/.env for anything beyond
    # throwaway local use; when unset a random one is generated each start (which invalidates
    # existing tokens on restart), so a fresh install is never signed with a known key.
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
        env_file="backend/.env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()

if not settings.SECRET_KEY:
    settings.SECRET_KEY = secrets.token_urlsafe(48)
    print("[WARN] SECRET_KEY is not set; generated a temporary one for this run. "
          "Set SECRET_KEY in backend/.env for stable sessions.")
