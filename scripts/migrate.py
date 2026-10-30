"""Brings the database schema up to date. Run by the container at start-up (RUN_MIGRATIONS=1) or by hand:

    python scripts/migrate.py

It copes with the three databases that exist in practice:
  * a new, empty one            -> built entirely by the migrations;
  * one created by create_all() -> the project's earlier way of making tables, with no Alembic history:
                                   any missing tables are created, it is marked as being at the last revision
                                   that predates the catch-up migration, and the rest are applied;
  * one Alembic already manages -> upgraded to the latest revision.
Running it again changes nothing."""
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT)

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

# The last revision before a8b9c0d1e2f3, which brings an older create_all() database level.
LEGACY_STAMP = "a7b8c9d0e1f2"


def _config() -> Config:
    cfg = Config(os.path.join(ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ROOT, "backend", "alembic"))
    return cfg


def wait_for_database(engine, attempts: int = 30, delay: float = 2.0, out=print) -> None:
    """The database container may still be starting when this one is."""
    for attempt in range(1, attempts + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as exc:
            if attempt == attempts:
                raise
            out(f"[migrate] database not ready ({type(exc).__name__}); retrying in {delay:.0f}s ({attempt}/{attempts})")
            time.sleep(delay)


def migrate(engine=None, config: Config = None, out=print) -> str:
    """Returns what it did: "upgraded", "adopted" (a create_all() database) or "built" (an empty one)."""
    from backend.app.core.database import Base, engine as app_engine
    import backend.app.models  # noqa: F401  (registers every table on Base.metadata)

    engine = engine or app_engine
    config = config or _config()
    wait_for_database(engine, out=out)
    tables = set(inspect(engine).get_table_names())

    if "alembic_version" in tables:
        action = "upgraded"
    elif "users" in tables:
        out("[migrate] found tables without migration history (made by create_all); adopting them")
        Base.metadata.create_all(bind=engine)  # only creates tables that are missing
        command.stamp(config, LEGACY_STAMP)
        action = "adopted"
    else:
        out("[migrate] empty database; building it from the migrations")
        action = "built"

    command.upgrade(config, "head")
    out(f"[migrate] schema is at the latest revision ({action})")
    return action


if __name__ == "__main__":
    migrate()
