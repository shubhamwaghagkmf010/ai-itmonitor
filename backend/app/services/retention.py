from datetime import datetime, timezone, timedelta
from backend.app.core.database import SessionLocal
from backend.app.core.config import settings
from backend.app.models.entities import (
    MachineMetric, NetworkMetric, ProcessSnapshot, ExtendedMetric, LogEntry,
)


def purge_old_data():
    """Delete time-series rows older than METRIC_RETENTION_DAYS. Idempotent and safe to run
    repeatedly; returns a per-table count of what was removed."""
    days = settings.METRIC_RETENTION_DAYS
    if days and days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    else:
        return {"skipped": True, "reason": "retention disabled"}

    db = SessionLocal()
    deleted = {}
    try:
        for model in (ProcessSnapshot, ExtendedMetric, NetworkMetric, MachineMetric, LogEntry):
            deleted[model.__tablename__] = (
                db.query(model).filter(model.timestamp < cutoff).delete(synchronize_session=False)
            )
        db.commit()
    finally:
        db.close()
    return {"cutoff": cutoff.isoformat(), "retention_days": days, "deleted": deleted}
