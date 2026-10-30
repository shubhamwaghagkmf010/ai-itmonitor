from datetime import datetime, timezone, timedelta
from backend.app.core.database import SessionLocal
from backend.app.core.config import settings
from backend.app.models.entities import (
    AgentCommand, MachineMetric, NetworkMetric, ProcessSnapshot, ExtendedMetric, LogEntry,
)

BATCH_SIZE = 10_000


def _delete_in_batches(db, model, condition, batch_size=BATCH_SIZE) -> int:
    """Deletes matching rows a slice at a time, committing after each, so cleaning a large backlog never
    holds one huge transaction (and its locks) open while agents are trying to write."""
    total = 0
    while True:
        ids = db.query(model.id).filter(condition).limit(batch_size)
        removed = db.query(model).filter(model.id.in_(ids.scalar_subquery())).delete(synchronize_session=False)
        db.commit()
        total += removed
        if removed < batch_size:
            return total


def purge_old_data(session_factory=None):
    """Delete time-series rows older than METRIC_RETENTION_DAYS. Idempotent and safe to run
    repeatedly; returns a per-table count of what was removed.

    Remote commands are cleaned up too once they are finished (completed, failed, expired, cancelled);
    ones still waiting or in flight are never deleted. The audit log is deliberately not touched."""
    days = settings.METRIC_RETENTION_DAYS
    if days and days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    else:
        return {"skipped": True, "reason": "retention disabled"}

    db = (session_factory or SessionLocal)()
    deleted = {}
    try:
        for model in (ProcessSnapshot, ExtendedMetric, NetworkMetric, MachineMetric, LogEntry):
            deleted[model.__tablename__] = _delete_in_batches(db, model, model.timestamp < cutoff)
        deleted[AgentCommand.__tablename__] = _delete_in_batches(
            db, AgentCommand,
            (AgentCommand.created_at < cutoff) & AgentCommand.status.notin_(("PENDING", "DISPATCHED")))
    finally:
        db.close()
    return {"cutoff": cutoff.isoformat(), "retention_days": days, "deleted": deleted}
