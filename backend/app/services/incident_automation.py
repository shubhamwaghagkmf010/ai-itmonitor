"""Raises incidents from the telemetry agents send, so a runaway machine shows up without anyone
having to press "scan".

Deliberately conservative: an incident needs the limit to be exceeded in several consecutive samples
(one spike is not an incident), one open incident per machine and category, and a cool-down after one
is closed so a value hovering around the limit does not open and close incidents all day."""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from backend.app.models.entities import (
    Incident, IncidentSeverity, IncidentStatus, Machine, MachineMetric,
)
from backend.app.services.anomaly import (
    CPU_WARN, CRITICAL_AT, DISK_WARN, RAM_WARN, detect_metric_anomalies,
)

SUSTAIN_SAMPLES = 3
MAX_SAMPLE_SPAN = timedelta(minutes=5)   # the samples must be consecutive in practice, not spread over hours
REOPEN_COOLDOWN = timedelta(minutes=10)

# Category names match the ones the diagnostic scan uses, so the two never raise the same problem twice.
CATEGORIES = {
    "CPU": ("cpu_percent", CPU_WARN, "High CPU usage", "CPU usage"),
    "MEMORY": ("ram_percent", RAM_WARN, "High memory usage", "Memory usage"),
    "STORAGE": ("disk_percent", DISK_WARN, "Disk almost full", "Disk usage"),
}


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def raise_incidents_for_sample(db: Session, machine: Machine, metric: MachineMetric,
                               top_processes: Optional[List[Dict]] = None,
                               now: Optional[datetime] = None) -> List[Incident]:
    """Opens an incident for every category that has been over its limit for SUSTAIN_SAMPLES samples in
    a row (this one included, so it must already be flushed). Returns the incidents it created; the
    caller commits."""
    now = now or datetime.now(timezone.utc)

    breached = [c for c, (field, limit, _t, _l) in CATEGORIES.items() if getattr(metric, field) >= limit]
    if not breached:
        return []  # the usual case costs nothing: no query is made

    recent = (db.query(MachineMetric).filter(MachineMetric.machine_id == machine.id)
              .order_by(MachineMetric.timestamp.desc(), MachineMetric.id.desc()).limit(SUSTAIN_SAMPLES).all())
    if len(recent) < SUSTAIN_SAMPLES:
        return []
    oldest = _aware(recent[-1].timestamp)
    if oldest is None or now - oldest > MAX_SAMPLE_SPAN:
        return []

    anomaly = detect_metric_anomalies(
        db, machine.id,
        {"cpu_percent": metric.cpu_percent, "ram_percent": metric.ram_percent, "disk_percent": metric.disk_percent},
        exclude_metric_id=metric.id)
    z = anomaly.get("z_scores") or {}

    created = []
    for category in breached:
        field, limit, title, label = CATEGORIES[category]
        if not all(getattr(m, field) >= limit for m in recent):
            continue

        still_open = (db.query(Incident.id)
                      .filter(Incident.machine_id == machine.id, Incident.category == category,
                              Incident.status.in_((IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS))).first())
        if still_open:
            continue
        last_closed = (db.query(Incident).filter(Incident.machine_id == machine.id, Incident.category == category,
                                                 Incident.resolved_at.isnot(None))
                       .order_by(Incident.resolved_at.desc()).first())
        if last_closed and now - _aware(last_closed.resolved_at) < REOPEN_COOLDOWN:
            continue

        value = getattr(metric, field)
        detail = (f"{label} on {machine.hostname} has been {limit:.0f}% or more for the last {SUSTAIN_SAMPLES} "
                  f"samples (now {value:.0f}%).")
        zkey = {"CPU": "cpu_z", "MEMORY": "ram_z"}.get(category)
        if zkey and z.get(zkey) is not None and z[zkey] > 0:
            detail += f" That is {z[zkey]:.1f} standard deviations above this machine's recent average."
        if top_processes and category in ("CPU", "MEMORY"):
            key = "cpu_percent" if category == "CPU" else "memory_percent"
            top = max(top_processes, key=lambda p: p.get(key) or 0)
            if (top.get(key) or 0) > 0:
                detail += f" Busiest process: {top.get('name')} (PID {top.get('pid')}) at {top.get(key):.0f}%."

        incident = Incident(
            incident_code=f"INC-{machine.id}-{uuid.uuid4().hex[:6].upper()}",
            title=f"{title} on {machine.hostname}",
            description=detail,
            category=category,
            severity=IncidentSeverity.CRITICAL if value >= CRITICAL_AT else IncidentSeverity.HIGH,
            status=IncidentStatus.OPEN,
            machine_id=machine.id,
        )
        db.add(incident)
        created.append(incident)
    if created:
        db.flush()
    return created
