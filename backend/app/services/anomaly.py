import numpy as np
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.app.models.entities import MachineMetric, MachineStatus

# One set of thresholds for everything that judges a sample: the status badge, anomaly detection and
# the incidents raised from it.
CPU_WARN = 85.0
RAM_WARN = 85.0
DISK_WARN = 90.0
CRITICAL_AT = 95.0
Z_THRESHOLD = 2.5


def classify_status(cpu: float, ram: float, disk: float) -> MachineStatus:
    """The health of a machine that is reporting, judged from its latest sample."""
    if max(cpu, ram, disk) >= CRITICAL_AT:
        return MachineStatus.CRITICAL
    if cpu >= CPU_WARN or ram >= RAM_WARN or disk >= DISK_WARN:
        return MachineStatus.WARNING
    return MachineStatus.HEALTHY


def detect_metric_anomalies(db: Session, machine_id: int, current_metric: Dict[str, float],
                            exclude_metric_id: Optional[int] = None) -> Dict[str, Any]:
    """Flags CPU/RAM/disk values that are over a fixed limit or, with enough history, far above this
    machine's own recent average (z-score). `exclude_metric_id` keeps the sample being judged out of
    its own baseline, which would otherwise pull the average towards it and hide a spike."""
    q = db.query(MachineMetric).filter(MachineMetric.machine_id == machine_id)
    if exclude_metric_id is not None:
        q = q.filter(MachineMetric.id != exclude_metric_id)
    history = q.order_by(MachineMetric.timestamp.desc(), MachineMetric.id.desc()).limit(30).all()

    cpu = current_metric.get("cpu_percent", 0)
    ram = current_metric.get("ram_percent", 0)
    disk = current_metric.get("disk_percent", 0)

    def severity(anomalies: List[str]) -> str:
        if max(cpu, ram, disk) >= CRITICAL_AT:
            return "CRITICAL"
        return "HIGH" if anomalies else "LOW"

    if len(history) < 5:
        anomalies = [name for name, hit in (("CPU", cpu >= CPU_WARN), ("RAM", ram >= RAM_WARN), ("Disk", disk >= DISK_WARN)) if hit]
        return {"has_anomaly": bool(anomalies), "anomalies_detected": anomalies,
                "severity": severity(anomalies), "z_scores": {}}

    def calculate_z_score(val: float, series: List[float]) -> float:
        mean = float(np.mean(series))
        std = float(np.std(series))
        if std == 0:
            return 0.0
        return (val - mean) / std

    cpu_z = calculate_z_score(cpu, [m.cpu_percent for m in history])
    ram_z = calculate_z_score(ram, [m.ram_percent for m in history])

    anomalies = []
    if cpu_z > Z_THRESHOLD or cpu >= CPU_WARN:
        anomalies.append("CPU")
    if ram_z > Z_THRESHOLD or ram >= RAM_WARN:
        anomalies.append("RAM")
    if disk >= DISK_WARN:
        anomalies.append("Disk")

    return {
        "has_anomaly": bool(anomalies),
        "anomalies_detected": anomalies,
        "severity": severity(anomalies),
        "z_scores": {"cpu_z": round(cpu_z, 2), "ram_z": round(ram_z, 2)},
    }
