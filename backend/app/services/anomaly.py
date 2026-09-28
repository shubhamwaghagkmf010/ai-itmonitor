import numpy as np
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.app.models.entities import MachineMetric


def detect_metric_anomalies(db: Session, machine_id: int, current_metric: Dict[str, float]) -> Dict[str, Any]:
    history = db.query(MachineMetric).filter(
        MachineMetric.machine_id == machine_id
    ).order_by(MachineMetric.timestamp.desc()).limit(30).all()

    if len(history) < 5:
        is_cpu_anomaly = current_metric.get("cpu_percent", 0) >= 85.0
        is_ram_anomaly = current_metric.get("ram_percent", 0) >= 85.0
        is_disk_anomaly = current_metric.get("disk_percent", 0) >= 90.0
        
        has_anomaly = is_cpu_anomaly or is_ram_anomaly or is_disk_anomaly
        return {
            "has_anomaly": has_anomaly,
            "anomalies_detected": [
                k for k, v in [("CPU", is_cpu_anomaly), ("RAM", is_ram_anomaly), ("Disk", is_disk_anomaly)] if v
            ],
            "severity": "CRITICAL" if (current_metric.get("cpu_percent", 0) >= 90.0) else "WARNING",
            "z_scores": {}
        }

    cpu_series = [m.cpu_percent for m in history]
    ram_series = [m.ram_percent for m in history]

    def calculate_z_score(val: float, series: List[float]) -> float:
        mean = float(np.mean(series))
        std = float(np.std(series))
        if std == 0:
            return 0.0
        return (val - mean) / std

    cpu_z = calculate_z_score(current_metric.get("cpu_percent", 0), cpu_series)
    ram_z = calculate_z_score(current_metric.get("ram_percent", 0), ram_series)

    cpu_flag = bool(cpu_z > 2.5 or current_metric.get("cpu_percent", 0) >= 85.0)
    ram_flag = bool(ram_z > 2.5 or current_metric.get("ram_percent", 0) >= 85.0)
    disk_flag = bool(current_metric.get("disk_percent", 0) >= 90.0)

    anomalies = []
    if cpu_flag: anomalies.append("CPU")
    if ram_flag: anomalies.append("RAM")
    if disk_flag: anomalies.append("Disk")

    return {
        "has_anomaly": len(anomalies) > 0,
        "anomalies_detected": anomalies,
        "severity": "CRITICAL" if (current_metric.get("cpu_percent", 0) >= 90.0 or current_metric.get("ram_percent", 0) >= 90.0) else "HIGH" if len(anomalies) > 0 else "LOW",
        "z_scores": {
            "cpu_z": round(cpu_z, 2),
            "ram_z": round(ram_z, 2)
        }
    }
