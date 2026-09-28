import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, Float, DateTime, 
    ForeignKey, Text, JSON, Enum
)
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class UserRole:
    ADMIN = "ADMIN"
    MANAGER = "MANAGER"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"
    CUSTOM = "CUSTOM"

class MachineStatus(str, enum.Enum):
    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    OFFLINE = "OFFLINE"

class IncidentSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

# Permissions with WOL additions
DEFAULT_PERMISSIONS = {
    "ADMIN": [
        "dashboard.view", "telemetry.view", "processes.view", "processes.kill",
        "remote_ops.execute", "incidents.view", "incidents.resolve",
        "incidents.analyze", "incidents.export", "admin.users_manage",
        "admin.audit_view", "ai_chat.use", "wol.view", "wol.execute", "wol.manage"
    ],
    "MANAGER": [
        "dashboard.view", "telemetry.view", "processes.view", "processes.kill",
        "incidents.view", "incidents.resolve", "incidents.analyze",
        "incidents.export", "admin.audit_view", "ai_chat.use", "wol.view", "wol.execute"
    ],
    "OPERATOR": [
        "dashboard.view", "telemetry.view", "processes.view", "processes.kill",
        "incidents.view", "incidents.resolve", "ai_chat.use", "wol.view", "wol.execute"
    ],
    "VIEWER": [
        "dashboard.view", "telemetry.view", "processes.view", "incidents.view", "wol.view"
    ]
}

# Widget list with wolController
DEFAULT_WIDGETS = {
    "ADMIN": {
        "kpiCards": True, "telemetryChart": True, "remoteHub": True,
        "storageBreakdown": True, "taskManager": True, "nodeInventory": True,
        "incidentsTable": True, "wolController": True
    },
    "MANAGER": {
        "kpiCards": True, "telemetryChart": True, "remoteHub": False,
        "storageBreakdown": True, "taskManager": True, "nodeInventory": True,
        "incidentsTable": True, "wolController": True
    },
    "OPERATOR": {
        "kpiCards": True, "telemetryChart": True, "remoteHub": True,
        "storageBreakdown": True, "taskManager": True, "nodeInventory": True,
        "incidentsTable": True, "wolController": True
    },
    "VIEWER": {
        "kpiCards": True, "telemetryChart": True, "remoteHub": False,
        "storageBreakdown": True, "taskManager": False, "nodeInventory": True,
        "incidentsTable": True, "wolController": False
    }
}

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="OPERATOR", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    permissions = Column(JSON, default=list, nullable=True)
    widget_permissions = Column(JSON, default=dict, nullable=True)
    
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_email = Column(String(255), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    target = Column(String(255), nullable=True)
    result = Column(String(50), default="SUCCESS", nullable=False)
    ip_address = Column(String(50), nullable=True)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

class Machine(Base):
    __tablename__ = "machines"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), unique=True, index=True, nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(50), nullable=True)
    mac_address = Column(String(17), nullable=True, index=True)
    logged_in_user = Column(String(100), default="System", nullable=True)
    os_name = Column(String(100), nullable=False)
    os_version = Column(String(100), nullable=True)
    architecture = Column(String(50), nullable=True)
    agent_version = Column(String(50), default="1.0.0", nullable=False)
    status = Column(Enum(MachineStatus), default=MachineStatus.HEALTHY, nullable=False)
    wol_enabled = Column(Boolean, default=True, nullable=False)
    wol_port = Column(Integer, default=9, nullable=False)
    last_wol_request = Column(DateTime(timezone=True), nullable=True)
    last_heartbeat = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=True)

    metrics = relationship("MachineMetric", back_populates="machine", cascade="all, delete-orphan")
    network_metrics = relationship("NetworkMetric", back_populates="machine", cascade="all, delete-orphan")
    processes = relationship("ProcessSnapshot", back_populates="machine", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="machine", cascade="all, delete-orphan")
    commands = relationship("AgentCommand", back_populates="machine", cascade="all, delete-orphan")
    logs = relationship("LogEntry", back_populates="machine", cascade="all, delete-orphan")
    wol_requests = relationship("WOLRequest", back_populates="machine", cascade="all, delete-orphan")

class MachineMetric(Base):
    __tablename__ = "machine_metrics"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    cpu_percent = Column(Float, nullable=False)
    ram_percent = Column(Float, nullable=False)
    ram_used_gb = Column(Float, nullable=False)
    ram_total_gb = Column(Float, nullable=False)
    disk_percent = Column(Float, nullable=False)
    disk_used_gb = Column(Float, nullable=False)
    disk_total_gb = Column(Float, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    machine = relationship("Machine", back_populates="metrics")

class NetworkMetric(Base):
    __tablename__ = "network_metrics"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    bytes_sent = Column(Float, default=0.0, nullable=False)
    bytes_recv = Column(Float, default=0.0, nullable=False)
    packets_sent = Column(Integer, default=0, nullable=False)
    packets_recv = Column(Integer, default=0, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    machine = relationship("Machine", back_populates="network_metrics")

class ProcessSnapshot(Base):
    __tablename__ = "process_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    metric_id = Column(Integer, ForeignKey("machine_metrics.id", ondelete="CASCADE"), nullable=True)
    pid = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    cpu_percent = Column(Float, default=0.0, nullable=False)
    memory_percent = Column(Float, default=0.0, nullable=False)
    status = Column(String(50), default="running", nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    machine = relationship("Machine", back_populates="processes")

class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(100), default="syslog", nullable=False)
    log_level = Column(String(50), default="ERROR", nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    machine = relationship("Machine", back_populates="logs")

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_code = Column(String(50), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), default="ANOMALY", nullable=False)
    severity = Column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM, nullable=False)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    resolution_notes = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=True)

    machine = relationship("Machine", back_populates="incidents")
    ai_analysis = relationship("AIAnalysis", back_populates="incident", uselist=False, cascade="all, delete-orphan")

class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, nullable=False)
    observed_facts = Column(JSON, nullable=False)
    probable_cause = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=False)
    recommended_actions = Column(JSON, nullable=False)
    preventive_actions = Column(JSON, nullable=False)
    confidence_score = Column(Float, default=0.85, nullable=False)
    model_name = Column(String(100), default="qwen2.5:0.5b", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    incident = relationship("Incident", back_populates="ai_analysis")

class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    command_type = Column(String(50), nullable=False)
    payload_json = Column(JSON, nullable=False)
    status = Column(String(20), default="PENDING")
    result_output = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    executed_at = Column(DateTime(timezone=True), nullable=True)

    machine = relationship("Machine", back_populates="commands")

class WOLRequest(Base):
    __tablename__ = "wol_requests"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    triggered_by = Column(String(255), nullable=False)
    mac_address = Column(String(17), nullable=False)
    broadcast_ip = Column(String(50), default="255.255.255.255", nullable=False)
    port = Column(Integer, default=9, nullable=False)
    status = Column(String(30), default="REQUEST_CREATED", nullable=False)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=True)

    machine = relationship("Machine", back_populates="wol_requests")


class ExtendedMetric(Base):
    """Best-effort extra telemetry an agent may report alongside core metrics: running
    services, containers, temperature sensors, SMART disk health and GPU. Each field is
    JSON so the shape can evolve per platform, and any that a host cannot provide is null."""
    __tablename__ = "extended_metrics"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True)
    services = Column(JSON, nullable=True)
    containers = Column(JSON, nullable=True)
    sensors = Column(JSON, nullable=True)
    disks_smart = Column(JSON, nullable=True)
    gpu = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)


class NetworkDevice(Base):
    """A device discovered on the LAN by the network scanner — the asset inventory."""
    __tablename__ = "network_devices"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), nullable=False, index=True)
    mac_address = Column(String(50), nullable=True, index=True)
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(120), nullable=True)
    device_type = Column(String(60), nullable=True)
    os_guess = Column(String(50), nullable=True)
    open_ports = Column(Text, nullable=True)
    source_subnet = Column(String(120), nullable=True)
    is_online = Column(Boolean, default=True, nullable=False)
    notes = Column(String(255), nullable=True)
    first_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)



class ScanRange(Base):
    """A saved network range/subnet the user can re-scan with one click."""
    __tablename__ = "scan_ranges"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    target = Column(String(120), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)



class MachineInventory(Base):
    """OCS-style per-machine inventory: detailed hardware and the installed-software list."""
    __tablename__ = "machine_inventory"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    hardware = Column(JSON, nullable=True)
    software = Column(JSON, nullable=True)
    software_count = Column(Integer, default=0, nullable=False)
    collected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class Asset(Base):
    """Formal asset-register entry (Excel-style). Technical columns are auto-filled from agent
    inventory; the rest (asset no, category, allocation, warranty, licence) are entered by hand."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_no = Column(String(80), nullable=True)
    category = Column(String(120), nullable=True)
    sub_category = Column(String(120), nullable=True)
    host_name = Column(String(255), nullable=True, index=True)
    make = Column(String(120), nullable=True)
    model = Column(String(160), nullable=True)
    allocation_type = Column(String(120), nullable=True)
    allocation_purpose = Column(String(255), nullable=True)
    owned_by_emp_id = Column(String(80), nullable=True)
    owned_by_emp_name = Column(String(160), nullable=True)
    workstation_number = Column(String(80), nullable=True)
    serial_no = Column(String(160), nullable=True)
    processor_type = Column(String(200), nullable=True)
    ram = Column(String(60), nullable=True)
    hard_disk_size = Column(String(60), nullable=True)
    os_architecture = Column(String(40), nullable=True)
    os_version = Column(String(160), nullable=True)
    os_edition = Column(String(160), nullable=True)
    license_key = Column(String(120), nullable=True)
    warranty_start = Column(String(40), nullable=True)
    warranty_end = Column(String(40), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=True)
