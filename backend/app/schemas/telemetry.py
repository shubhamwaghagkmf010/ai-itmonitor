from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime
from backend.app.models.entities import MachineStatus


class AgentRegisterRequest(BaseModel):
    hostname: str
    os_name: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    agent_version: str = "1.0.0"
    ip_address: Optional[str] = None
    logged_in_user: Optional[str] = "System"


class AgentRegisterResponse(BaseModel):
    agent_id: str
    machine_id: int
    hostname: str
    logged_in_user: Optional[str] = "System"
    status: MachineStatus
    message: str


class ProcessInfo(BaseModel):
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    status: Optional[str] = None


class CommandResultReport(BaseModel):
    command_id: int
    status: str
    output: str


class MetricsIngestRequest(BaseModel):
    agent_id: str
    logged_in_user: Optional[str] = "System"
    cpu_percent: float
    ram_percent: float
    ram_used_gb: float
    ram_total_gb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    bytes_sent: float = 0.0
    bytes_recv: float = 0.0
    packets_sent: int = 0
    packets_recv: int = 0
    top_processes: List[ProcessInfo] = []
    command_results: List[CommandResultReport] = []


class MachineResponse(BaseModel):
    id: int
    agent_id: str
    hostname: str
    ip_address: Optional[str] = None
    logged_in_user: Optional[str] = "System"
    os_name: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    agent_version: str
    status: MachineStatus
    last_heartbeat: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
