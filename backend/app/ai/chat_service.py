import json
import httpx
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.models.entities import Machine, Incident, AIAnalysis


def query_ai_assistant(user_prompt: str, db: Session) -> str:
    """
    Advanced AI IT Operations Assistant with dual capability:
    1. Real-time Infrastructure Observability & DB telemetry queries.
    2. Interactive Problem Solving, Command Reference & Remediation Playbooks (ChatGPT / Gemini style).
    """
    machines = db.query(Machine).all()
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()

    machine_summary = [
        {"host": m.hostname, "os": m.os_name, "status": m.status.value, "ip": m.ip_address}
        for m in machines
    ]

    incident_summary = []
    for inc in incidents:
        rca = db.query(AIAnalysis).filter(AIAnalysis.incident_id == inc.id).first()
        incident_summary.append({
            "code": inc.incident_code,
            "host": inc.machine.hostname if inc.machine else "N/A",
            "title": inc.title,
            "severity": inc.severity.value,
            "status": inc.status.value,
            "resolution": inc.resolution_notes or "Unresolved",
            "rca": rca.probable_cause if rca else "Pending"
        })

    system_prompt = f"""You are an expert Senior Site Reliability Engineer (SRE) and AI IT Operations Assistant (AI-ITMonitor).

LIVE INFRASTRUCTURE STATE:
Nodes: {json.dumps(machine_summary)}
Recent Incidents: {json.dumps(incident_summary)}

INSTRUCTIONS:
1. If the user asks about monitored machines or incidents, answer accurately using the LIVE INFRASTRUCTURE STATE.
2. If the user asks how to solve, troubleshoot, or fix a technical problem (such as high CPU, memory leaks, disk cleanup, hanging processes, or network issues), provide actionable, step-by-step technical instructions with exact Windows PowerShell or Linux terminal commands.
3. Be clear, concise, and professional like ChatGPT/Gemini."""

    try:
        with httpx.Client(timeout=120.0) as client:
            res = client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": f"{system_prompt}\n\nUser: {user_prompt}\nAssistant:",
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 250
                    }
                }
            )
            res.raise_for_status()
            return res.json().get("response", "No response received from local AI engine.").strip()
    except Exception as e:
        # Intelligent fallback for troubleshooting questions if LLM is offline
        p_lower = user_prompt.lower()
        if "cpu" in p_lower or "load" in p_lower:
            return "🔧 High CPU Troubleshooting: 1) Identify top thread: Run `top -b -n 1` (Linux) or `Get-Process | Sort-Object CPU -Descending | Select -First 5` (Windows). 2) Check process logs for deadlock. 3) Terminate runaway process using 'End Process Tree' in Dashboard."
        elif "disk" in p_lower or "space" in p_lower:
            return "🧹 Disk Cleanup: 1) Check directory sizes: `df -h` and `du -sh /var/log/*` (Linux) or `cleanmgr.exe` / `Get-PSDrive` (Windows). 2) Rotate logs: `journalctl --vacuum-size=500M`. 3) Remove temp files."
        elif "memory" in p_lower or "ram" in p_lower:
            return "🧠 High RAM/Memory Leak Troubleshooting: 1) Check swap/pagefile: `free -m` (Linux). 2) Profile application garbage collection. 3) Restart service via `systemctl restart <service>`."
        else:
            return f"Infrastructure Overview: {len(machines)} monitored nodes ({len([m for m in machines if m.status.value != 'HEALTHY'])} unhealthy). Open Incidents: {len([i for i in incidents if i.status.value == 'OPEN'])}."
