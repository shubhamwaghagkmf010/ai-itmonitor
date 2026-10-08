import json
import httpx
from typing import Optional
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.models.entities import Machine, Incident, AIAnalysis


def _fallback(user_prompt: str, machines, incidents) -> str:
    """Offline helper used when the local LLM is unreachable. Commands are wrapped
    in fenced code blocks so the UI renders a copy button."""
    p = user_prompt.lower()
    if "cpu" in p or "load" in p:
        return ("**High CPU - quick triage**\n"
                "1. Find the top consumers:\n"
                "```powershell\nGet-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name,Id,CPU\n```\n"
                "```bash\nps -eo pid,comm,%cpu --sort=-%cpu | head -5\n```\n"
                "2. Inspect or stop the runaway process (confirm first), or use the Remote Console / Diagnostic Scan.")
    if "disk" in p or "space" in p or "storage" in p:
        return ("**Free up disk space**\n"
                "1. See what is using space:\n"
                "```powershell\nGet-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object FullName,@{n='MB';e={[int]($_.Length/1MB)}} -First 20\n```\n"
                "```bash\ndu -xh / 2>/dev/null | sort -rh | head -20\n```\n"
                "2. Clear temp / rotate logs:\n"
                "```bash\nsudo journalctl --vacuum-time=3d\n```")
    if "memory" in p or "ram" in p:
        return ("**High memory / leak triage**\n"
                "```bash\nps -eo pid,comm,%mem --sort=-%mem | head -5\n```\n"
                "Restart the offending service once identified:\n"
                "```bash\nsudo systemctl restart <service>\n```")
    unhealthy = len([m for m in machines if m.status.value != 'HEALTHY'])
    open_inc = len([i for i in incidents if i.status.value == 'OPEN'])
    return (f"**Fleet overview**\n- Monitored nodes: {len(machines)} ({unhealthy} not healthy)\n"
            f"- Open incidents: {open_inc}\n\n"
            "Ask me about a specific host, high CPU/RAM/disk, or how to fix an incident. "
            "(Local AI engine is offline right now, so this is a summarised answer.)")


def query_ai_assistant(user_prompt: str, db: Session, machine_context: Optional[dict] = None) -> str:
    """AI SRE Copilot: answers grounded in this environment's live telemetry, and
    returns ChatGPT-style formatted guidance with fenced, copyable commands."""
    machines = db.query(Machine).all()
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()

    machine_summary = [
        {"host": m.hostname, "os": m.os_name, "status": m.status.value,
         "ip": m.ip_address, "user": m.logged_in_user}
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
            "rca": rca.probable_cause if rca else "Pending",
        })

    focused = f"\nCurrently viewed node: {json.dumps(machine_context)}" if machine_context else ""

    system_prompt = f"""You are the AI Diagnostic SRE Copilot built into AI-ITMonitor. You have DIRECT ACCESS to this environment's live monitoring data below - treat it as ground truth.

LIVE INFRASTRUCTURE STATE
Monitored nodes ({len(machines)}): {json.dumps(machine_summary)}
Recent incidents: {json.dumps(incident_summary)}{focused}

HOW TO ANSWER
- For questions about the monitored machines, incidents, logged-in users, CPU/RAM/disk or status, answer from the LIVE INFRASTRUCTURE STATE above - name the host and give the numbers. If it is not in the data, say you do not have that data yet.
- For "how do I fix/troubleshoot" questions, give short numbered steps.
- ALWAYS put any terminal command inside a fenced code block tagged with its shell, for example:
```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
```
```bash
df -h
```
- Be concise and practical; prefer the exact commands over long prose."""

    try:
        with httpx.Client(timeout=120.0) as client:
            res = client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": f"{system_prompt}\n\nUser: {user_prompt}\nAssistant:",
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 512},
                },
            )
            res.raise_for_status()
            reply = res.json().get("response", "").strip()
            return reply or _fallback(user_prompt, machines, incidents)
    except Exception as e:
        print(f"[!] Chat LLM fallback triggered: {e}")
        return _fallback(user_prompt, machines, incidents)
