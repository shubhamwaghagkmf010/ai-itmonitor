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


def _build_chat_context(db: Session, machine_context: Optional[dict] = None):
    """Shared grounding data + system prompt for both the one-shot and the
    streaming chat path, so they never drift apart.

    The prompt is built as compact plain text, not JSON - on this CPU-only
    deployment, PROMPT PREFILL (not generation) turned out to be the dominant
    cost (~11 tok/s observed vs ~6 tok/s generation): a verbose JSON dump of
    the fleet pushed the prompt past 900 tokens, most of it punctuation
    (braces/quotes/field names) carrying no extra information. Plain
    "key: value" lines say the same thing in roughly half the tokens."""
    machines = db.query(Machine).all()
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(3).all()

    machine_lines = "\n".join(
        f"- {m.hostname} | {m.os_name} | {m.status.value} | {m.ip_address or 'no-ip'} | user:{m.logged_in_user or 'none'}"
        for m in machines[:20]
    ) or "(none registered yet)"

    incident_lines = []
    for inc in incidents:
        rca = db.query(AIAnalysis).filter(AIAnalysis.incident_id == inc.id).first()
        rca_text = (rca.probable_cause[:140] if rca and rca.probable_cause else "pending")
        host = inc.machine.hostname if inc.machine else "N/A"
        incident_lines.append(
            f"- {inc.incident_code} [{host}] {inc.severity.value}/{inc.status.value}: {inc.title} - {rca_text}")
    incident_block = "\n".join(incident_lines) or "(none)"

    focused = ""
    if machine_context:
        focused = "\nCurrently viewed node: " + ", ".join(
            f"{k}={v}" for k, v in machine_context.items())

    system_prompt = f"""You are the AI SRE Copilot built into AI-ITMonitor. The data below is live - treat it as ground truth.

NODES ({len(machines)}):
{machine_lines}

RECENT INCIDENTS:
{incident_block}{focused}

Answer questions about these nodes/incidents using the data above - name the host and give the numbers; say you don't have it if it's missing. For "how do I fix" questions give short numbered steps. Keep answers to 3-5 sentences/bullets - this is a small local model, brevity keeps it fast. Put any terminal command in a fenced code block with its shell, e.g.:
```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
```"""
    return system_prompt, machines, incidents


def query_ai_assistant(user_prompt: str, db: Session, machine_context: Optional[dict] = None) -> str:
    """Non-streaming variant, kept for any caller that needs one plain string."""
    system_prompt, machines, incidents = _build_chat_context(db, machine_context)
    try:
        with httpx.Client(timeout=120.0) as client:
            res = client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": f"{system_prompt}\n\nUser: {user_prompt}\nAssistant:",
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 320},
                },
            )
            res.raise_for_status()
            reply = res.json().get("response", "").strip()
            return reply or _fallback(user_prompt, machines, incidents)
    except Exception as e:
        print(f"[!] Chat LLM fallback triggered: {e}")
        return _fallback(user_prompt, machines, incidents)


def stream_ai_assistant(user_prompt: str, db: Session, machine_context: Optional[dict] = None):
    """AI SRE Copilot, streamed token-by-token as the local model generates them -
    the reply starts appearing in ~1-2s instead of waiting for the whole answer,
    which is what actually made the chat feel slow on this CPU-only deployment
    (the model itself is already the smallest practical size). Falls back to one
    complete message if the local engine is unreachable."""
    system_prompt, machines, incidents = _build_chat_context(db, machine_context)
    try:
        with httpx.Client(timeout=120.0) as client:
            with client.stream(
                "POST",
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": f"{system_prompt}\n\nUser: {user_prompt}\nAssistant:",
                    "stream": True,
                    "options": {"temperature": 0.3, "num_predict": 320},
                },
            ) as res:
                res.raise_for_status()
                got_any = False
                for line in res.iter_lines():
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    chunk = obj.get("response", "")
                    if chunk:
                        got_any = True
                        yield chunk
                    if obj.get("done"):
                        break
                if not got_any:
                    yield _fallback(user_prompt, machines, incidents)
    except Exception as e:
        print(f"[!] Chat LLM stream fallback triggered: {e}")
        yield _fallback(user_prompt, machines, incidents)
