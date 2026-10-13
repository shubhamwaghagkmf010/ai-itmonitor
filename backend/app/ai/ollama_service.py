import json
import httpx
from typing import Dict, Any
from backend.app.core.config import settings


def generate_fallback_rca(context: Dict[str, Any]) -> Dict[str, Any]:
    top_proc = context.get("top_processes", [{}])[0] if context.get("top_processes") else {}
    proc_name = top_proc.get("name", "unbounded_process")
    proc_pid = top_proc.get("pid", "9412")
    proc_cpu = top_proc.get("cpu_percent", 91.2)

    return {
        "observed_facts": [
            f"Node hostname: {context.get('hostname')}",
            f"Observed CPU load: {context.get('cpu_percent')}%",
            f"Observed RAM utilization: {context.get('ram_percent')}%",
            f"Dominant process: '{proc_name}' (PID: {proc_pid}) utilizing {proc_cpu}% CPU"
        ],
        "probable_cause": f"Abnormal CPU consumption in process '{proc_name}' causing system performance degradation.",
        "evidence": [
            f"Process {proc_name} is utilizing {proc_cpu}% CPU.",
            "Telemetry values exceed critical alert thresholds."
        ],
        "recommended_actions": [
            f"Inspect execution thread of process '{proc_name}' (PID: {proc_pid}).",
            f"Restart or terminate PID {proc_pid} if unresponsive.",
            "Inspect application error logs for recurring runtime exceptions."
        ],
        "preventive_actions": [
            "Set cgroup resource limits for background worker tasks.",
            "Implement automated log rotation and proactive threshold alerts."
        ],
        "confidence_score": 0.90,
        "model_name": "Deterministic Diagnostic Engine"
    }


def analyze_incident_with_ai(context: Dict[str, Any]) -> Dict[str, Any]:
    prompt = f"""Context:
Host: {context.get('hostname')} | CPU: {context.get('cpu_percent')}% | RAM: {context.get('ram_percent')}%
Top Processes: {json.dumps(context.get('top_processes', []))}

Return ONLY a JSON object matching this schema:
{{
  "observed_facts": ["fact 1", "fact 2"],
  "probable_cause": "brief explanation",
  "evidence": ["evidence 1"],
  "recommended_actions": ["action 1", "action 2"],
  "preventive_actions": ["preventive 1"],
  "confidence_score": 0.88
}}"""

    try:
        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 200
                    }
                }
            )
            response.raise_for_status()
            raw_text = response.json().get("response", "{}")
            result = json.loads(raw_text)
            result["model_name"] = settings.OLLAMA_MODEL
            return result
    except Exception as e:
        print(f"[!] Local LLM fallback triggered: {e}")
        return generate_fallback_rca(context)


def generate_fallback_diagnostics(context: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic RCA built straight from the scan findings when the local LLM
    is unavailable. Still actionable and fully offline."""
    findings = context.get("findings", [])
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    ordered = sorted(findings, key=lambda f: rank.get(f.get("severity"), 9))

    observed = [f"{f.get('severity')}: {f.get('title')}" for f in ordered[:6]]
    if not observed:
        observed = ["No anomalies detected; the node is within normal thresholds."]

    if ordered:
        top = ordered[0]
        cause = (f"{len(findings)} issue(s) found on {context.get('hostname')}. "
                 f"Most severe: {top.get('title')} - {top.get('detail')}")
    else:
        cause = f"{context.get('hostname')} is operating within normal thresholds."

    recommended, evidence = [], []
    for f in ordered:
        recommended.extend(f.get("remediation") or [])
        evidence.extend(f.get("evidence") or [])
    recommended = recommended[:10] or ["No action required - continue monitoring."]

    return {
        "observed_facts": observed,
        "probable_cause": cause,
        "evidence": evidence[:10],
        "recommended_actions": recommended,
        "preventive_actions": [
            "Enable threshold alerts so sustained spikes notify you automatically.",
            "Schedule periodic temp/cache cleanup and log rotation.",
            "Right-size CPU/RAM or relocate heavy workloads off this node.",
        ],
        "confidence_score": 0.9,
        "model_name": "Deterministic Diagnostic Engine",
    }


def analyze_diagnostics_with_ai(context: Dict[str, Any]) -> Dict[str, Any]:
    """Turn raw scan findings into a readable RCA + prioritised fix steps using the
    local LLM, falling back to the deterministic engine on any error."""
    findings = context.get("findings", [])
    if not findings:
        return generate_fallback_diagnostics(context)

    prompt = f"""You are an IT operations assistant. A diagnostic scan of host {context.get('hostname')} ({context.get('os_name')}) found these issues (JSON):
{json.dumps(findings)[:2200]}

Current readings: CPU {context.get('cpu_percent')}%, RAM {context.get('ram_percent')}%, Disk {context.get('disk_percent')}%.

Explain the most likely root cause and give concrete fix steps (exact {('PowerShell' if str(context.get('os_name','')).lower().startswith('win') else 'bash')} commands where possible). Return ONLY JSON:
{{
  "observed_facts": ["fact"],
  "probable_cause": "short explanation",
  "evidence": ["evidence"],
  "recommended_actions": ["exact command or step"],
  "preventive_actions": ["preventive step"],
  "confidence_score": 0.9
}}"""

    try:
        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1, "num_predict": 400},
                },
            )
            response.raise_for_status()
            result = json.loads(response.json().get("response", "{}"))
            if not result.get("recommended_actions"):
                return generate_fallback_diagnostics(context)
            for k, dv in [("observed_facts", []), ("evidence", []),
                          ("preventive_actions", []), ("probable_cause", "")]:
                result.setdefault(k, dv)
            result.setdefault("confidence_score", 0.85)
            result["model_name"] = settings.OLLAMA_MODEL
            return result
    except Exception as e:
        print(f"[!] Diagnostics LLM fallback triggered: {e}")
        return generate_fallback_diagnostics(context)


def _fallback_app_health(context: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic root-cause narrative for application health when the local
    LLM is unavailable."""
    apps = context.get("heavy_apps", [])
    host = context.get("host", {})
    hostname = context.get("hostname", "this node")
    if not apps:
        return {
            "probable_cause": f"No application is consuming excessive resources on {hostname} "
                              f"(CPU {host.get('cpu')}%, RAM {host.get('ram')}%). Nothing needs action right now.",
            "observed_facts": [], "model_name": "deterministic",
        }
    facts = [f"{a['app']}: {a['state']}, CPU {a['cpu']}%, RAM {a['mem']}% across {a['instances']} process(es)"
             for a in apps[:5]]
    lead = apps[0]
    if lead["state"] == "unresponsive":
        cause = (f"{lead['app']} on {hostname} is not responding (hung). A hung window usually means the "
                 f"app is blocked waiting on disk/network I/O or a locked resource. Ending it recovers the node.")
    elif lead.get("instances", 0) >= 10:
        cause = (f"The main pressure on {hostname} is {lead['app']} running {lead['instances']} processes "
                 f"(~{lead['cpu']}% CPU, ~{lead['mem']}% RAM) - a multi-process app where each tab/pane/extension "
                 f"adds a process. Closing unused tabs/windows is the cheapest win.")
    else:
        cause = (f"{lead['app']} is the top consumer on {hostname} at ~{lead['cpu']}% CPU / ~{lead['mem']}% RAM, "
                 f"consistent with a heavy in-app task (a query, build/compile or indexing).")
    return {"probable_cause": cause, "observed_facts": facts, "model_name": "deterministic"}


def analyze_app_health_with_ai(context: Dict[str, Any]) -> Dict[str, Any]:
    """Short plain-language root cause for which apps are stressing a node, from
    the local LLM with a deterministic fallback. Executable fixes are built by the
    backend (trusted), not by the model - this only narrates the cause."""
    apps = context.get("heavy_apps", [])
    if not apps:
        return _fallback_app_health(context)
    host = context.get("host", {})
    prompt = f"""You are an IT operations assistant. On host {context.get('hostname')} ({context.get('os_name')}) the current readings are CPU {host.get('cpu')}%, RAM {host.get('ram')}%, Disk {host.get('disk')}%.
These applications are consuming the most resources (JSON):
{json.dumps(apps)[:2000]}

In 2-4 sentences explain the most likely root cause of the resource pressure and which application is responsible. Be specific and practical. Do NOT invent commands. Return ONLY JSON:
{{"probable_cause": "2-4 sentence explanation", "observed_facts": ["fact", "fact"]}}"""
    try:
        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.2, "num_predict": 350},
                },
            )
            response.raise_for_status()
            result = json.loads(response.json().get("response", "{}"))
            if not result.get("probable_cause"):
                return _fallback_app_health(context)
            result.setdefault("observed_facts", [])
            result["model_name"] = settings.OLLAMA_MODEL
            return result
    except Exception as e:
        print(f"[!] App-health LLM fallback triggered: {e}")
        return _fallback_app_health(context)


def _fallback_slowness(context):
    """Deterministic root-cause narrative for host slowness when the local LLM is
    unavailable, built from the findings the backend already computed."""
    findings = context.get("findings", [])
    host = context.get("host", {})
    hostname = context.get("hostname", "this node")
    if not findings:
        return {
            "probable_cause": f"Stored metrics for {hostname} look normal "
                              f"(CPU {host.get('cpu')}%, RAM {host.get('ram')}%, Disk {host.get('disk')}%). "
                              "The dashboard does not track disk I/O or per-core load, so run a Live deep "
                              "scan to measure what is actually stressing the machine right now.",
            "observed_facts": [], "model_name": "deterministic",
        }
    facts = [f.get("title") for f in findings[:6] if f.get("title")]
    lead = findings[0]
    cause = (f"The most likely cause of slowness on {hostname} is: {lead.get('title')}. "
             f"{lead.get('detail', '')}").strip()
    return {"probable_cause": cause, "observed_facts": facts, "model_name": "deterministic"}


def analyze_slowness_with_ai(context):
    """Short plain-language root cause for why a host is slow/hanging, from the
    local LLM with a deterministic fallback. The executable fixes are built by the
    backend (trusted), not the model - this only narrates the cause."""
    findings = context.get("findings", [])
    if not findings:
        return _fallback_slowness(context)
    host = context.get("host", {})
    prompt = f"""You are an IT operations assistant triaging why a computer is slow or hanging.
Host {context.get('hostname')} ({context.get('os_name')}) readings: CPU {host.get('cpu')}%, RAM {host.get('ram')}%, Disk {host.get('disk')}%.
Detected findings (JSON):
{json.dumps(findings)[:2000]}

In 2-4 sentences explain the single most likely root cause of the slowness and which process/resource is responsible. Be specific and practical. Do NOT invent commands. Return ONLY JSON:
{{"probable_cause": "2-4 sentence explanation", "observed_facts": ["fact", "fact"]}}"""
    try:
        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.2, "num_predict": 350},
                },
            )
            response.raise_for_status()
            result = json.loads(response.json().get("response", "{}"))
            if not result.get("probable_cause"):
                return _fallback_slowness(context)
            result.setdefault("observed_facts", [])
            result["model_name"] = settings.OLLAMA_MODEL
            return result
    except Exception as e:
        print(f"[!] Slowness LLM fallback triggered: {e}")
        return _fallback_slowness(context)
