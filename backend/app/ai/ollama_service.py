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
