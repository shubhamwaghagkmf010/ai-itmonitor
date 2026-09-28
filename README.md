# AI-ITMonitor

Self-hosted IT infrastructure monitoring with an AI assistant. Install a lightweight agent
on each machine, watch live health on a web dashboard, and let a local LLM explain incidents
and answer operational questions — all on your own network, no cloud, no data leaving your
infrastructure.

> **Status: beta.** Actively developed; the API may still change. Review the security notes
> before exposing it beyond a trusted network.

## What it does

- **Live monitoring** — CPU, RAM, disk, network and per-process telemetry from every agent,
  refreshed continuously.
- **AI root-cause analysis** — an incident is analysed by a local LLM (via Ollama) into
  observed facts, probable cause, and recommended and preventive actions, with a deterministic
  fallback when no model is available.
- **AI operations assistant** — an SRE-style chat that knows your live fleet and recent
  incidents and helps you troubleshoot.
- **Anomaly detection** — z-score based flagging of CPU/RAM/disk spikes against each machine's
  own history.
- **Remote operations** — kill a runaway process or run an approved remote action, gated by
  role-based permissions.
- **Wake-on-LAN** — power machines on with magic packets, including a relay-assisted path for
  cross-subnet wake.
- **Role-based access** — Admin / Manager / Operator / Viewer, with granular permissions and
  per-role dashboard widgets.
- **Audit trail** — every sensitive action is recorded with actor, target, result and IP.
- **PDF incident reports** — export an incident with its AI analysis.

## Architecture

```
  Agents (Python / Go)  ──telemetry──►  FastAPI backend  ──►  PostgreSQL
        on each host                         :8000                metrics, incidents, users
                                               │
                                     Ollama (local LLM)     React dashboard (:5173)
                                        RCA + chat
```

| Component | Stack |
| --- | --- |
| Backend | FastAPI, SQLAlchemy, Alembic, PostgreSQL, JWT auth |
| Frontend | React (Vite, Tailwind) |
| Agents | Python (psutil) and a Go agent for Windows |
| AI | Ollama (local, e.g. llama3.2) |

## Quick start (Docker)

```bash
git clone <your-repo-url> ai-itmonitor
cd ai-itmonitor
cp backend/.env.example backend/.env      # set SECRET_KEY, DB and AGENT_API_KEY
docker compose up --build
```

Dashboard: <http://localhost:5173> · API docs: <http://localhost:8000/docs>

## Running from source

```bash
# Backend (Python 3.12, PostgreSQL and Ollama running)
python3 -m venv venv && source venv/bin/activate
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env       # then edit it
alembic upgrade head
PYTHONPATH=. uvicorn backend.app.main:app --host 0.0.0.0 --port 8000

# Frontend (Node 20)
cd frontend && npm install && npm run dev -- --host 0.0.0.0

# Agent (on any machine to be monitored)
PYTHONPATH=. python3 agent/main.py
```

## Configuration

All settings live in `backend/.env` (see `backend/.env.example`).

| Setting | Purpose |
| --- | --- |
| `SECRET_KEY` | JWT signing key. Required for stable sessions; a temporary one is generated if unset. |
| `POSTGRES_*` | Database connection. |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Local LLM endpoint and model. |
| `CORS_ORIGINS` | Allowed browser origins. |
| `AGENT_API_KEY` | Shared key agents must send to enroll and report. Leave empty only on a trusted network. |

## Security

- Passwords are bcrypt-hashed; sessions are JWT.
- Agent enrollment and metric ingestion can require a shared key (`AGENT_API_KEY`).
- Remote actions and process control are gated by role permissions and audited.
- Put the API behind TLS and never expose it directly to an untrusted network.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[Apache License 2.0](LICENSE).
