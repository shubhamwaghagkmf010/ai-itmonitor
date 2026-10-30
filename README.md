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
python3 scripts/init_env.py --with-agent-key   # creates backend/.env (mode 600) with a real SECRET_KEY and AGENT_API_KEY
# then set POSTGRES_PASSWORD in backend/.env, and give every agent the same AGENT_API_KEY
docker compose up --build
```

Dashboard: <http://localhost:5173> · API docs: <http://localhost:8000/docs>

## Running from source

```bash
# Backend (Python 3.12, PostgreSQL and Ollama running)
python3 -m venv venv && source venv/bin/activate
pip install -r backend/requirements.txt
python3 scripts/init_env.py                # creates backend/.env with a real SECRET_KEY; then edit the rest
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
| `ENVIRONMENT` | `development` (default) prints warnings about weak settings; `production` refuses to start with them. |
| `SECRET_KEY` | JWT signing key, at least 32 random characters (`scripts/init_env.py` makes one). A placeholder or short key stops the server from starting; if empty, a temporary key is generated and every session ends on restart. |
| `POSTGRES_*` | Database connection. A default or well-known password is flagged (an error in production). |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Local LLM endpoint and model. |
| `CORS_ORIGINS` | Allowed browser origins. |
| `AGENT_API_KEY` | Shared key agents must send to enroll and report. While it is empty anyone who can reach the API can enrol an agent; required in production. |

The file is read from `backend/.env` next to the code, wherever the server is started from, and a warning is
printed if other users on the machine can read it.

## Tests

```bash
pip install -r backend/requirements-dev.txt
pytest
```

## Security

- Passwords are bcrypt-hashed; sessions are JWT.
- Agent enrollment and metric ingestion can require a shared key (`AGENT_API_KEY`).
- Remote actions and process control are gated by role permissions and audited.
- Put the API behind TLS and never expose it directly to an untrusted network.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[Apache License 2.0](LICENSE).
