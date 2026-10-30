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
| `TRUSTED_PROXIES` | JSON list of proxy addresses/CIDRs (default loopback) whose `X-Forwarded-For` is believed, e.g. `["172.18.0.0/16"]` for the nginx container. Anyone else's header is ignored. Needed for the self-service page to see real client addresses behind a proxy. |
| `SCAN_MAX_HOSTS` | Largest range one network scan may cover (default 1024). Larger ranges are refused, not truncated. |
| `SCAN_ALLOW_PUBLIC` | `false` (default) restricts scans to private (RFC 1918) addresses; loopback, link-local and multicast are never scanned. |
| `REQUIRE_AGENT_TOKEN` | `false` (default) still accepts older agents and the Go agent, which have no per-agent token. Set `true` once every agent is upgraded. |

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
- Each enrolled agent also gets its own token (stored hashed). With it, knowing a machine's `agent_id`
  (derived from its hostname and MAC) is not enough to report as it, collect its commands or answer for
  them; a command result is only accepted from the machine the command was queued for.
- What the server tells an agent to do is signed. Commands, agent updates and the HTTPS address the agent
  should move to carry an HMAC made with `AGENT_API_KEY`; the agent refuses anything that does not verify, so
  someone on the network path cannot add a shell command to a response or swap in a different update.
  Updates must also be newer than the running version, are unpacked only into the agent folder, and never
  overwrite `agent_config.json`. Without an `AGENT_API_KEY` an agent only updates over verified HTTPS.
- An agent follows an HTTPS address for the same host it already talks to; a different host needs the
  server's signature (or `AGENT_ALLOWED_HOSTS=host1,host2` on the agent).
- Downloading the agent needs a signed-in user with `agents.manage` (or the agent key, used for self-update),
  is audited, and the bundle never includes `agent_config.json`, `.env` or key files.
- The asset register, network scans and the AI assistant have their own permissions: `assets.view`
  (look; licence keys are masked), `assets.manage` (change, sync, export), `network.manage` (scan and
  manage saved ranges) and `ai_chat.use`. Changes to the register, scans and exports are audited.
- Scans only cover private address ranges up to `SCAN_MAX_HOSTS`, one at a time.
- The no-login `/self-service` page recognises a computer by its address, so it can only be used from inside
  the network, only changes the four owner fields of a computer the monitor already knows, is rate limited
  and audited, and never creates records for unknown addresses.
- CSV exports prefix cells that start with `=`, `+`, `-` or `@` so they open as text, not formulas.
- Remote actions are limited to a fixed list (shell, kill, reboot, diagnose, service control), validated on
  the server, expire after 5 minutes if the machine does not collect them, and can be cancelled.
- Remote actions, process kills, MAC changes, deleting machines and pushing updates are recorded in the audit
  trail with who, what, which machine and the connection address. Deleting machines, changing a MAC and
  pushing updates need the `agents.manage` permission (separate from `wol.manage`).
- Put the API behind TLS and never expose it directly to an untrusted network.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[Apache License 2.0](LICENSE).
