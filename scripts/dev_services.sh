#!/usr/bin/env bash
# Starts, stops and reports on the development processes: the API, a local monitoring agent and the Vite dev
# server. For a real deployment use docker compose, or deploy/systemd/.
#
#     scripts/dev_services.sh start | stop | status | restart
#
# Each service gets its own process group and a pid file in run/, and stopping sends SIGTERM to exactly those
# processes. It never matches on process names, so it cannot touch another uvicorn, agent or Vite that is running
# on the same machine (the old launcher ran `pkill -9 -f uvicorn`). A pid file is only trusted if the process
# it names still looks like the service, which guards against a recycled pid.
#
# Settings (environment): HOST (default 127.0.0.1; use 0.0.0.0 to reach it from other machines), BACKEND_PORT,
# FRONTEND_PORT, WITH_AGENT=0 to skip the local agent, VENV (default ./venv), AIM_RUN_DIR, AIM_LOG_DIR.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${AIM_RUN_DIR:-$ROOT/run}"
LOG_DIR="${AIM_LOG_DIR:-$ROOT/logs}"
VENV="${VENV:-$ROOT/venv}"
ENV_FILE="${AIM_ENV_FILE:-$ROOT/backend/.env}"
HOST="${HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
WITH_AGENT="${WITH_AGENT:-1}"
STOP_WAIT="${STOP_WAIT:-10}"      # seconds to wait for a clean exit before SIGKILL

# name -> text its command line must contain
marker() {
    case "$1" in
        backend) echo "uvicorn" ;;
        agent) echo "agent/main.py" ;;
        frontend) echo "npm" ;;
    esac
}

pid_of() { cat "$RUN_DIR/$1.pid" 2>/dev/null; }

# Is the process in the pid file alive and still the thing we started?
is_ours() {
    local name="$1" pid
    pid="$(pid_of "$name")"
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qF -- "$(marker "$name")"
}

start_one() {
    local name="$1"; shift
    if is_ours "$name"; then
        echo "[=] $name already running (pid $(pid_of "$name"))"
        return 0
    fi
    rm -f "$RUN_DIR/$name.pid"
    mkdir -p "$RUN_DIR" "$LOG_DIR"
    # setsid gives the service its own process group; the shell writes its own pid and then becomes the service,
    # so the pid file holds the pid of the real process (and, being the group leader, of its whole group).
    setsid bash -c 'echo $$ > "$0"; exec "${@:1}"' "$RUN_DIR/$name.pid" "$@" >> "$LOG_DIR/$name.log" 2>&1 < /dev/null &
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [ -s "$RUN_DIR/$name.pid" ] && break
        sleep 0.1
    done
    sleep 0.3
    if is_ours "$name"; then
        echo "[+] $name started (pid $(pid_of "$name"), log $LOG_DIR/$name.log)"
    else
        echo "[x] $name did not stay up; see $LOG_DIR/$name.log" >&2
        rm -f "$RUN_DIR/$name.pid"
        return 1
    fi
}

stop_one() {
    local name="$1" pid i
    pid="$(pid_of "$name")"
    if [ -z "$pid" ]; then
        echo "[-] $name is not running"
        return 0
    fi
    if ! is_ours "$name"; then
        echo "[!] $name: pid $pid is not the $name process any more (stale pid file); leaving that process alone"
        rm -f "$RUN_DIR/$name.pid"
        return 0
    fi
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for ((i = 0; i < STOP_WAIT * 10; i++)); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "[!] $name ignored SIGTERM for ${STOP_WAIT}s; sending SIGKILL"
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
    fi
    rm -f "$RUN_DIR/$name.pid"
    echo "[+] $name stopped"
}

status_one() {
    if is_ours "$1"; then
        echo "$1: running (pid $(pid_of "$1"))"
    else
        echo "$1: stopped"
        return 3
    fi
}

cmd_start() {
    if [ ! -x "$VENV/bin/uvicorn" ]; then
        echo "No virtual environment at $VENV (expected $VENV/bin/uvicorn)." >&2
        echo "Create one: python3 -m venv venv && venv/bin/pip install -r backend/requirements.txt" >&2
        return 1
    fi
    if [ ! -f "$ENV_FILE" ]; then
        echo "$ENV_FILE is missing. Create it with: python3 scripts/init_env.py" >&2
        return 1
    fi
    cd "$ROOT" || return 1
    export PYTHONPATH="$ROOT"
    local rc=0
    start_one backend "$VENV/bin/uvicorn" backend.app.main:app --host "$HOST" --port "$BACKEND_PORT" || rc=1
    if [ "$WITH_AGENT" = "1" ]; then
        start_one agent "$VENV/bin/python" agent/main.py || rc=1
    fi
    if [ -d "$ROOT/frontend/node_modules" ]; then
        (cd "$ROOT/frontend" && start_one frontend npm run dev -- --host "$HOST" --port "$FRONTEND_PORT") || rc=1
    else
        echo "[-] frontend skipped: run 'npm install' in frontend/ first"
    fi
    echo
    echo "API:       http://$HOST:$BACKEND_PORT/docs"
    echo "Dashboard: http://$HOST:$FRONTEND_PORT"
    return $rc
}

cmd_stop() {
    local name
    for name in frontend agent backend; do
        stop_one "$name"
    done
}

cmd_status() {
    local rc=0 name
    for name in backend agent frontend; do
        status_one "$name" || rc=3
    done
    return $rc
}

case "${1:-}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_stop; cmd_start ;;
    status) cmd_status ;;
    *) echo "usage: $0 start|stop|restart|status" >&2; exit 2 ;;
esac
