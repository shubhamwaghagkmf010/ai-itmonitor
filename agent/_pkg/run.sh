#!/usr/bin/env bash
cd "$(dirname "$0")"
export SERVER_URL="${SERVER_URL:-__SERVER_URL__}"
export INVENTORY_INTERVAL="${INVENTORY_INTERVAL:-1800}"
export PYTHONPATH="$(pwd)"
python3 -m pip install --quiet --user httpx psutil 2>/dev/null || true
exec python3 agent/main.py
