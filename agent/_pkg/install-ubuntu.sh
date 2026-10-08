#!/usr/bin/env bash
# Install the AI-ITMonitor agent as a systemd service (run with: sudo bash install-ubuntu.sh)
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_URL="${SERVER_URL:-__SERVER_URL__}"
python3 -m pip install --quiet httpx psutil 2>/dev/null || pip3 install --quiet httpx psutil || true
cat >/etc/systemd/system/ai-itmonitor-agent.service <<UNIT
[Unit]
Description=AI-ITMonitor Agent
After=network-online.target

[Service]
Environment=SERVER_URL=$SERVER_URL
Environment=PYTHONPATH=$DIR
ExecStart=/usr/bin/python3 $DIR/agent/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now ai-itmonitor-agent
echo "Installed and started. Logs: journalctl -u ai-itmonitor-agent -f"
