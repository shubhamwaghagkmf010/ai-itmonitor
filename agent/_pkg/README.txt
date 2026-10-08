AI-ITMonitor Agent
==================

This agent reports telemetry (CPU, RAM, disk, processes, inventory) to your
AI-ITMonitor server. The server URL is already set inside the run scripts.

WINDOWS
  1) Install Python 3 from python.org and tick "Add Python to PATH".
  2) Double-click run.bat

LINUX
  Quick test:            bash run.sh
  Install as a service:  sudo bash install-ubuntu.sh
     (auto-starts on boot; view logs with: journalctl -u ai-itmonitor-agent -f)
