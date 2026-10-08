@echo off
title AI-ITMonitor Agent
net session >nul 2>&1
if %errorLevel% neq 0 (
  echo [*] Requesting administrator privileges ^(needed for service control / reboot^)...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set SERVER_URL=__SERVER_URL__
set INVENTORY_INTERVAL=1800
set PYTHONPATH=%~dp0
python -m pip install --quiet --user httpx psutil
python "%~dp0agent/main.py"
pause
