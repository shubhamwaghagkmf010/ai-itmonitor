@echo off
title AI-ITMonitor Agent
set SERVER_URL=__SERVER_URL__
set INVENTORY_INTERVAL=1800
set PYTHONPATH=%~dp0
python -m pip install --quiet --user httpx psutil
python "%~dp0agent/main.py"
pause
