#!/bin/bash
echo "[*] Stopping AI-ITMonitor services..."
pkill -9 -f uvicorn 2>/dev/null
pkill -9 -f "agent/main.py" 2>/dev/null
pkill -9 -f vite 2>/dev/null
echo "[+] All services stopped."
