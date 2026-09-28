#!/bin/bash
# AI-ITMonitor launcher (works copy under /home/claude)
A=/home/claude/AI-ITMonitor
echo "[*] Stopping any existing instances..."
pkill -9 -f uvicorn 2>/dev/null
pkill -9 -f "agent/main.py" 2>/dev/null
pkill -9 -f vite 2>/dev/null
sleep 2

cd "$A"
source venv/bin/activate

echo "[*] Starting FastAPI Backend (Port 8000)..."
PYTHONPATH=. nohup uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 > backend.log 2>&1 &

echo "[*] Starting Monitoring Agent..."
PYTHONPATH=. nohup python3 agent/main.py > agent.log 2>&1 &

echo "[*] Starting React Frontend (Port 5173)..."
cd "$A/frontend"
nohup npm run dev -- --host 0.0.0.0 > frontend.log 2>&1 &

sleep 6
IP=$(hostname -I | awk '{print $1}')
echo ""
echo "=================================================="
echo "   AI-ITMonitor is UP"
echo "   Dashboard: http://$IP:5173"
echo "   Backend:   http://$IP:8000/docs"
echo "=================================================="
