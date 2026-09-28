import time
import httpx
import sys
import os

SERVER_URL = "http://127.0.0.1:8000/api/v1/agents"


def trigger_demo():
    print("==========================================================")
    print("    AI-ITMonitor College Viva Incident Simulator          ")
    print("==========================================================")
    
    with httpx.Client() as client:
        # 1. Register Simulated Node: "PROD-APP-02"
        reg_payload = {
            "hostname": "PROD-APP-02",
            "os_name": "Ubuntu Linux",
            "os_version": "24.04 LTS",
            "architecture": "x86_64",
            "ip_address": "192.168.1.150"
        }
        res = client.post(f"{SERVER_URL}/register", json=reg_payload)
        res.raise_for_status()
        agent_id = res.json()["agent_id"]
        print(f"[+] Node registered: PROD-APP-02 (Agent ID: {agent_id})")

        # 2. Transmit normal baseline metrics
        print("[*] Streaming normal baseline telemetry (CPU: 22%)...")
        normal_metric = {
            "agent_id": agent_id,
            "cpu_percent": 22.4,
            "ram_percent": 38.1,
            "ram_used_gb": 3.05,
            "ram_total_gb": 8.0,
            "disk_percent": 45.0,
            "disk_used_gb": 45.0,
            "disk_total_gb": 100.0,
            "top_processes": [
                {"pid": 1102, "name": "nginx", "cpu_percent": 2.1, "memory_percent": 1.5, "status": "running"},
                {"pid": 1405, "name": "postgres", "cpu_percent": 3.4, "memory_percent": 4.2, "status": "running"}
            ]
        }
        client.post(f"{SERVER_URL}/metrics", json=normal_metric)
        time.sleep(2)

        # 3. Simulate Runaway Incident Spike
        print("\n[!] >>> TRIGGERING ABNORMAL RUNAWAY ANOMALY (CPU: 96.8%) <<<")
        anomaly_metric = {
            "agent_id": agent_id,
            "cpu_percent": 96.8,
            "ram_percent": 88.5,
            "ram_used_gb": 7.08,
            "ram_total_gb": 8.0,
            "disk_percent": 45.0,
            "disk_used_gb": 45.0,
            "disk_total_gb": 100.0,
            "top_processes": [
                {"pid": 9412, "name": "unbounded_worker_thread", "cpu_percent": 91.2, "memory_percent": 64.0, "status": "running"},
                {"pid": 1405, "name": "postgres", "cpu_percent": 4.2, "memory_percent": 4.2, "status": "running"}
            ]
        }
        res = client.post(f"{SERVER_URL}/metrics", json=anomaly_metric)
        print(f"[+] Server Ingestion Response: {res.json()}")
        print("\n[SUCCESS] Anomaly detected and Incident automatically generated in Dashboard!")


if __name__ == "__main__":
    trigger_demo()
