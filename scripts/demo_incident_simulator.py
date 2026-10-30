"""Streams a normal sample and then a runaway one for a fake machine, so the dashboard has something to show.

    AGENT_API_KEY=...  python scripts/demo_incident_simulator.py

To have the script check that an incident really appeared, also set DEMO_EMAIL and DEMO_PASSWORD (a
dashboard login that may view incidents). Without them it only reports what the server answered, and
you check the dashboard yourself."""
import os
import sys
import time

import httpx

SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:8000/api/v1/agents")
API_URL = SERVER_URL.rsplit("/agents", 1)[0]
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
SAMPLES_TO_SEND = 4  # the server wants several high samples in a row before it calls it an incident


def sample(cpu, ram, procs):
    return {
        "cpu_percent": cpu, "ram_percent": ram, "ram_used_gb": round(8.0 * ram / 100, 2), "ram_total_gb": 8.0,
        "disk_percent": 45.0, "disk_used_gb": 45.0, "disk_total_gb": 100.0, "top_processes": procs,
    }


def trigger_demo() -> int:
    headers = {"X-Agent-Token-Support": "1"}
    if AGENT_API_KEY:
        headers["X-Agent-Key"] = AGENT_API_KEY

    with httpx.Client(headers=headers, timeout=15.0) as client:
        res = client.post(f"{SERVER_URL}/register", json={
            "hostname": "PROD-APP-02", "os_name": "Ubuntu Linux", "os_version": "24.04 LTS",
            "architecture": "x86_64", "ip_address": "192.168.1.150", "machine_uid": "demo00000002"})
        if res.status_code != 200:
            print(f"[x] Registration failed: HTTP {res.status_code} {res.text[:200]}")
            return 1
        data = res.json()
        agent_id = data["agent_id"]
        if data.get("agent_token"):
            client.headers["X-Agent-Token"] = data["agent_token"]
        print(f"[+] Node registered: PROD-APP-02 (Agent ID: {agent_id})")

        print("[*] Streaming a normal baseline sample (CPU 22%)...")
        res = client.post(f"{SERVER_URL}/metrics", json={"agent_id": agent_id, **sample(22.4, 38.1, [
            {"pid": 1102, "name": "nginx", "cpu_percent": 2.1, "memory_percent": 1.5, "status": "running"}])})
        if res.status_code != 200:
            print(f"[x] Baseline sample refused: HTTP {res.status_code} {res.text[:200]}")
            return 1

        print(f"[!] Streaming {SAMPLES_TO_SEND} runaway samples (CPU 96.8%)...")
        for _ in range(SAMPLES_TO_SEND):
            time.sleep(1)
            res = client.post(f"{SERVER_URL}/metrics", json={"agent_id": agent_id, **sample(96.8, 88.5, [
                {"pid": 9412, "name": "demo_runaway_worker", "cpu_percent": 91.2, "memory_percent": 64.0, "status": "running"}])})
            if res.status_code != 200:
                print(f"[x] Sample refused: HTTP {res.status_code} {res.text[:200]}")
                return 1
        print(f"[+] Server accepted the samples; machine status is now {res.json().get('machine_status')}.")

        email, password = os.getenv("DEMO_EMAIL"), os.getenv("DEMO_PASSWORD")
        if not (email and password):
            print("[i] Not verified: set DEMO_EMAIL and DEMO_PASSWORD to have this script look for the incident.")
            return 0
        login = client.post(f"{API_URL}/auth/login", data={"username": email, "password": password})
        if login.status_code != 200:
            print(f"[x] Could not log in to check: HTTP {login.status_code}")
            return 1
        token = login.json()["access_token"]
        incidents = client.get(f"{API_URL}/incidents/", headers={"Authorization": f"Bearer {token}"})
        found = [i for i in incidents.json() if i.get("machine_hostname") == "PROD-APP-02" and i.get("status") != "CLOSED"]
        if found:
            print(f"[SUCCESS] {len(found)} incident(s) exist for PROD-APP-02, e.g. {found[0]['incident_code']}: {found[0]['title']}")
            return 0
        print("[x] No incident was raised for PROD-APP-02.")
        return 1


if __name__ == "__main__":
    sys.exit(trigger_demo())
