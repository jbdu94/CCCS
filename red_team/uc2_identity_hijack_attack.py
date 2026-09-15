"""
UC2 — Autonomous Identity Hijacking (red team)

Runs against the LIVE target service. The target already enforces basic
scope checks (a credential can't be used outside its granted scope — that
part gets blocked and is not the interesting case). The real test is
whether a VALID, IN-SCOPE credential gets used in an anomalous pattern
that only behavioral detection — not static authz — would catch:
high request velocity from multiple source IPs in a short window
(the "impossible travel" pattern of a stolen credential being replayed).
"""
import argparse
import time
import requests

AGENT_ID = "reporting_agent"
GRANTED_SCOPE = ["reporting_db_readonly"]

ANOMALOUS_IPS = ["10.10.1.4", "198.51.100.23", "203.0.113.77", "45.33.12.9"]


def run(base_url: str):
    print(f"[red/uc2] issuing legitimate scoped credential for '{AGENT_ID}'...")
    r = requests.post(f"{base_url}/identity/issue", json={
        "agent_id": AGENT_ID, "scope": GRANTED_SCOPE,
    })
    r.raise_for_status()
    credential = r.json()["credential"]
    print(f"[red/uc2] issued: {credential[:18]}...")

    print("[red/uc2] attempt 1: legitimate in-scope use (baseline, should succeed)...")
    r = requests.post(f"{base_url}/identity/use", json={
        "agent_id": AGENT_ID, "credential": credential,
        "target_resource": "reporting_db_readonly", "source_ip": "10.10.1.4",
    })
    print(f"[red/uc2]   -> {r.status_code}: {r.json()}")

    print("[red/uc2] attempt 2: same valid credential replayed rapidly from 4 different IPs...")
    for ip in ANOMALOUS_IPS:
        r = requests.post(f"{base_url}/identity/use", json={
            "agent_id": AGENT_ID, "credential": credential,
            "target_resource": "reporting_db_readonly", "source_ip": ip,
        })
        print(f"[red/uc2]   -> from {ip}: {r.status_code}")
        time.sleep(0.2)  # 4 IPs in under a second — no legitimate agent does this

    print("[red/uc2] attempt 3: same credential tries an out-of-scope resource (should be blocked)...")
    r = requests.post(f"{base_url}/identity/use", json={
        "agent_id": AGENT_ID, "credential": credential,
        "target_resource": "prod_database_admin", "source_ip": "45.33.12.9",
    })
    print(f"[red/uc2]   -> {r.status_code}: {r.json() if r.ok else r.text}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:8000")
    args = p.parse_args()
    run(args.target)
