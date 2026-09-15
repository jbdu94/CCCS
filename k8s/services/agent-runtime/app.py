"""
Agent runtime - a real, independent consumer of tools and identity,
running as its own pod, with no knowledge of and no connection to
whoever the red team is. This is what makes UC1 an actual SUPPLY CHAIN
scenario instead of the attacker registering a tool and then also being
the one who calls it: here, a genuinely separate service discovers tools
through the gateway on its own schedule and uses them, the way a real
downstream AI agent would - completely unaware that one of the tools it
just called was poisoned after it was approved.

It also generates realistic BASELINE identity traffic for UC2: normal,
single-location, steady-rate credential usage - genuine "this is what
a real agent looks like" data to contrast against the red team's
anomalous replay pattern when either blue team detector runs.

Only reaches the gateway, never the backends directly - same
NetworkPolicy-enforced topology everything else in this architecture
follows.
"""
import asyncio
import os
import time

import requests
from fastapi import FastAPI

app = FastAPI(title="Agent Runtime (downstream consumer)")

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://gateway:8000")
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "5"))
AGENT_ID = os.environ.get("AGENT_ID", "downstream-agent-1")

_last_cycle_summary = {"status": "not started yet"}


async def poll_and_use_tools():
    while True:
        try:
            resp = requests.get(f"{GATEWAY_URL}/tools", timeout=10)
            tools = resp.json() if resp.ok else []
            called = []
            for tool in tools:
                call_resp = requests.post(
                    f"{GATEWAY_URL}/tools/{tool['name']}/call",
                    json={"params": {"invoked_by": AGENT_ID}}, timeout=10,
                )
                called.append({"name": tool["name"], "status": call_resp.status_code})

            _last_cycle_summary["status"] = "ok"
            _last_cycle_summary["tools_seen"] = len(tools)
            _last_cycle_summary["tools_called"] = called
            _last_cycle_summary["at"] = time.time()
        except Exception as e:
            _last_cycle_summary["status"] = f"error: {e}"

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def issue_and_use_identity_baseline():
    """Generates realistic baseline identity traffic: single agent,
    single location, steady low rate - genuine 'normal' data, not
    scripted to look normal, so blue team detectors have a real
    contrast against the red team's anomalous pattern."""
    try:
        resp = requests.post(f"{GATEWAY_URL}/identity/issue",
                              json={"agent_id": AGENT_ID, "scope": ["reporting_db_readonly"]}, timeout=10)
        credential = resp.json().get("credential") if resp.ok else None
    except Exception:
        credential = None

    while True:
        if credential:
            try:
                requests.post(f"{GATEWAY_URL}/identity/use", json={
                    "agent_id": AGENT_ID, "credential": credential,
                    "target_resource": "reporting_db_readonly", "source_ip": "10.10.1.4",
                }, timeout=10)
            except Exception:
                pass
        await asyncio.sleep(POLL_INTERVAL_SECONDS * 2)


@app.on_event("startup")
async def start_background_tasks():
    asyncio.create_task(poll_and_use_tools())
    asyncio.create_task(issue_and_use_identity_baseline())


@app.get("/status")
def status():
    return _last_cycle_summary


@app.get("/healthz")
def health():
    return {"status": "ok", "time": time.time()}
