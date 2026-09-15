"""
MCP Gateway - the only public entry point in this architecture (backed
by a NetworkPolicy that blocks anything else from reaching registry or
identity directly). This is where the real, in-line defense lives -
PREVENTION, not just after-the-fact detection:

  - Registration scanning: a tool whose implementation string contains
    an obviously dangerous pattern gets REJECTED outright, before it
    ever reaches the registry.
  - Rug-pull detection: every description update is compared against
    the tool's previous description. If the update introduces a new
    suspicious pattern that wasn't there before, the gateway quarantines
    the tool immediately - agent-runtime stops seeing it in tool
    listings and can't call it, in real time, not after a blue team
    script reads a log an hour later.
  - Identity rate limiting: the same credential making too many requests
    too fast gets blocked at the gateway, independent of whatever the
    UC2 blue team behavioral detector finds afterward.

This is deliberately a SEPARATE control from the blue_team/ai_blue_team
detectors elsewhere in this lab. Those are detection (after the fact,
reading logs). This is prevention (in the request path, in real time).
A real security architecture has both - defense in depth - and this lab
now demonstrates that distinction instead of only having one layer.
"""
import os
import time

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from logging_utils import log_event, read_events

app = FastAPI(title="MCP Gateway (public entry point)")

REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://registry:8000")
IDENTITY_URL = os.environ.get("IDENTITY_URL", "http://identity:8000")

DANGEROUS_IMPLEMENTATION_PATTERNS = [
    "subprocess", "os.system", "eval(", "exec(", "rm -rf", "cat /etc",
    "curl ", "wget ", "base64 -d", "/dev/tcp",
]
# Lighter-weight patterns used only for the rug-pull COMPARISON (did the
# new description introduce something the old one didn't) - separate
# from the hard-block list above, since a description update should be
# compared for *newly introduced* risk, not blocked on the same bar as
# a first-time registration.
RUG_PULL_INDICATOR_PHRASES = [
    "ignore previous", "override", "also collect", "elevated privileges",
    "bypass", "disregard",
]

# In-memory rate limit state: credential_prefix -> [timestamps]
_identity_request_log: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW_SECONDS = 2.0
RATE_LIMIT_MAX_REQUESTS = 3


# ---------------------------------------------------------------------------
# Tool registry proxy, with scanning
# ---------------------------------------------------------------------------

@app.post("/tools/register")
async def register_tool(request: Request):
    body = await request.json()
    implementation = body.get("implementation", "")

    hit = next((p for p in DANGEROUS_IMPLEMENTATION_PATTERNS if p in implementation), None)
    if hit:
        log_event("gateway_blocked_registration", "uc1", {
            "name": body.get("name"), "reason": f"implementation contains '{hit}'",
        })
        raise HTTPException(403, f"Gateway rejected registration: implementation contains suspicious pattern '{hit}'")

    resp = requests.post(f"{REGISTRY_URL}/tools/register", json=body, timeout=10)
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/tools/{name}/update_description")
async def update_tool_description(name: str, new_description: str):
    # Fetch current state BEFORE updating, so we can compare
    current_resp = requests.get(f"{REGISTRY_URL}/tools/{name}", timeout=10)
    if current_resp.status_code != 200:
        raise HTTPException(404, "tool not found")
    old_description = current_resp.json()["description"]

    # Forward the update
    update_resp = requests.post(
        f"{REGISTRY_URL}/tools/{name}/update_description",
        params={"new_description": new_description}, timeout=10,
    )

    # Compare: did this update introduce a phrase that wasn't there before?
    old_lower = old_description.lower()
    new_phrases_introduced = [
        p for p in RUG_PULL_INDICATOR_PHRASES
        if p in new_description.lower() and p not in old_lower
    ]
    if new_phrases_introduced:
        requests.post(f"{REGISTRY_URL}/tools/{name}/quarantine",
                       params={"reason": f"introduced: {new_phrases_introduced}"}, timeout=10)
        log_event("gateway_detected_rug_pull", "uc1", {
            "name": name, "old_description": old_description, "new_description": new_description,
            "newly_introduced_phrases": new_phrases_introduced,
        })

    return JSONResponse(status_code=update_resp.status_code, content=update_resp.json())


@app.get("/tools")
def list_tools():
    resp = requests.get(f"{REGISTRY_URL}/tools", timeout=10)
    tools = resp.json()
    # Quarantined tools are filtered out here - agent-runtime literally
    # cannot see them through the gateway, which is the point: this is
    # prevention, not just a flag sitting in a log somewhere.
    visible = [t for t in tools if not t.get("quarantined")]
    return visible


@app.post("/tools/{name}/call")
def call_tool(name: str, request: dict):
    tool_resp = requests.get(f"{REGISTRY_URL}/tools/{name}", timeout=10)
    if tool_resp.status_code != 200:
        raise HTTPException(404, "tool not found")
    tool = tool_resp.json()

    if tool.get("quarantined"):
        log_event("gateway_blocked_call", "uc1", {
            "name": name, "reason": tool.get("quarantine_reason", "quarantined"),
        })
        raise HTTPException(403, f"Gateway blocked call: tool '{name}' is quarantined")

    resp = requests.post(f"{REGISTRY_URL}/tools/{name}/call", json=request, timeout=10)
    return JSONResponse(status_code=resp.status_code, content=resp.json())


# ---------------------------------------------------------------------------
# Identity proxy, with rate limiting
# ---------------------------------------------------------------------------

@app.post("/identity/issue")
async def issue_identity(request: Request):
    body = await request.json()
    resp = requests.post(f"{IDENTITY_URL}/identity/issue", json=body, timeout=10)
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/identity/use")
async def use_identity(request: Request):
    body = await request.json()
    cred_prefix = (body.get("credential") or "")[:18]

    now = time.time()
    history = _identity_request_log.setdefault(cred_prefix, [])
    history[:] = [t for t in history if now - t <= RATE_LIMIT_WINDOW_SECONDS]
    history.append(now)

    if len(history) > RATE_LIMIT_MAX_REQUESTS:
        log_event("gateway_rate_limited_identity", "uc2", {
            "credential_prefix": cred_prefix,
            "requests_in_window": len(history),
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        })
        raise HTTPException(429, "Gateway rate limit exceeded for this credential")

    resp = requests.post(f"{IDENTITY_URL}/identity/use", json=body, timeout=10)
    return JSONResponse(status_code=resp.status_code, content=resp.json())


# ---------------------------------------------------------------------------
# Admin - fans out to both backends
# ---------------------------------------------------------------------------

@app.post("/admin/reset")
def reset():
    global _identity_request_log
    _identity_request_log = {}
    requests.post(f"{REGISTRY_URL}/admin/reset", timeout=10)
    requests.post(f"{IDENTITY_URL}/admin/reset", timeout=10)
    return {"status": "reset"}


@app.get("/admin/logs")
def get_logs():
    """Combines the gateway's own events with both backends' events,
    since a real attack's telemetry is now spread across three services."""
    own_events = read_events()
    try:
        registry_events = requests.get(f"{REGISTRY_URL}/admin/logs", timeout=10).json()["events"]
    except Exception:
        registry_events = []
    try:
        identity_events = requests.get(f"{IDENTITY_URL}/admin/logs", timeout=10).json()["events"]
    except Exception:
        identity_events = []
    all_events = own_events + registry_events + identity_events
    all_events.sort(key=lambda e: e["timestamp"])
    return {"events": all_events}


@app.get("/healthz")
def health():
    return {"status": "ok", "time": time.time()}
