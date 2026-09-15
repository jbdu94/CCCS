"""
Registry service - the actual tool store (UC1). In this architecture it
is NOT the public entry point: only the gateway can reach it (enforced
by Kubernetes NetworkPolicy - see manifests/02-networkpolicies.yaml).
Anything that wants to register or call a tool has to go through the
gateway, which scans traffic on the way through. That's the point: a
direct-attack-the-backend path doesn't exist in this topology, the same
way it wouldn't in a real deployment with an API gateway in front of an
internal service.
"""
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from logging_utils import log_event, reset_log, read_events, verify_chain

app = FastAPI(title="Registry (backend - gateway-only)")

TOOL_REGISTRY: dict[str, dict] = {}


class ToolRegistration(BaseModel):
    name: str
    description: str
    implementation: str


class ToolCall(BaseModel):
    params: dict = {}


@app.post("/tools/register")
def register_tool(tool: ToolRegistration):
    TOOL_REGISTRY[tool.name] = {
        "name": tool.name,
        "description": tool.description,
        "implementation": tool.implementation,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "quarantined": False,
    }
    log_event("tool_registered", "uc1", {
        "name": tool.name, "description": tool.description, "implementation": tool.implementation,
    })
    return {"status": "registered", "name": tool.name}


@app.post("/tools/{name}/update_description")
def update_tool_description(name: str, new_description: str):
    if name not in TOOL_REGISTRY:
        raise HTTPException(404, "tool not found")
    old = TOOL_REGISTRY[name]["description"]
    TOOL_REGISTRY[name]["description"] = new_description
    log_event("tool_description_changed", "uc1", {
        "name": name, "old_description": old, "new_description": new_description,
    })
    return {"status": "updated", "name": name}


@app.get("/tools")
def list_tools():
    return list(TOOL_REGISTRY.values())


@app.get("/tools/{name}")
def get_tool(name: str):
    if name not in TOOL_REGISTRY:
        raise HTTPException(404, "tool not found")
    return TOOL_REGISTRY[name]


@app.post("/tools/{name}/quarantine")
def quarantine_tool(name: str, reason: str = ""):
    """Called by the gateway when it detects a rug-pull. The registry
    itself just records the flag - the gateway is what actually refuses
    to serve or call a quarantined tool."""
    if name not in TOOL_REGISTRY:
        raise HTTPException(404, "tool not found")
    TOOL_REGISTRY[name]["quarantined"] = True
    TOOL_REGISTRY[name]["quarantine_reason"] = reason
    return {"status": "quarantined", "name": name}


@app.post("/tools/{name}/call")
def call_tool(name: str, call: ToolCall):
    if name not in TOOL_REGISTRY:
        raise HTTPException(404, "tool not found")
    tool = TOOL_REGISTRY[name]
    # SIMULATED execution only - never actually runs anything, here or
    # anywhere else in this lab.
    simulated_result = f"[simulated] would have executed with params={call.params}"
    log_event("tool_called", "uc1", {
        "name": name,
        "description_at_call_time": tool["description"],
        "implementation": tool["implementation"],
        "params": call.params,
    })
    return {"status": "executed", "result": simulated_result}


@app.post("/admin/reset")
def reset():
    TOOL_REGISTRY.clear()
    reset_log()
    return {"status": "reset"}


@app.get("/admin/verify_chain")
def verify_chain_endpoint():
    """Exposes the tamper-evident hash-chain check over HTTP, same as
    the local target - lets --prod verify audit integrity against this
    real registry pod's telemetry."""
    return verify_chain()


@app.get("/admin/logs")
def get_logs():
    return {"events": read_events()}


@app.get("/healthz")
def health():
    return {"status": "ok", "time": time.time()}
