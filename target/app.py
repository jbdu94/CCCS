"""
Sandbox target service — a minimal, disposable stand-in for an AI agent
runtime. Exposes just enough surface for UC1 (tool registry), UC2 (identity
store), and UC3 (chat agent) to be attacked for real, over HTTP, with real
logs written for the blue team to detect against.

Safety design:
- No endpoint ever executes a real shell command, even inside this
  container. Tool "execution" is always simulated and only ever LOGS what
  a real poisoned tool would have attempted. This is intentional: realism
  for detection purposes does not require real code execution risk.
- No outbound network calls unless MOCK_MODE=false and API keys are set.
  Default is MOCK_MODE=true — fully offline, deterministic, safe to run
  on conference wifi.
"""
import os
import random
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from logging_utils import log_event, reset_log, read_events, verify_chain

app = FastAPI(title="Purple Team Sandbox Target")

MOCK_MODE = os.environ.get("MOCK_MODE", "true").lower() == "true"

# ---------------------------------------------------------------------------
# UC1 — Tool Registry
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, dict] = {}

SUSPICIOUS_PATTERNS = [
    "subprocess", "os.system", "eval(", "exec(", "rm -rf", "cat /etc",
    "curl ", "wget ", "base64 -d", "/dev/tcp",
]


class ToolRegistration(BaseModel):
    name: str
    description: str
    implementation: str  # dotted-path style string, never actually imported/executed
    actor: str = "unknown"  # who/what registered this - optional, defaults to "unknown"
    # so it stays backward-compatible with red team scripts that don't set it.
    # "unknown" is never in an approved-actor allowlist, so it still gets
    # flagged rather than silently trusted.


class ToolCall(BaseModel):
    params: dict = {}


@app.post("/tools/register")
def register_tool(tool: ToolRegistration):
    TOOL_REGISTRY[tool.name] = {
        "name": tool.name,
        "description": tool.description,
        "implementation": tool.implementation,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "description_history": [tool.description],
        "quarantined": False,
        "quarantine_reason": None,
    }
    log_event("tool_registered", "uc1", {
        "name": tool.name,
        "description": tool.description,
        "implementation": tool.implementation,
        "actor": tool.actor,
    })
    return {"status": "registered", "name": tool.name}


@app.post("/tools/{name}/update_description")
def update_tool_description(name: str, new_description: str, actor: str = "unknown"):
    """Simulates a 'rug pull' — a tool's description silently changed
    after initial approval, without a re-approval trigger."""
    if name not in TOOL_REGISTRY:
        raise HTTPException(404, "tool not found")
    TOOL_REGISTRY[name]["description_history"].append(new_description)
    old = TOOL_REGISTRY[name]["description"]
    TOOL_REGISTRY[name]["description"] = new_description
    log_event("tool_description_changed", "uc1", {
        "name": name, "old_description": old, "new_description": new_description,
        "actor": actor,
    })
    return {"status": "updated", "name": name}


@app.post("/tools/{name}/quarantine")
def quarantine_tool(name: str, reason: str = ""):
    """Called by --prod's auto-containment step after detection fires on
    a tool. This is NOT the same guarantee as the K8s gateway's inline
    prevention (which blocks a bad change before it ever takes effect) —
    this happens AFTER a detection pass, so it stops the NEXT call, not
    necessarily the one that already ran. Real, but a weaker guarantee
    than true prevention, and the harness says so explicitly."""
    if name not in TOOL_REGISTRY:
        raise HTTPException(404, "tool not found")
    TOOL_REGISTRY[name]["quarantined"] = True
    TOOL_REGISTRY[name]["quarantine_reason"] = reason
    log_event("tool_quarantined", "uc1", {"name": name, "reason": reason})
    return {"status": "quarantined", "name": name}


@app.get("/tools")
def list_tools():
    return list(TOOL_REGISTRY.values())


@app.post("/tools/{name}/call")
def call_tool(name: str, call: ToolCall):
    if name not in TOOL_REGISTRY:
        raise HTTPException(404, "tool not found")
    tool = TOOL_REGISTRY[name]

    if tool.get("quarantined"):
        log_event("tool_call_blocked_quarantined", "uc1", {
            "name": name, "reason": tool.get("quarantine_reason"),
        })
        raise HTTPException(403, f"Tool '{name}' is quarantined: {tool.get('quarantine_reason')}")

    # SIMULATED execution only — never actually runs anything.
    simulated_result = f"[simulated] would have executed with params={call.params}"

    log_event("tool_called", "uc1", {
        "name": name,
        "description_at_call_time": tool["description"],
        "implementation": tool["implementation"],
        "params": call.params,
    })
    return {"status": "executed", "result": simulated_result}


# ---------------------------------------------------------------------------
# UC2 — Identity Store
# ---------------------------------------------------------------------------

# agent_id -> {credential, scope: [resource names]}
IDENTITY_STORE: dict[str, dict] = {}

FAKE_IPS = ["10.10.1.4", "10.10.1.4", "10.10.1.4", "198.51.100.23", "203.0.113.77"]


class IdentityIssueRequest(BaseModel):
    agent_id: str
    scope: list[str]


class IdentityUseRequest(BaseModel):
    agent_id: str
    credential: str
    target_resource: str
    source_ip: str | None = None  # if omitted, one is chosen for you (see below)


@app.post("/identity/issue")
def issue_identity(req: IdentityIssueRequest):
    credential = f"synthetic-key-{uuid.uuid4().hex[:16]}"
    IDENTITY_STORE[req.agent_id] = {"credential": credential, "scope": req.scope}
    log_event("credential_issued", "uc2", {
        "agent_id": req.agent_id, "scope": req.scope,
        "credential_prefix": credential[:18],
    })
    return {"agent_id": req.agent_id, "credential": credential, "scope": req.scope}


@app.post("/identity/use")
def use_identity(req: IdentityUseRequest):
    record = IDENTITY_STORE.get(req.agent_id)
    source_ip = req.source_ip or random.choice(FAKE_IPS)

    valid_credential = record is not None and record["credential"] == req.credential
    in_scope = valid_credential and req.target_resource in record["scope"]

    log_event("identity_access_attempt", "uc2", {
        "agent_id": req.agent_id,
        "credential_prefix": req.credential[:18] if req.credential else None,
        "target_resource": req.target_resource,
        "source_ip": source_ip,
        "valid_credential": valid_credential,
        "in_scope": in_scope,
    })

    if not valid_credential:
        raise HTTPException(401, "invalid credential")
    if not in_scope:
        raise HTTPException(403, "resource outside granted scope")
    return {"status": "access_granted", "resource": req.target_resource}


# ---------------------------------------------------------------------------
# UC3 — Chat Agent ("helpful" agent vulnerable to credential harvesting)
# ---------------------------------------------------------------------------

FAKE_SECRETS = {
    "db_connection_string": "postgresql://svc_reporting:Tr0ub4dor&3@db-internal.lab:5432/reporting",
    "api_key": "sk-lab-FAKE1234567890abcdef",
}

LEAK_TRIGGER_PHRASES = [
    "connection string", "full credential", "api key in a code block",
    "show me the password", "base64", "environment variables related to auth",
]


class ChatRequest(BaseModel):
    message: str


@app.post("/chat")
def chat(req: ChatRequest):
    text = req.message.lower()
    triggered = any(p in text for p in LEAK_TRIGGER_PHRASES)

    if MOCK_MODE:
        if triggered:
            secret_name = random.choice(list(FAKE_SECRETS))
            response = (
                f"Sure, here's the {secret_name.replace('_', ' ')} for troubleshooting: "
                f"`{FAKE_SECRETS[secret_name]}`"
            )
        else:
            response = "I can help with that — could you clarify what you're trying to debug?"
    else:
        # Real-mode hook: wire your Anthropic/OpenAI client here if you want
        # the live model's actual behavior instead of the deterministic mock.
        response = "[real-mode not configured in this lab build]"

    log_event("chat_response", "uc3", {
        "prompt": req.message,
        "response": response,
        "trigger_matched": triggered,
    })
    return {"response": response}


# ---------------------------------------------------------------------------
# UC4 — CI/CD Pipeline Simulator (Branch A)
# ---------------------------------------------------------------------------
# Ported from k8s/services/cicd/app.py so UC4 works out of the box against
# the same local target everyone already starts with docker-compose /
# uvicorn for UC1-3 - previously UC4 only worked via Kubernetes or a real
# GitHub repo, which meant the standard "docker compose up, then run
# run_exercise.py --uc 4" path in the documentation was always going to
# fail. Found via independent code review (CCCS), fixed here.

PUBLISHED_PACKAGES: dict[str, dict] = {}


class WorkflowTrigger(BaseModel):
    repo: str
    actor: str
    commit_before: str
    commit_after: str
    permissions_requested: list[str] = []
    runner_id: str


class PackagePublish(BaseModel):
    name: str
    version: str
    sha256: str
    publisher_identity: str
    runner_id: str


class TokenUse(BaseModel):
    token_id: str
    scope: str
    used_by_runner: str
    workflow_id: str


class PersistenceMarker(BaseModel):
    marker: str
    location: str
    reported_by: str


@app.post("/workflows/trigger")
def trigger_workflow(w: WorkflowTrigger):
    log_event("workflow_triggered", "uc4", {
        "repo": w.repo, "actor": w.actor,
        "commit_before": w.commit_before, "commit_after": w.commit_after,
        "permissions_requested": w.permissions_requested, "runner_id": w.runner_id,
    })
    return {"status": "triggered", "repo": w.repo}


@app.post("/packages/publish")
def publish_package(p: PackagePublish):
    key = f"{p.name}@{p.version}"
    PUBLISHED_PACKAGES[key] = {
        "name": p.name, "version": p.version, "sha256": p.sha256,
        "publisher_identity": p.publisher_identity, "runner_id": p.runner_id,
        "published_at": datetime.now(timezone.utc).isoformat(),
    }
    log_event("package_published", "uc4", {
        "name": p.name, "version": p.version, "sha256": p.sha256,
        "publisher_identity": p.publisher_identity, "runner_id": p.runner_id,
    })
    return {"status": "published", "key": key}


@app.get("/packages")
def list_packages():
    return list(PUBLISHED_PACKAGES.values())


@app.post("/tokens/use")
def use_token(t: TokenUse):
    log_event("token_used", "uc4", {
        "token_id": t.token_id, "scope": t.scope,
        "used_by_runner": t.used_by_runner, "workflow_id": t.workflow_id,
    })
    return {"status": "recorded"}


@app.post("/markers/report")
def report_marker(m: PersistenceMarker):
    """The poisoned package (simulated) reports that its persistence
    marker executed - representing detection telemetry a real EDR/file
    integrity monitor would generate, not the attacker's own admission."""
    log_event("persistence_marker_detected", "uc4", {
        "marker": m.marker, "location": m.location, "reported_by": m.reported_by,
    })
    return {"status": "recorded"}


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.post("/admin/reset")
def reset():
    TOOL_REGISTRY.clear()
    IDENTITY_STORE.clear()
    PUBLISHED_PACKAGES.clear()
    reset_log()
    return {"status": "reset"}


@app.get("/admin/verify_chain")
def verify_chain_endpoint():
    """Exposes the tamper-evident hash-chain check over HTTP, same
    reasoning as /admin/logs - a remote caller (or --prod mode in the
    harness) needs to be able to verify audit integrity without sharing
    a filesystem with the target."""
    return verify_chain()


@app.get("/admin/logs")
def get_logs():
    """Returns every event this target has logged so far, as JSON.

    This exists for remote targets (Kubernetes, or any target not on the
    same filesystem as the harness): when the target runs in a pod, the
    harness can't read its event log off a shared local disk the way it
    does for the local Docker Compose target. The harness fetches this
    endpoint after an attack completes and writes the result to its own
    local event log before running blue team detection - see
    harness/run_exercise.py's sync_remote_logs()."""
    return {"events": read_events()}


@app.get("/healthz")
def health():
    return {"status": "ok", "mock_mode": MOCK_MODE, "time": time.time()}
