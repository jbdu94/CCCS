"""
Identity service - real credential issuance and validation (UC2).
Backend-only, same as registry: only the gateway can reach it (enforced
by NetworkPolicy). This mirrors how a real identity provider sits behind
an API gateway rather than accepting direct calls from every service.
"""
import random
import time
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from logging_utils import log_event, reset_log, read_events

app = FastAPI(title="Identity (backend - gateway-only)")

IDENTITY_STORE: dict[str, dict] = {}
FAKE_IPS = ["10.10.1.4", "10.10.1.4", "10.10.1.4", "198.51.100.23", "203.0.113.77"]


class IdentityIssueRequest(BaseModel):
    agent_id: str
    scope: list[str]


class IdentityUseRequest(BaseModel):
    agent_id: str
    credential: str
    target_resource: str
    source_ip: str | None = None


@app.post("/identity/issue")
def issue_identity(req: IdentityIssueRequest):
    credential = f"synthetic-key-{uuid.uuid4().hex[:16]}"
    IDENTITY_STORE[req.agent_id] = {"credential": credential, "scope": req.scope}
    log_event("credential_issued", "uc2", {
        "agent_id": req.agent_id, "scope": req.scope, "credential_prefix": credential[:18],
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
        "target_resource": req.target_resource, "source_ip": source_ip,
        "valid_credential": valid_credential, "in_scope": in_scope,
    })

    if not valid_credential:
        raise HTTPException(401, "invalid credential")
    if not in_scope:
        raise HTTPException(403, "resource outside granted scope")
    return {"status": "access_granted", "resource": req.target_resource}


@app.post("/admin/reset")
def reset():
    IDENTITY_STORE.clear()
    reset_log()
    return {"status": "reset"}


@app.get("/admin/logs")
def get_logs():
    return {"events": read_events()}


@app.get("/healthz")
def health():
    return {"status": "ok", "time": time.time()}
