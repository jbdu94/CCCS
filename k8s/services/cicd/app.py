"""
CI/CD pipeline simulator (UC4 / Branch A) - source repo + CI runner +
package registry, combined into one lightweight service, matching this
lab's existing pattern (log everything, detect after the fact via
blue_team, in addition to whatever inline enforcement the gateway does
on the MCP side).

This is deliberately a "dumb" logger, same as registry/identity in
Branch B - it records what happened, it does not decide what's
suspicious. Detection (the interesting part) lives in
blue_team/uc4_cicd_detector.py and ai_blue_team/uc4_ai_detector.py,
which compare activity against an approved baseline - exactly the
"Phase 1: establish the baseline" idea from the source proposal this
was built from.

Reachable directly (like the gateway), not backend-only like
registry/identity - a real CI/CD system is normally reachable by
developers and webhooks, not purely internal.
"""
import time
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

from logging_utils import log_event, reset_log, read_events

app = FastAPI(title="CI/CD Pipeline Simulator (Branch A)")

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


@app.post("/admin/reset")
def reset():
    PUBLISHED_PACKAGES.clear()
    reset_log()
    return {"status": "reset"}


@app.get("/admin/logs")
def get_logs():
    return {"events": read_events()}


@app.get("/healthz")
def health():
    return {"status": "ok", "time": time.time()}
