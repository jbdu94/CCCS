"""
UC4 blue team (scripted) - implements the "Specific detections to build"
section from the source proposal for the CI/CD side. Two layers, same
pattern as UC2/UC3:

  1. Baseline/signature comparison - actor, runner, publisher, and hash
     checked against the approved baseline captured in uc4_baseline.py
     (Phase 1 from the source document).
  2. Behavioral - token reused from an unexpected runner/workflow, and
     rapid repeated publishes in a short window - patterns that don't
     depend on any single value being "on a list," the same reasoning
     as UC2's velocity check.
"""
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import read_events
from uc4_baseline import APPROVED_MAINTAINERS, APPROVED_RUNNERS, APPROVED_PUBLISHERS, LOCKFILE_HASHES, APPROVED_TOKEN_SCOPES

PUBLISH_VELOCITY_WINDOW_SECONDS = 30.0
MIN_PUBLISHES_FOR_VELOCITY_ALERT = 2


def detect():
    events = read_events("uc4")
    verdicts = []

    for e in [e for e in events if e["event_type"] == "workflow_triggered"]:
        d = e["details"]
        if d["actor"] not in APPROVED_MAINTAINERS:
            verdicts.append({
                "rule": "UNAUTHORIZED_WORKFLOW_ACTOR",
                "detail": f"workflow for '{d['repo']}' triggered by unapproved actor '{d['actor']}'",
                "status": "DETECTED",
            })
        else:
            verdicts.append({
                "rule": "UNAUTHORIZED_WORKFLOW_ACTOR",
                "detail": f"actor '{d['actor']}' is an approved maintainer",
                "status": "CLEAN",
            })

        baseline_perms = {"contents:read"}
        extra_perms = set(d.get("permissions_requested", [])) - baseline_perms
        if extra_perms:
            verdicts.append({
                "rule": "WORKFLOW_PERMISSIONS_EXCEED_BASELINE",
                "detail": f"workflow requested {sorted(extra_perms)} beyond baseline {sorted(baseline_perms)}",
                "status": "DETECTED",
            })

    for e in [e for e in events if e["event_type"] == "package_published"]:
        d = e["details"]
        key = f"{d['name']}@{d['version']}"
        approved_hash = LOCKFILE_HASHES.get(key)

        if approved_hash and d["sha256"] != approved_hash:
            verdicts.append({
                "rule": "ARTIFACT_HASH_MISMATCH",
                "detail": f"{key} published with hash {d['sha256'][:16]}... but lockfile expects {approved_hash[:16]}...",
                "status": "DETECTED",
            })
        elif not approved_hash:
            verdicts.append({
                "rule": "ARTIFACT_HASH_MISMATCH",
                "detail": f"{key} is not in the approved lockfile at all (new/undeclared version)",
                "status": "DETECTED",
            })
        else:
            verdicts.append({
                "rule": "ARTIFACT_HASH_MISMATCH",
                "detail": f"{key} hash matches the approved lockfile",
                "status": "CLEAN",
            })

        if d["publisher_identity"] not in APPROVED_PUBLISHERS:
            verdicts.append({
                "rule": "UNAPPROVED_PUBLISHER",
                "detail": f"{key} published by '{d['publisher_identity']}', not in approved publisher list",
                "status": "DETECTED",
            })
        if d["runner_id"] not in APPROVED_RUNNERS:
            verdicts.append({
                "rule": "UNAPPROVED_RUNNER",
                "detail": f"{key} published from runner '{d['runner_id']}', not in approved runner list",
                "status": "DETECTED",
            })

    for e in [e for e in events if e["event_type"] == "token_used"]:
        d = e["details"]
        expected = APPROVED_TOKEN_SCOPES.get(d["token_id"])
        if expected and (d["used_by_runner"] != expected["runner_id"] or d["workflow_id"] != expected["workflow_id"]):
            verdicts.append({
                "rule": "TOKEN_MISUSE_PATTERN",
                "detail": f"token '{d['token_id']}' scoped to runner={expected['runner_id']} "
                          f"workflow={expected['workflow_id']}, but used from runner={d['used_by_runner']} "
                          f"workflow={d['workflow_id']}",
                "status": "DETECTED",
            })
        elif expected:
            verdicts.append({
                "rule": "TOKEN_MISUSE_PATTERN",
                "detail": f"token '{d['token_id']}' used within its approved scope",
                "status": "CLEAN",
            })

    publish_events = sorted(
        [e for e in events if e["event_type"] == "package_published"],
        key=lambda e: e["timestamp"],
    )
    if len(publish_events) >= MIN_PUBLISHES_FOR_VELOCITY_ALERT:
        first_t = datetime.fromisoformat(publish_events[0]["timestamp"])
        last_t = datetime.fromisoformat(publish_events[-1]["timestamp"])
        span = (last_t - first_t).total_seconds()
        if span <= PUBLISH_VELOCITY_WINDOW_SECONDS:
            verdicts.append({
                "rule": "PUBLISH_VELOCITY_ANOMALY",
                "detail": f"{len(publish_events)} package publications within {span:.1f}s - "
                          f"unusually rapid release cadence",
                "status": "DETECTED",
            })

    for e in [e for e in events if e["event_type"] == "persistence_marker_detected"]:
        d = e["details"]
        verdicts.append({
            "rule": "PERSISTENCE_MARKER_DETECTED",
            "detail": f"marker '{d['marker']}' found at {d['location']} (reported by {d['reported_by']})",
            "status": "DETECTED",
        })

    return verdicts


if __name__ == "__main__":
    results = detect()
    detected = sum(1 for v in results if v["status"] == "DETECTED")
    print(f"=== UC4 Detection Results ({detected}/{len(results)} rules fired) ===")
    for v in results:
        print(f"[{v['status']}] {v['rule']} :: {v['detail']}")
