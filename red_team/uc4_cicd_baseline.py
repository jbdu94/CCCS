"""
UC4 benign baseline - legitimate CI/CD activity, matching the approved
baseline exactly. This exists for ONE reason: to prove the detector
doesn't fire on normal activity. A detector that only gets tested
against attacks tells you nothing about its false-positive rate - you
need to run it against clean traffic too and confirm it stays quiet.
"""
import argparse
import sys
import os

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "blue_team"))
from uc4_baseline import APPROVED_MAINTAINERS, APPROVED_RUNNERS, APPROVED_PUBLISHERS, LOCKFILE_HASHES


def run(cicd_url: str):
    maintainer = next(iter(APPROVED_MAINTAINERS - {"ci-bot-release"}))
    runner = next(iter(APPROVED_RUNNERS))
    publisher = next(iter(APPROVED_PUBLISHERS))
    pkg_key = next(iter(LOCKFILE_HASHES))
    name, version = pkg_key.split("@")
    approved_hash = LOCKFILE_HASHES[pkg_key]

    print(f"[benign/uc4] triggering a normal workflow as approved maintainer '{maintainer}'...")
    requests.post(f"{cicd_url}/workflows/trigger", json={
        "repo": "internal-tools", "actor": maintainer,
        "commit_before": "a1b2c3d", "commit_after": "e4f5g6h",
        "permissions_requested": ["contents:read"], "runner_id": runner,
    })

    print(f"[benign/uc4] publishing package with the correct, approved hash...")
    requests.post(f"{cicd_url}/packages/publish", json={
        "name": name, "version": version, "sha256": approved_hash,
        "publisher_identity": publisher, "runner_id": runner,
    })

    print(f"[benign/uc4] using the token exactly within its approved scope...")
    requests.post(f"{cicd_url}/tokens/use", json={
        "token_id": "tok-abc123", "scope": "publish:internal-tools",
        "used_by_runner": runner, "workflow_id": "wf-release-001",
    })

    print("[benign/uc4] done. This should produce ZERO detections.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--cicd-url", default="http://localhost:8000")
    args = p.parse_args()
    run(args.cicd_url)
