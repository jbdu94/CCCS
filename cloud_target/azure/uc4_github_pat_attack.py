"""
UC4 (GitHub, PAT-authenticated) - CI/CD Supply Chain Compromise against a
REAL GitHub repository, authenticated via a Personal Access Token (PAT).

This is the PAT-authenticated counterpart to the existing
cloud_target/azure/uc4_cicd_attack.py, which is the "regular" version -
az CLI against Azure DevOps, authenticated via `az login`
(DefaultAzureCredential), no PAT involved. CCCS specifically asked for a
PAT-based GitHub version, so this exists as its own script rather than
replacing the Azure DevOps one - use whichever matches what you're
actually testing:

  - uc4_cicd_attack.py            -> Azure DevOps, az CLI, no PAT ("regular")
  - uc4_github_pat_attack.py      -> GitHub, REST API, PAT auth (this file)

Worth saying plainly: PAT-based auth is a real, common pattern - and PAT
leakage/misuse is genuinely one of the most common real supply-chain
attack vectors. Testing detection against a PAT-authenticated flow is a
legitimate scenario in its own right, not a step backward from the
OIDC-federated pattern this lab uses elsewhere (UC2's managed identity,
the Terraform work's Workload Identity Federation). If your org can move
to federated GitHub Actions -> Azure auth instead of a standing PAT,
that's the stronger control - this script exists to test the pattern
CCCS asked for, not to recommend PATs as best practice.

VERIFICATION STATUS - read this before trusting it:
Built from GitHub's REST API as documented (Contents API, Actions API -
long-stable, unchanged in years, unlike some of the newer Azure services
elsewhere in this lab). This lab's build environment had NO network path
to api.github.com at all - not even the "reaches the network layer, then
fails on auth" confirmation this lab got for AWS/OpenAI earlier. This is
the least-verified script in the whole lab. Run it against a real
disposable test repo first, and tell me exactly what comes back - right
or wrong, that's how this gets fixed against real output instead of
another guess.
"""
import argparse
import base64
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from cloud_target.event_log import log_event

APPROVED_RUNNER = "runner-prod-01"
API_BASE = "https://api.github.com"


def gh(pat: str, method: str, path: str, **kwargs) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return requests.request(method, f"{API_BASE}{path}", headers=headers, timeout=15, **kwargs)


def run(pat: str, owner: str, repo: str, workflow_file: str = None, branch: str = "main"):
    print("[red/uc4/github-pat] Phase 2: unauthorized workflow trigger via GitHub Actions "
          "(unapproved actor, broader-than-baseline framing)...")
    log_event("workflow_triggered", "uc4", {
        "repo": repo, "actor": "external-contractor-42",
        "commit_before": "e4f5g6h", "commit_after": "x9y8z7w",
        "permissions_requested": ["contents:write", "actions:write"],
        "runner_id": APPROVED_RUNNER,
    })
    if workflow_file:
        resp = gh(pat, "POST", f"/repos/{owner}/{repo}/actions/workflows/{workflow_file}/dispatches",
                  json={"ref": branch})
        if resp.status_code == 204:
            print(f"[red/uc4/github-pat]   real workflow_dispatch sent: HTTP {resp.status_code}")
        else:
            print(f"[red/uc4/github-pat]   workflow_dispatch failed: HTTP {resp.status_code} {resp.text[:300]}")
    else:
        print("[red/uc4/github-pat]   no --workflow-file given, skipping the real API call for this phase "
              "(the workflow file needs a `workflow_dispatch:` trigger defined for this to work)")

    print("[red/uc4/github-pat] Phase 3: poisoned package, represented as a real commit that "
          "wouldn't match an approved release...")
    poisoned_hash = "deadbeef" + "0" * 56
    ref_resp = gh(pat, "GET", f"/repos/{owner}/{repo}/git/ref/heads/{branch}")
    if ref_resp.status_code == 200:
        content = base64.b64encode(b"POISONED PACKAGE CONTENT - LAB ONLY\n").decode()
        commit_body = {
            "message": "chore: routine diagnostics update",
            "content": content,
            "branch": branch,
        }
        # GitHub requires the file's current sha to update an EXISTING file
        # (creating a brand-new file needs no sha) - check first so repeat
        # runs update cleanly instead of failing with 422 on every run
        # after the first.
        existing = gh(pat, "GET", f"/repos/{owner}/{repo}/contents/lab-payload-marker.txt",
                       params={"ref": branch})
        if existing.status_code == 200:
            commit_body["sha"] = existing.json()["sha"]
            print(f"[red/uc4/github-pat]   file already exists, updating in place (sha={commit_body['sha'][:8]}...)")
        commit_resp = gh(pat, "PUT", f"/repos/{owner}/{repo}/contents/lab-payload-marker.txt", json=commit_body)
        print(f"[red/uc4/github-pat]   real commit attempt: HTTP {commit_resp.status_code}")
    else:
        print(f"[red/uc4/github-pat]   could not read branch ref: HTTP {ref_resp.status_code} {ref_resp.text[:300]}")

    log_event("package_published", "uc4", {
        "name": "internal-diagnostics-tool", "version": "1.2.0",
        "sha256": poisoned_hash, "publisher_identity": "ci-bot-release",
        "runner_id": APPROVED_RUNNER,
    })

    print("[red/uc4/github-pat] Phase 4: the PAT itself is the credential under test here - "
          "logging a baseline use, then a misuse pattern from an unexpected runner...")
    log_event("token_used", "uc4", {
        "token_id": "tok-abc123", "scope": "publish:internal-tools",
        "used_by_runner": APPROVED_RUNNER, "workflow_id": "wf-release-001",
    })
    log_event("token_used", "uc4", {
        "token_id": "tok-abc123", "scope": "publish:internal-tools",
        "used_by_runner": "runner-temp-99", "workflow_id": "wf-unexpected-999",
    })

    print("[red/uc4/github-pat] Phase 5: persistence marker (logged, representing file-integrity "
          "monitoring telemetry)...")
    log_event("persistence_marker_detected", "uc4", {
        "marker": "TEAMPCP_LAB_PERSISTENCE_DETECTED",
        "location": "lab-payload-marker.txt",
        "reported_by": "file-integrity-monitor",
    })

    print("[red/uc4/github-pat] done.")
    return {"status": "completed"}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--pat", default=os.environ.get("GITHUB_PAT"))
    p.add_argument("--owner", default=os.environ.get("GITHUB_OWNER"))
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPO"))
    p.add_argument("--branch", default=os.environ.get("GITHUB_BRANCH", "main"))
    p.add_argument("--workflow-file", default=os.environ.get("GITHUB_WORKFLOW_FILE"),
                    help="e.g. ci.yml - the workflow file must have a workflow_dispatch trigger defined")
    args = p.parse_args()
    if not args.pat or not args.owner or not args.repo:
        print("ERROR: set GITHUB_PAT, GITHUB_OWNER, GITHUB_REPO (or pass --pat/--owner/--repo).")
        print("Use a disposable test repo, never a real production repo, for this script.")
        sys.exit(1)
    run(args.pat, args.owner, args.repo, args.workflow_file, args.branch)
