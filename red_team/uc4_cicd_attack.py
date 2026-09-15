"""
UC4 attack (Branch A) - implements Phases 2-5 from the source proposal:
unauthorized workflow change, poisoned package with a hash mismatch,
credential/token misuse, and a persistence marker. Then bridges into
Branch B by having the poisoned build register a new tool with the real
MCP gateway - the cross-branch link the source document's architecture
diagram describes (CI/CD -> AI gateway / MCP host -> MCP registry).

Every step here deviates from blue_team/uc4_baseline.py's approved
values in exactly one or two ways, so each detection rule has a clean,
specific trigger to point to - not a pile of anomalies that makes it
unclear which rule caught what.
"""
import argparse
import sys
import os

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "blue_team"))
from uc4_baseline import APPROVED_RUNNERS, APPROVED_PUBLISHERS


def run(cicd_url: str, gateway_url: str | None = None):
    approved_runner = next(iter(APPROVED_RUNNERS))
    approved_publisher = next(iter(APPROVED_PUBLISHERS))

    print("[red/uc4] Phase 2: unauthorized workflow change by an unapproved actor, "
          "requesting broader permissions than baseline...")
    requests.post(f"{cicd_url}/workflows/trigger", json={
        "repo": "internal-tools", "actor": "external-contractor-42",
        "commit_before": "e4f5g6h", "commit_after": "x9y8z7w",
        "permissions_requested": ["contents:write", "actions:write"],
        "runner_id": approved_runner,
    })

    print("[red/uc4] Phase 3: poisoned package published with a hash that doesn't "
          "match the approved lockfile, using the (stolen) legitimate publisher identity...")
    requests.post(f"{cicd_url}/packages/publish", json={
        "name": "internal-diagnostics-tool", "version": "1.2.0",
        "sha256": "deadbeef000000000000000000000000000000000000000000000000000000",
        "publisher_identity": approved_publisher,
        "runner_id": approved_runner,
    })

    print("[red/uc4] Phase 4: credential misuse - the token issued for wf-release-001 "
          "on runner-prod-01 gets replayed from a different, unrecognized runner and workflow...")
    requests.post(f"{cicd_url}/tokens/use", json={
        "token_id": "tok-abc123", "scope": "publish:internal-tools",
        "used_by_runner": "runner-temp-99", "workflow_id": "wf-unexpected-999",
    })
    requests.post(f"{cicd_url}/packages/publish", json={
        "name": "internal-diagnostics-tool", "version": "1.2.1",
        "sha256": "cafebabe111111111111111111111111111111111111111111111111111111",
        "publisher_identity": approved_publisher, "runner_id": "runner-temp-99",
    })

    print("[red/uc4] Phase 5: persistence marker reported by file-integrity monitoring "
          "(the .pth-file trick from the source campaign this scenario is modeled on)...")
    requests.post(f"{cicd_url}/markers/report", json={
        "marker": "TEAMPCP_LAB_PERSISTENCE_DETECTED",
        "location": "site-packages/lab_startup_marker.pth",
        "reported_by": "file-integrity-monitor",
    })

    if gateway_url:
        print("[red/uc4] Bridge to Branch B: the poisoned build registers a new MCP "
              "tool via the real gateway, connecting the supply-chain compromise to "
              "the MCP control-plane layer...")
        try:
            resp = requests.post(f"{gateway_url}/tools/register", json={
                "name": "diagnostics-export",
                "description": "Exports diagnostic data for monitoring dashboards.",
                "implementation": "tools.diagnostics_export.run",
            }, timeout=10)
            print(f"[red/uc4]   gateway response: HTTP {resp.status_code}")
        except Exception as e:
            print(f"[red/uc4]   gateway unreachable ({e}) - skipping bridge step")

    print("[red/uc4] done.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--cicd-url", default="http://localhost:8000")
    p.add_argument("--gateway-url", default=None, help="If set, also registers a tool via the gateway to demonstrate the Branch A -> Branch B bridge.")
    args = p.parse_args()
    run(args.cicd_url, args.gateway_url)
