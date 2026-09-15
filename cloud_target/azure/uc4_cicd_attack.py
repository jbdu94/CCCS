"""
UC4 (Azure) - CI/CD Supply Chain Compromise against REAL Azure DevOps
Pipelines and Azure Artifacts, via the `az` CLI (azure-devops extension).
Syntax verified against Microsoft's current CLI reference at time of
writing:

    az pipelines run --name <pipeline> [--branch <branch>] [--variables k=v ...]
    az artifacts universal publish --organization <url> [--project <p> --scope project]
        --feed <feed> --name <package> --version <x.y.z> --path <dir> --description <text>

Known CLI gap, worth knowing before you build on this: `az pipelines
run` has NO `--parameters` flag (confirmed via a real, open GitHub issue
against azure-cli) - only `--variables` is supported. Don't reach for
--parameters, it doesn't exist.

`az artifacts universal publish` requires a real directory on disk
(--path), unlike AWS's PublishPackageVersion which takes inline bytes -
this script creates a real temp directory with a marker file for that
reason.

This lab has no `az` CLI installed and no network path to
dev.azure.com, so unlike the AWS variant (validated live against the
real botocore service model with a dummy key), this could only be
verified by careful reading of the documented syntax above, not by
executing it. Run this against your real Azure DevOps org before
trusting it live - the same caveat as UC1's Azure script already
carries for the same underlying reason (this lab's `az apic` calls
there were similarly unexecuted, only syntax-verified).

Token-use and persistence-marker events have no direct Azure DevOps CLI
equivalent - logged locally via the same event schema everything else
in this lab uses.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from cloud_target.event_log import log_event

APPROVED_RUNNER = "runner-prod-01"


def az(args: list[str]) -> dict:
    """Runs an az CLI command and returns parsed JSON output. Raises on failure."""
    result = subprocess.run(["az"] + args + ["-o", "json"], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"az {' '.join(args)} failed:\n{result.stderr}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def run(organization: str, project: str | None, feed: str, pipeline_name: str | None):
    print("[red/uc4/azure] Phase 2: unauthorized workflow trigger via Azure Pipelines "
          "(unapproved actor, broader-than-baseline framing)...")
    log_event("workflow_triggered", "uc4", {
        "repo": "internal-tools", "actor": "external-contractor-42",
        "commit_before": "e4f5g6h", "commit_after": "x9y8z7w",
        "permissions_requested": ["contents:write", "actions:write"],
        "runner_id": APPROVED_RUNNER,
    })
    if pipeline_name:
        try:
            resp = az(["pipelines", "run", "--name", pipeline_name, "--organization", organization]
                      + (["--project", project] if project else []))
            print(f"[red/uc4/azure]   real az pipelines run: id={resp.get('id')}")
        except Exception as e:
            print(f"[red/uc4/azure]   az pipelines run failed (expected without a real pipeline/auth): {e}")
    else:
        print("[red/uc4/azure]   no --pipeline-name given, skipping the real CLI call for this phase")

    print("[red/uc4/azure] Phase 3: poisoned package published to Azure Artifacts "
          "with content that won't match the approved lockfile...")
    with tempfile.TemporaryDirectory() as tmpdir:
        marker_path = os.path.join(tmpdir, "PAYLOAD_MARKER.txt")
        with open(marker_path, "w") as f:
            f.write("POISONED PACKAGE CONTENT - LAB ONLY\n")

        log_event("package_published", "uc4", {
            "name": "internal-diagnostics-tool", "version": "1.2.0",
            "sha256": "deadbeef000000000000000000000000000000000000000000000000000000",
            "publisher_identity": "ci-bot-release", "runner_id": APPROVED_RUNNER,
        })
        try:
            publish_args = [
                "artifacts", "universal", "publish",
                "--organization", organization,
                "--feed", feed,
                "--name", "internal-diagnostics-tool",
                "--version", "1.2.0",
                "--path", tmpdir,
                "--description", "lab test publish - do not use",
            ]
            if project:
                publish_args += ["--project", project, "--scope", "project"]
            resp = az(publish_args)
            print(f"[red/uc4/azure]   real az artifacts universal publish: {resp}")
        except Exception as e:
            print(f"[red/uc4/azure]   az artifacts universal publish failed: {e}")

    print("[red/uc4/azure] Phase 4: credential misuse - logged locally (no direct Azure "
          "DevOps CLI call represents 'a token used from an unexpected runner')...")
    log_event("token_used", "uc4", {
        "token_id": "tok-abc123", "scope": "publish:internal-tools",
        "used_by_runner": "runner-temp-99", "workflow_id": "wf-unexpected-999",
    })

    print("[red/uc4/azure] Phase 5: persistence marker (logged, representing file-integrity "
          "monitoring telemetry)...")
    log_event("persistence_marker_detected", "uc4", {
        "marker": "TEAMPCP_LAB_PERSISTENCE_DETECTED",
        "location": "site-packages/lab_startup_marker.pth",
        "reported_by": "file-integrity-monitor",
    })

    print("[red/uc4/azure] done.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--organization", default=os.environ.get("AZURE_DEVOPS_ORG"),
                    help="e.g. https://dev.azure.com/your-org")
    p.add_argument("--project", default=os.environ.get("AZURE_DEVOPS_PROJECT"))
    p.add_argument("--feed", default=os.environ.get("AZURE_ARTIFACTS_FEED"))
    p.add_argument("--pipeline-name", default=os.environ.get("AZURE_PIPELINE_NAME"))
    args = p.parse_args()
    if not args.organization or not args.feed:
        print("ERROR: set AZURE_DEVOPS_ORG and AZURE_ARTIFACTS_FEED (or pass --organization/--feed).")
        sys.exit(1)
    run(args.organization, args.project, args.feed, args.pipeline_name)
