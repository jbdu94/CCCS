"""
UC4 (AWS) - CI/CD Supply Chain Compromise against REAL AWS CodeArtifact
(package publish) and CodePipeline (workflow trigger). Field names
verified directly from the current botocore service model
(PublishPackageVersion, StartPipelineExecution) - not guessed.

Requires:
  - An existing CodeArtifact domain + repository (create once via
    `aws codeartifact create-domain` / `create-repository`, or reuse
    an existing one - this script does not provision them, same as
    UC1/UC2's AWS scripts don't provision the registry/workload
    identity themselves beyond the one-time setup.sh step)
  - An existing CodePipeline pipeline (optional - if you don't have
    one, the workflow-trigger step will fail gracefully and log that,
    same pattern as everywhere else in this lab)

Token-use and persistence-marker events have no direct 1:1 AWS API
(those are IAM/EDR-level concepts, not something you "call") - they are
logged locally via the same event schema everything else in this lab
uses, exactly like the local cicd service does, so the detector reads
identical telemetry regardless of which target produced it.
"""
import argparse
import hashlib
import os
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from cloud_target.event_log import log_event

APPROVED_RUNNER = "runner-prod-01"


def run(region: str, domain: str, repository: str, pipeline_name: str | None):
    codeartifact = boto3.client("codeartifact", region_name=region)
    codepipeline = boto3.client("codepipeline", region_name=region)

    print("[red/uc4/aws] Phase 2: unauthorized workflow trigger via CodePipeline "
          "(unapproved actor, broader-than-baseline framing)...")
    log_event("workflow_triggered", "uc4", {
        "repo": "internal-tools", "actor": "external-contractor-42",
        "commit_before": "e4f5g6h", "commit_after": "x9y8z7w",
        "permissions_requested": ["contents:write", "actions:write"],
        "runner_id": APPROVED_RUNNER,
    })
    if pipeline_name:
        try:
            resp = codepipeline.start_pipeline_execution(name=pipeline_name)
            print(f"[red/uc4/aws]   real StartPipelineExecution: {resp.get('pipelineExecutionId')}")
        except ClientError as e:
            print(f"[red/uc4/aws]   StartPipelineExecution failed (expected without a real pipeline/creds): {e}")
    else:
        print("[red/uc4/aws]   no --pipeline-name given, skipping the real API call for this phase")

    print("[red/uc4/aws] Phase 3: poisoned package published to CodeArtifact with a "
          "hash that won't match the approved lockfile...")
    poisoned_content = b"POISONED PACKAGE CONTENT - LAB ONLY"
    poisoned_hash = hashlib.sha256(poisoned_content).hexdigest()
    log_event("package_published", "uc4", {
        "name": "internal-diagnostics-tool", "version": "1.2.0",
        "sha256": poisoned_hash, "publisher_identity": "ci-bot-release",
        "runner_id": APPROVED_RUNNER,
    })
    try:
        resp = codeartifact.publish_package_version(
            domain=domain, repository=repository, format="pypi",
            package="internal-diagnostics-tool", packageVersion="1.2.0",
            assetContent=poisoned_content, assetName="internal-diagnostics-tool-1.2.0.tar.gz",
            assetSHA256=poisoned_hash,
        )
        print(f"[red/uc4/aws]   real PublishPackageVersion: status={resp.get('status')}")
    except ClientError as e:
        print(f"[red/uc4/aws]   PublishPackageVersion failed: {e}")

    print("[red/uc4/aws] Phase 4: credential misuse - logged locally (no direct AWS "
          "API call represents 'a token used from an unexpected runner')...")
    log_event("token_used", "uc4", {
        "token_id": "tok-abc123", "scope": "publish:internal-tools",
        "used_by_runner": "runner-temp-99", "workflow_id": "wf-unexpected-999",
    })

    print("[red/uc4/aws] Phase 5: persistence marker (logged, representing file-integrity "
          "monitoring telemetry)...")
    log_event("persistence_marker_detected", "uc4", {
        "marker": "TEAMPCP_LAB_PERSISTENCE_DETECTED",
        "location": "site-packages/lab_startup_marker.pth",
        "reported_by": "file-integrity-monitor",
    })

    print("[red/uc4/aws] done.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    p.add_argument("--domain", default=os.environ.get("AWS_CODEARTIFACT_DOMAIN"))
    p.add_argument("--repository", default=os.environ.get("AWS_CODEARTIFACT_REPOSITORY"))
    p.add_argument("--pipeline-name", default=os.environ.get("AWS_CODEPIPELINE_NAME"))
    args = p.parse_args()
    if not args.domain or not args.repository:
        print("ERROR: set AWS_CODEARTIFACT_DOMAIN and AWS_CODEARTIFACT_REPOSITORY (or pass --domain/--repository).")
        sys.exit(1)
    run(args.region, args.domain, args.repository, args.pipeline_name)
