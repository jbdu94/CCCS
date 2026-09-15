"""
UC2 (AWS) - Identity Hijacking against a REAL Bedrock AgentCore workload
identity, using boto3's bedrock-agentcore data-plane client's real
GetWorkloadAccessToken operation. Field names verified directly from the
current botocore service model (workloadName in, workloadAccessToken out)
- not guessed.

Requires cloud_target/aws/infra/setup.sh to have been run first, and AWS
credentials with bedrock-agentcore permissions.

Real tokens are requested from the real AgentCore Identity service. What's
simulated is the ATTACK PATTERN layered on top: requesting the same
workload's access token repeatedly in a short window under different
declared source IPs, the way a stolen credential replay would look.
"""
import argparse
import os
import sys
import time

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from cloud_target.event_log import log_event

SIMULATED_SOURCE_IPS = ["10.10.1.4", "198.51.100.23", "203.0.113.77", "45.33.12.9"]


def run(region: str, workload_name: str, agent_id: str):
    client = boto3.client("bedrock-agentcore", region_name=region)

    print(f"[red/uc2/aws] requesting a REAL workload access token for '{workload_name}'...")
    try:
        resp = client.get_workload_access_token(workloadName=workload_name)
        token = resp["workloadAccessToken"]
        print(f"[red/uc2/aws] token acquired ({len(token)} chars).")
    except Exception as e:
        print(f"[red/uc2/aws] token request failed: {e}")
        log_event("identity_access_attempt", "uc2", {
            "agent_id": agent_id, "credential_prefix": "acquisition_failed",
            "target_resource": workload_name, "source_ip": "10.10.1.4",
            "valid_credential": False, "in_scope": False, "error": str(e),
        })
        return

    credential_prefix = f"agentcore-token-{token[:12]}"

    print("[red/uc2/aws] attempt 1: baseline use from expected location...")
    log_event("identity_access_attempt", "uc2", {
        "agent_id": agent_id, "credential_prefix": credential_prefix,
        "target_resource": workload_name, "source_ip": "10.10.1.4",
        "valid_credential": True, "in_scope": True,
    })

    print("[red/uc2/aws] attempt 2: same workload identity's token exercised "
          "rapidly from 4 different simulated source IPs (replay pattern)...")
    for ip in SIMULATED_SOURCE_IPS:
        try:
            client.get_workload_access_token(workloadName=workload_name)
            valid = True
        except Exception:
            valid = False
        log_event("identity_access_attempt", "uc2", {
            "agent_id": agent_id, "credential_prefix": credential_prefix,
            "target_resource": workload_name, "source_ip": ip,
            "valid_credential": valid, "in_scope": valid,
        })
        print(f"[red/uc2/aws]   -> from {ip}: {'ok' if valid else 'failed'}")
        time.sleep(0.2)

    print("[red/uc2/aws] done. All token requests above were real AgentCore Identity calls.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    p.add_argument("--workload-name", default=os.environ.get("AWS_WORKLOAD_NAME"))
    p.add_argument("--agent-id", default="reporting_agent")
    args = p.parse_args()
    if not args.workload_name:
        print("ERROR: set AWS_WORKLOAD_NAME (or pass --workload-name). Comes from cloud_target/aws/infra/setup.sh output.")
        sys.exit(1)
    run(args.region, args.workload_name, args.agent_id)
