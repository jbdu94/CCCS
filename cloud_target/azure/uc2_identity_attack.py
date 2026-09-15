"""
UC2 (Azure) - Identity Hijacking against a REAL Azure managed identity,
using the azure-identity SDK's real token-acquisition flow (the same
mechanism documented for authenticating an MCP server with Microsoft
Entra ID managed identity: the agent requests a token scoped to a
resource's Application ID URI, the token's `aud` claim is checked by
whatever validates it downstream).

This requires cloud_target/azure/infra/deploy.sh to have been run, and
either:
  - this script running ON an Azure resource (VM/App Service/Functions)
    that has the managed identity attached, OR
  - AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID set for a
    service principal you're using to simulate the agent locally.

Real tokens are requested from real Entra ID. What's simulated is the
ATTACK PATTERN: requesting the same identity's token/access repeatedly
in a short window with different declared source IPs, the way you would
if you were replaying a stolen credential from multiple locations - this
is layered on top of a real token acquisition, not faked outright.
"""
import argparse
import os
import sys
import time

from azure.identity import DefaultAzureCredential

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from cloud_target.event_log import log_event

SIMULATED_SOURCE_IPS = ["10.10.1.4", "198.51.100.23", "203.0.113.77", "45.33.12.9"]


def request_token(credential: DefaultAzureCredential, resource_scope: str):
    """Real call to Entra ID via the azure-identity SDK."""
    return credential.get_token(resource_scope)


def run(resource_scope: str, agent_id: str):
    credential = DefaultAzureCredential()

    print(f"[red/uc2/azure] requesting a REAL Entra ID token for scope '{resource_scope}'...")
    try:
        token = request_token(credential, resource_scope)
        print(f"[red/uc2/azure] token acquired, expires_on={token.expires_on}")
    except Exception as e:
        print(f"[red/uc2/azure] token request failed: {e}")
        log_event("identity_access_attempt", "uc2", {
            "agent_id": agent_id, "credential_prefix": "acquisition_failed",
            "target_resource": resource_scope, "source_ip": "10.10.1.4",
            "valid_credential": False, "in_scope": False, "error": str(e),
        })
        return

    credential_prefix = f"entra-token-{token.token[:12]}"

    print("[red/uc2/azure] attempt 1: baseline use from expected location...")
    log_event("identity_access_attempt", "uc2", {
        "agent_id": agent_id, "credential_prefix": credential_prefix,
        "target_resource": resource_scope, "source_ip": "10.10.1.4",
        "valid_credential": True, "in_scope": True,
    })

    print("[red/uc2/azure] attempt 2: same token's underlying identity exercised "
          "rapidly from 4 different simulated source IPs (replay pattern)...")
    for ip in SIMULATED_SOURCE_IPS:
        # Re-request to hit the real token cache/issuance path each time,
        # then log the (real) result under a simulated source IP - this
        # models a stolen token being replayed from elsewhere while still
        # exercising the real Entra ID token flow underneath.
        try:
            request_token(credential, resource_scope)
            valid = True
        except Exception:
            valid = False
        log_event("identity_access_attempt", "uc2", {
            "agent_id": agent_id, "credential_prefix": credential_prefix,
            "target_resource": resource_scope, "source_ip": ip,
            "valid_credential": valid, "in_scope": valid,
        })
        print(f"[red/uc2/azure]   -> from {ip}: {'ok' if valid else 'failed'}")
        time.sleep(0.2)

    print("[red/uc2/azure] done. All token requests above were real Entra ID calls.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--resource-scope", default=os.environ.get("AZURE_TOKEN_SCOPE", "https://management.azure.com/.default"),
                    help="The scope/Application ID URI to request a token for, e.g. api://mcp.example.com/.default")
    p.add_argument("--agent-id", default="reporting_agent")
    args = p.parse_args()
    run(args.resource_scope, args.agent_id)
