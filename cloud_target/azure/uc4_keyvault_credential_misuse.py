"""
UC4 Key Vault enhancement - makes "credential misuse" pull a REAL secret
from REAL Azure Key Vault, so the resulting audit trail is something you
can show in Log Analytics afterward, not a logged Python dict entry.

Run this alongside (not instead of) cloud_target/azure/uc4_cicd_attack.py
- that script covers the workflow/package/persistence-marker phases; this
covers the credential-misuse phase against the real vault created by
terraform-realistic-lab/keyvault.tf.

Requires: azure-keyvault-secrets (pip install azure-keyvault-secrets)
alongside the azure-identity dependency this lab already uses.

Verification status: same as the rest of this lab's Azure integration -
uses azure-identity's DefaultAzureCredential, the same real Entra ID
token flow already validated in cloud_target/azure/uc2_identity_attack.py.
Not tested against a live vault from where this was built (no Azure
credentials or network path available there).
"""
import argparse
import os
import sys
import time

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from cloud_target.event_log import log_event


def run(vault_name: str, secret_name: str = "publish-token"):
    vault_url = f"https://{vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)

    print(f"[red/uc4/azure-kv] fetching real secret '{secret_name}' from {vault_url} "
          f"(baseline: normal, expected retrieval)...")
    try:
        secret = client.get_secret(secret_name)
        print(f"[red/uc4/azure-kv]   retrieved, length={len(secret.value)} chars "
              f"(value not printed)")
        log_event("token_used", "uc4", {
            "token_id": secret_name, "scope": "publish:internal-tools",
            "used_by_runner": "runner-prod-01", "workflow_id": "wf-release-001",
        })
    except Exception as e:
        print(f"[red/uc4/azure-kv]   fetch failed: {e}")
        return

    print(f"[red/uc4/azure-kv] re-fetching the SAME secret rapidly, simulating a "
          f"replay/misuse pattern an unexpected caller would produce...")
    for i in range(4):
        try:
            client.get_secret(secret_name)
            log_event("token_used", "uc4", {
                "token_id": secret_name, "scope": "publish:internal-tools",
                "used_by_runner": "runner-temp-99", "workflow_id": "wf-unexpected-999",
            })
        except Exception as e:
            print(f"[red/uc4/azure-kv]   attempt {i+1} failed: {e}")
        time.sleep(0.3)

    print("[red/uc4/azure-kv] done. Check Key Vault's diagnostic logs in the Log Analytics")
    print("workspace this lab's Terraform created (azurerm_monitor_diagnostic_setting.key_vault)")
    print("for the real AuditEvent entries this just generated.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--vault-name", default=os.environ.get("AZURE_KEY_VAULT_NAME"))
    p.add_argument("--secret-name", default="publish-token")
    args = p.parse_args()
    if not args.vault_name:
        print("ERROR: set AZURE_KEY_VAULT_NAME (from terraform output key_vault_name) or pass --vault-name.")
        sys.exit(1)
    run(args.vault_name, args.secret_name)
