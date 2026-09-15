# Connecting this lab to the real Azure deployment

Once your CCCS contact has run `terraform apply` and sent you the output
values, here's exactly how to point the existing lab code at them. No
new code to write — everything below reuses scripts already built and
tested earlier in this project.

## 1. Get the outputs

Ask for the output of `terraform output` from the deployment. You need:
`resource_group_name`, `api_center_name`, `agent_managed_identity_client_id`,
`key_vault_name`, `container_registry_login_server`,
`aks_get_credentials_command`.

## 2. UC1 — real Azure API Center

```
export AZURE_RESOURCE_GROUP=<resource_group_name>
export AZURE_APIC_NAME=<api_center_name>

cd harness
python run_exercise.py --uc 1 --cloud azure --mode scripted
```

This is the exact same command from earlier in this project — the only
thing that changed is which real API Center instance it's pointed at.

## 3. UC2 — real Entra ID identity

```
python run_exercise.py --uc 2 --cloud azure --mode scripted
```

**One honest nuance worth knowing:** this uses `DefaultAzureCredential`,
which on your laptop picks up *your own* `az login` session — real Entra
ID calls, but not exercising the specific federated managed identity
Terraform created for the AKS workload. To actually test *that* identity
specifically, the script needs to run *from inside* a pod on the new AKS
cluster (where the `agent-runtime` service account is the one federated
to it) — a reasonable next step, not required for a first pass.

## 4. UC4 — real Azure DevOps + real Key Vault

If Terraform created the DevOps project for you:
```
export AZURE_DEVOPS_ORG=https://dev.azure.com/your-org
export AZURE_ARTIFACTS_FEED=<devops_feed_name output>
export AZURE_DEVOPS_PROJECT=<devops_project_name output>

python run_exercise.py --uc 4 --cloud azure --mode scripted
```

Then, separately, exercise the *real* Key Vault credential-misuse path
(this is new — see `cloud_target/azure/uc4_keyvault_credential_misuse.py`):
```
pip install azure-keyvault-secrets
export AZURE_KEY_VAULT_NAME=<key_vault_name output>

cd ../cloud_target/azure
python uc4_keyvault_credential_misuse.py
```

This pulls a *real* secret from a *real* vault, repeatedly, simulating
misuse — check the Key Vault's diagnostic logs in the Log Analytics
workspace Terraform created afterward for genuine `AuditEvent` entries,
not a logged Python dict.

## 5. The gateway architecture, on real AKS

This is the part worth doing even if you don't touch UC1/2/4's cloud
scripts at all — it puts this lab's entire multi-service gateway
architecture (`k8s/services/`: registry, identity, gateway,
agent-runtime, cicd) on a real AKS cluster with real Azure network
policy enforcement, instead of a generic cluster.

```bash
eval $(terraform output -raw aks_get_credentials_command)
# or just run the printed command directly - it's a real `az aks get-credentials` call

cd k8s
./deploy_full_architecture.sh
./port-forward-gateway.sh          # separate terminal

cd ../harness
python run_exercise.py --uc 1 --target http://localhost:8000 --mode scripted
```

No code changes needed for this step — `deploy_full_architecture.sh`
already works against any `kubectl`-configured cluster, and now
`kubectl` is configured to point at real AKS instead of whatever you
were using before.

**Worth trying once you're comfortable:** `kubectl port-forward` straight
to the `registry` service instead of the `gateway`, to confirm Azure's
real network policy enforcement (not just Kubernetes NetworkPolicy)
actually blocks it — same test this lab's `k8s/README.md` already
describes, now against real Azure CNI network policy instead of a
generic cluster's implementation.

## 6. Teardown

When you're done, one command from your CCCS contact removes everything:
```
terraform destroy
```
