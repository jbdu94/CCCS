# Deploying this lab

## What you need before running this

- Terraform >= 1.5.0
- Azure CLI, logged in (`az login`) with Contributor rights on the target subscription
- Your Entra tenant ID: `az account show --query tenantId -o tsv`
- (Optional) An Azure DevOps organization + a Personal Access Token if you want the CI/CD resources created automatically

## Deploy

```bash
cd terraform-realistic-lab
terraform init

# Required
export TF_VAR_tenant_id="<your tenant ID>"

# Optional - only if you want Azure DevOps resources created for you
export TF_VAR_devops_org_url="https://dev.azure.com/your-org"
export TF_VAR_devops_pat="<your PAT>"

terraform validate    # do this BEFORE apply - see the note on API Center below
terraform plan
terraform apply
```

## Before you run `apply` - one thing to check first

`registry.tf` (Azure API Center) was written without access to the live
Terraform registry to verify it against. Run `terraform validate` first.
If it errors on `azurerm_api_center_service`, comment that resource out
and use the CLI fallback documented at the bottom of `registry.tf`
instead - those exact commands are already proven working elsewhere in
this lab.

## What you get

Everything under one resource group (`rg-purple-team-cccs-lab` by
default), with the full output list printed at the end of `apply`:

```
terraform output
```

Send those outputs back - specifically `aks_get_credentials_command`,
`api_center_name`, `agent_managed_identity_client_id`, `key_vault_name`,
and `container_registry_login_server`. That's everything needed to point
the lab's existing code at this deployment.

## Teardown

```bash
terraform destroy
```

One command, removes everything, including the resource group itself.
