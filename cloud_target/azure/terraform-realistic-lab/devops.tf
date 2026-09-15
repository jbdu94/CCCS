# Azure DevOps resources - real CI/CD attack surface for UC4.
#
# Uses the SEPARATE `microsoft/azuredevops` Terraform provider, not
# azurerm - Azure DevOps is a different control plane from the rest of
# Azure. Needs a Personal Access Token (devops_pat variable), scoped to:
# Project and team (read, write, manage), Build (read and execute),
# Packaging (read, write, manage).
#
# If devops_org_url is left blank (the default), NONE of this file's
# resources get created - create the DevOps project manually in that
# case and skip straight to running cloud_target/azure/uc4_cicd_attack.py
# against it with --organization/--project/--feed set directly.
#
# CONFIDENCE NOTE: same honesty as registry.tf - this was written from
# general knowledge of the azuredevops provider's resource shapes, not
# verified against the live registry from this lab's build environment.
# Validate before applying.

provider "azuredevops" {
  org_service_url       = var.devops_org_url
  personal_access_token = var.devops_pat
}

resource "azuredevops_project" "main" {
  count              = var.devops_org_url != "" ? 1 : 0
  name               = "${var.name_prefix}-supply-chain-lab"
  visibility         = "private"
  version_control    = "Git"
  work_item_template = "Agile"

  description = "Disposable CCCS workshop project - safe to delete after."
}

resource "azuredevops_git_repository" "main" {
  count      = var.devops_org_url != "" ? 1 : 0
  project_id = azuredevops_project.main[0].id
  name       = "internal-tools"

  initialization {
    init_type = "Clean"
  }
}

# Azure Artifacts feed - what UC4's --feed target actually publishes to.
resource "azuredevops_feed" "main" {
  count = var.devops_org_url != "" ? 1 : 0
  name  = "${var.name_prefix}-internal-tools-feed"
}

output "devops_project_name" {
  value = var.devops_org_url != "" ? azuredevops_project.main[0].name : "not created - devops_org_url was blank"
}

output "devops_feed_name" {
  value = var.devops_org_url != "" ? azuredevops_feed.main[0].name : "not created - devops_org_url was blank"
}
