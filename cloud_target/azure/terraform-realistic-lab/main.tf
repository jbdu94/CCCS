terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    # Only needed if you set devops_org_url/devops_pat. Comment out this
    # block (and devops.tf's provider block) if you're skipping the
    # Azure DevOps resources and creating the project manually instead.
    azuredevops = {
      source  = "microsoft/azuredevops"
      version = "~> 0.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    purpose    = "disposable-cccs-security-workshop"
    managed_by = "terraform"
  }
}
