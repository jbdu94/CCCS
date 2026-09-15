variable "location" {
  description = "Azure region for the lab."
  type        = string
  default     = "canadacentral"
}

variable "resource_group_name" {
  description = "Name of the disposable resource group - everything lives here, one teardown removes it all."
  type        = string
  default     = "rg-purple-team-cccs-lab"
}

variable "name_prefix" {
  description = "Prefix applied to resource names to keep them unique and identifiable."
  type        = string
  default     = "ptcccs"
}

variable "aks_node_count" {
  type    = number
  default = 2
}

variable "aks_vm_size" {
  type    = string
  default = "Standard_B2s"
}

variable "tenant_id" {
  description = "Your Entra tenant ID - required for Key Vault access policy configuration."
  type        = string
}

variable "devops_org_url" {
  description = "Your Azure DevOps organization URL, e.g. https://dev.azure.com/your-org. Leave blank to skip DevOps resource creation (you can create the project manually instead)."
  type        = string
  default     = ""
}

variable "devops_pat" {
  description = "Azure DevOps Personal Access Token with project/pipeline/feed creation rights. Required only if devops_org_url is set. Never commit this - pass via TF_VAR_devops_pat env var."
  type        = string
  default     = ""
  sensitive   = true
}
