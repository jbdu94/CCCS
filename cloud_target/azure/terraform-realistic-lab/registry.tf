# Azure API Center - the real tool/MCP registry.
#
# HONESTY NOTE, READ BEFORE APPLYING: the resource block below
# (azurerm_api_center_service) is written from the general
# azurerm naming convention (azurerm_<service>_<thing>), NOT verified
# against the live Terraform registry - this lab's build environment had
# no network path to registry.terraform.io to check. API Center is a
# newer Microsoft service (GA 2024), so Terraform support may be recent
# or the exact attribute names may differ from what's below.
#
# Run `terraform validate` first. If this resource doesn't exist or the
# schema doesn't match, use the CLI fallback at the bottom of this file
# instead - those exact `az apic` commands WERE verified against
# Microsoft's current CLI reference (see cloud_target/azure/uc1_registry_attack.py
# in this lab, which already uses them successfully).

resource "azurerm_api_center_service" "main" {
  name                = "${var.name_prefix}-apic"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_role_assignment" "agent_apic_reader" {
  scope                = azurerm_api_center_service.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# -----------------------------------------------------------------------
# CLI FALLBACK - use this instead if the resource above fails validation
# or apply. Comment out the resource block above, then run this from the
# same directory after `terraform apply` has created the resource group:
#
#   az apic create \
#     --resource-group <resource_group_name output> \
#     --name <name_prefix>-apic \
#     --location <location>
#
# This is the exact command shape already proven in
# cloud_target/azure/infra/deploy.sh elsewhere in this lab. If you use
# this path, the AZURE_APIC_NAME value the lab's harness needs is just
# "<name_prefix>-apic" - see CONNECT_THE_LAB.md.
# -----------------------------------------------------------------------
