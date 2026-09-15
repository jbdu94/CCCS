# Real Key Vault instead of the local lab's in-memory synthetic token.
# UC4's "token misuse" finding becomes something you can point at real
# Key Vault audit logs afterward - "this secret was accessed from an
# unexpected identity/location" is a real, queryable event here, not a
# logged Python dict entry.

resource "azurerm_key_vault" "main" {
  name                = "${var.name_prefix}-kv"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  enable_rbac_authorization = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

# Private endpoint - matches the architecture diagram; the vault is not
# reachable from the public internet, only from inside the VNet.
resource "azurerm_private_endpoint" "key_vault" {
  name                = "${var.name_prefix}-kv-pe"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "${var.name_prefix}-kv-psc"
    private_connection_resource_id = azurerm_key_vault.main.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
}

resource "azurerm_role_assignment" "agent_kv_secrets_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# The synthetic publish token UC4's attack script reads/misuses. Real
# secret, real Key Vault, real audit trail - the "credential misuse"
# scenario now has something genuine underneath it.
resource "azurerm_key_vault_secret" "publish_token" {
  name         = "publish-token"
  value        = "lab-synthetic-token-${random_id.token_suffix.hex}"
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.agent_kv_secrets_user]
}

resource "random_id" "token_suffix" {
  byte_length = 8
}
