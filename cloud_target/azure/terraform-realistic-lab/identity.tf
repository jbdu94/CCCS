# The real version of what UC2 (identity hijacking) tests against. A
# production AKS workload authenticates via Workload Identity Federation
# - no stored secret, a short-lived federated token exchanged for an
# Entra token scoped to whatever this identity has RBAC on. This is the
# actual current recommended pattern (successor to pod-managed
# identities), the same category of mechanism Entra Agent ID uses.

resource "azurerm_user_assigned_identity" "agent" {
  name                = "${var.name_prefix}-agent-identity"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_federated_identity_credential" "agent" {
  name                = "${var.name_prefix}-agent-fic"
  resource_group_name = azurerm_resource_group.main.name
  parent_id           = azurerm_user_assigned_identity.agent.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.main.oidc_issuer_url

  # Matches the Kubernetes ServiceAccount that k8s/services/agent-runtime
  # will run as - adjust the namespace if you deploy this lab's
  # services into a different one than "purple-team-lab".
  subject = "system:serviceaccount:purple-team-lab:agent-runtime-sa"
}

# Minimal Reader role, matching the same "start narrow, widen only if
# you need to test broader blast radius" reasoning as the local lab's
# Bicep template.
resource "azurerm_role_assignment" "agent_reader" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id          = azurerm_user_assigned_identity.agent.principal_id
}
