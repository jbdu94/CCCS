output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.main.name
}

output "aks_get_credentials_command" {
  value = "az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_kubernetes_cluster.main.name}"
}

output "api_center_name" {
  value = azurerm_api_center_service.main.name
}

output "agent_managed_identity_client_id" {
  value = azurerm_user_assigned_identity.agent.client_id
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "container_registry_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "log_analytics_workspace_name" {
  value = azurerm_log_analytics_workspace.main.name
}

output "teardown_command" {
  value = "terraform destroy"
}
