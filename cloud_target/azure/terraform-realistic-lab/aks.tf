# Runs this lab's existing k8s/services/ (registry, identity, gateway,
# agent-runtime, cicd) for real. Same deploy_full_architecture.sh and
# manifests/ from this lab work against this cluster unmodified - see
# CONNECT_THE_LAB.md for the exact steps once this is up.

resource "azurerm_kubernetes_cluster" "main" {
  name                = "${var.name_prefix}-aks"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "${var.name_prefix}-aks"

  default_node_pool {
    name           = "default"
    node_count     = var.aks_node_count
    vm_size        = var.aks_vm_size
    vnet_subnet_id = azurerm_subnet.aks.id
  }

  identity {
    type = "SystemAssigned"
  }

  # Required for the Workload Identity Federation pattern in identity.tf
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  # Azure CNI + network policy = the real enforcement layer behind the
  # NetworkPolicy manifests in k8s/manifests/02-networkpolicies.yaml.
  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }

  tags = {
    purpose = "disposable-cccs-security-workshop"
  }
}
