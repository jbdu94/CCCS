// Purple team lab - Azure infrastructure
// Provisions:
//   - Azure API Center (the real, GA enterprise MCP/API registry) for UC1
//   - A User-Assigned Managed Identity + role assignment for UC2
// Everything lives in one resource group so teardown is one command:
//   az group delete --name <rg> --yes --no-wait
//
// NOTE ON SCOPE: Azure API Management (APIM) is the recommended production
// AI Gateway in front of a registry like this (governance, MCP-specific
// policies, versioning - see Azure's June 2026 APIM release notes). Its
// native MCP-server CLI/Bicep surface is new and still evolving quickly at
// time of writing, so it is deliberately NOT included here to avoid
// shipping you Bicep for an API shape that may have changed by the time
// you deploy. API Center alone is sufficient to demonstrate the real
// attack/detection pattern (register -> approve -> rug-pull -> detect).
// Add APIM in front once you've confirmed current syntax against
// `az apim --help` / the Azure docs for your subscription's API version.

@description('Base name used to derive resource names (must be globally unique for API Center).')
param baseName string = 'purpleteamlab${uniqueString(resourceGroup().id)}'

@description('Location for all resources.')
param location string = resourceGroup().location

resource apiCenter 'Microsoft.ApiCenter/services@2024-03-01' = {
  name: baseName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
}

resource workspace 'Microsoft.ApiCenter/services/workspaces@2024-03-01' = {
  parent: apiCenter
  name: 'default'
}

resource agentIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${baseName}-agent-identity'
  location: location
}

// Minimal Reader role on the resource group, scoped tightly - this is the
// identity UC2's red/blue scripts will actually request tokens for and
// exercise, so its permissions should be exactly what you want to test
// blast radius against. Reader is a safe, non-destructive default; change
// the roleDefinitionId if you want to test a more privileged scenario.
resource readerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, agentIdentity.id, 'Reader')
  scope: resourceGroup()
  properties: {
    principalId: agentIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'acdd72a7-3385-48ef-bd42-f606fba81ae7' // built-in Reader role
    )
  }
}

output apiCenterName string = apiCenter.name
output resourceGroupName string = resourceGroup().name
output agentIdentityClientId string = agentIdentity.properties.clientId
output agentIdentityPrincipalId string = agentIdentity.properties.principalId
