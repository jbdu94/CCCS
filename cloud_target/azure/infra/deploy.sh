#!/bin/bash
# Deploys the purple team lab Azure infrastructure into a dedicated,
# disposable resource group. Requires: az CLI, logged in (`az login`),
# with a subscription selected (`az account set --subscription <id>`).
set -e

RG_NAME="${RG_NAME:-rg-purple-team-lab}"
LOCATION="${LOCATION:-eastus}"

echo "Creating resource group $RG_NAME in $LOCATION..."
az group create --name "$RG_NAME" --location "$LOCATION"

echo "Deploying infrastructure (API Center + managed identity)..."
az deployment group create \
  --resource-group "$RG_NAME" \
  --template-file main.bicep \
  --query "properties.outputs"

echo ""
echo "Done. Export these before running the cloud attack/detection scripts:"
echo "  export AZURE_RESOURCE_GROUP=$RG_NAME"
echo "  export AZURE_APIC_NAME=<apiCenterName from the output above>"
