#!/bin/bash
# Destroys the entire Azure purple team lab resource group. Nothing about
# this touches any other resource group or subscription resource.
set -e
RG_NAME="${RG_NAME:-rg-purple-team-lab}"
echo "Deleting resource group $RG_NAME (this deletes everything in it)..."
az group delete --name "$RG_NAME" --yes --no-wait
echo "Deletion started. Confirm with: az group show --name $RG_NAME (should eventually 404)"
