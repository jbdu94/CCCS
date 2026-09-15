# Deletes the entire namespace - all five services, NetworkPolicies,
# ServiceAccounts, ConfigMaps, everything - in one command.
$ErrorActionPreference = "Stop"
$NAMESPACE = if ($env:K8S_NAMESPACE) { $env:K8S_NAMESPACE } else { "purple-team-lab" }
Write-Host "Deleting namespace $NAMESPACE (this deletes everything in it)..."
kubectl delete namespace $NAMESPACE
Write-Host "Done."
