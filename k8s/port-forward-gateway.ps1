# Forwards localhost:8000 to the gateway - the one public entry point in
# this architecture. Point the harness's --target at this address.
$ErrorActionPreference = "Stop"
$NAMESPACE = if ($env:K8S_NAMESPACE) { $env:K8S_NAMESPACE } else { "purple-team-lab" }
Write-Host "Forwarding localhost:8000 -> $NAMESPACE/svc/gateway:8000"
Write-Host "Leave this running in its own terminal; Ctrl+C to stop."
kubectl port-forward -n $NAMESPACE svc/gateway 8000:8000
