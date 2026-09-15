# Forwards localhost:8010 to the cicd service (Branch A / UC4).
$ErrorActionPreference = "Stop"
$NAMESPACE = if ($env:K8S_NAMESPACE) { $env:K8S_NAMESPACE } else { "purple-team-lab" }
Write-Host "Forwarding localhost:8010 -> $NAMESPACE/svc/cicd:8000"
Write-Host "Leave this running in its own terminal; Ctrl+C to stop."
kubectl port-forward -n $NAMESPACE svc/cicd 8010:8000
