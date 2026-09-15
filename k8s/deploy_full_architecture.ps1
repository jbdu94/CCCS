# Deploys the full five-service architecture (registry, identity,
# gateway, agent-runtime, cicd) into your namespace, with NetworkPolicies
# enforcing that registry and identity can only be reached through the
# gateway. No container registry needed - each service's code is
# mounted from a ConfigMap generated fresh from the real source files
# in services/, every time you run this.
#
# PowerShell port of deploy_full_architecture.sh - same steps, same
# output, for environments with no bash/WSL/Git Bash available.

$ErrorActionPreference = "Stop"

$NAMESPACE = if ($env:K8S_NAMESPACE) { $env:K8S_NAMESPACE } else { "purple-team-lab" }
$SCRIPT_DIR = $PSScriptRoot
$SERVICES_DIR = Join-Path $SCRIPT_DIR "services"
$MANIFESTS_DIR = Join-Path $SCRIPT_DIR "manifests"

Write-Host "Using namespace: $NAMESPACE"
Write-Host "kubectl context: $(kubectl config current-context)"
Write-Host ""

Write-Host "1/6 Namespace..."
(Get-Content (Join-Path $MANIFESTS_DIR "00-namespace.yaml") -Raw) -replace "purple-team-lab", $NAMESPACE | kubectl apply -f -
if ($LASTEXITCODE -ne 0) { throw "Failed applying namespace manifest" }

Write-Host "2/6 ServiceAccounts..."
(Get-Content (Join-Path $MANIFESTS_DIR "01-serviceaccounts.yaml") -Raw) -replace "namespace: purple-team-lab", "namespace: $NAMESPACE" | kubectl apply -f -
if ($LASTEXITCODE -ne 0) { throw "Failed applying serviceaccounts manifest" }

Write-Host "3/6 NetworkPolicies (zero-trust segmentation)..."
(Get-Content (Join-Path $MANIFESTS_DIR "02-networkpolicies.yaml") -Raw) -replace "namespace: purple-team-lab", "namespace: $NAMESPACE" | kubectl apply -f -
if ($LASTEXITCODE -ne 0) {
    Write-Warning "NetworkPolicy creation failed - your cluster may restrict this even though pods are allowed."
    Write-Warning "Continuing without network segmentation enforced. Run 'kubectl auth can-i create networkpolicies -n $NAMESPACE' to confirm."
}

Write-Host "4/6 Generating ConfigMaps from real source files in services/..."
$svcList = @("registry", "identity", "gateway", "agent-runtime", "cicd")
foreach ($svc in $svcList) {
    Write-Host "  - $svc"
    $appPath = Join-Path $SERVICES_DIR "$svc\app.py"
    $reqPath = Join-Path $SERVICES_DIR "$svc\requirements.txt"
    $logPath = Join-Path $SERVICES_DIR "$svc\logging_utils.py"

    $cmArgs = @(
        "--namespace", $NAMESPACE,
        "--from-file=app.py=$appPath",
        "--from-file=requirements.txt=$reqPath"
    )
    if (Test-Path $logPath) {
        $cmArgs += "--from-file=logging_utils.py=$logPath"
    }

    kubectl create configmap "$svc-code" @cmArgs --dry-run=client -o yaml | kubectl apply -f -
    if ($LASTEXITCODE -ne 0) { throw "Failed creating configmap for $svc" }
}

Write-Host "5/6 Deployments + Services..."
$manifestFiles = @("03-registry.yaml", "04-identity.yaml", "05-gateway.yaml", "06-agent-runtime.yaml", "07-cicd.yaml")
foreach ($f in $manifestFiles) {
    (Get-Content (Join-Path $MANIFESTS_DIR $f) -Raw) -replace "namespace: purple-team-lab", "namespace: $NAMESPACE" | kubectl apply -f -
    if ($LASTEXITCODE -ne 0) { throw "Failed applying $f" }
}

Write-Host "6/6 Waiting for all five to become ready..."
foreach ($dep in @("registry", "identity", "gateway", "agent-runtime", "cicd")) {
    kubectl rollout status "deployment/$dep" -n $NAMESPACE --timeout=120s
    if ($LASTEXITCODE -ne 0) { throw "Deployment $dep did not become ready in time" }
}

Write-Host ""
Write-Host "Deployed. To reach the gateway (the only public entry point) from the harness:"
Write-Host ""
Write-Host "  kubectl port-forward -n $NAMESPACE svc/gateway 8000:8000"
Write-Host "  (leave that running in its own window, then in another window:)"
Write-Host "  cd ..\harness"
Write-Host "  python run_exercise.py --target http://localhost:8000 --mode scripted"
Write-Host ""
Write-Host "For Branch A (UC4 - CI/CD compromise), forward the cicd service instead:"
Write-Host "  kubectl port-forward -n $NAMESPACE svc/cicd 8010:8000"
Write-Host "  python run_exercise.py --uc 4 --target http://localhost:8010 --mode scripted"
Write-Host ""
Write-Host "Try to reach registry directly to confirm the NetworkPolicy is actually enforced:"
Write-Host "  kubectl port-forward -n $NAMESPACE svc/registry 8001:8000"
Write-Host "  curl http://localhost:8001/healthz   # should hang or be refused if enforced by your CNI"
