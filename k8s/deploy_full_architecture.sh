#!/bin/bash
# Deploys the full four-service architecture (registry, identity,
# gateway, agent-runtime) into your namespace, with NetworkPolicies
# enforcing that registry and identity can only be reached through the
# gateway. No container registry needed - each service's code is
# mounted from a ConfigMap generated fresh from the real source files
# in services/, every time you run this.
set -e

NAMESPACE="${K8S_NAMESPACE:-purple-team-lab}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICES_DIR="$SCRIPT_DIR/services"
MANIFESTS_DIR="$SCRIPT_DIR/manifests"

echo "Using namespace: $NAMESPACE"
echo "kubectl context: $(kubectl config current-context)"
echo ""

echo "1/6 Namespace..."
sed "s/purple-team-lab/$NAMESPACE/" "$MANIFESTS_DIR/00-namespace.yaml" | kubectl apply -f -

echo "2/6 ServiceAccounts..."
sed "s/namespace: purple-team-lab/namespace: $NAMESPACE/" "$MANIFESTS_DIR/01-serviceaccounts.yaml" | kubectl apply -f -

echo "3/6 NetworkPolicies (zero-trust segmentation)..."
sed "s/namespace: purple-team-lab/namespace: $NAMESPACE/" "$MANIFESTS_DIR/02-networkpolicies.yaml" | kubectl apply -f -

echo "4/6 Generating ConfigMaps from real source files in services/..."
for svc in registry identity gateway agent-runtime cicd; do
  echo "  - $svc"
  ARGS=(--namespace "$NAMESPACE" --from-file=app.py="$SERVICES_DIR/$svc/app.py" --from-file=requirements.txt="$SERVICES_DIR/$svc/requirements.txt")
  if [ -f "$SERVICES_DIR/$svc/logging_utils.py" ]; then
    ARGS+=(--from-file=logging_utils.py="$SERVICES_DIR/$svc/logging_utils.py")
  fi
  kubectl create configmap "${svc}-code" "${ARGS[@]}" --dry-run=client -o yaml | kubectl apply -f -
done

echo "5/6 Deployments + Services..."
for f in 03-registry.yaml 04-identity.yaml 05-gateway.yaml 06-agent-runtime.yaml 07-cicd.yaml; do
  sed "s/namespace: purple-team-lab/namespace: $NAMESPACE/" "$MANIFESTS_DIR/$f" | kubectl apply -f -
done

echo "6/6 Waiting for all five to become ready..."
kubectl rollout status deployment/registry -n "$NAMESPACE" --timeout=120s
kubectl rollout status deployment/identity -n "$NAMESPACE" --timeout=120s
kubectl rollout status deployment/gateway -n "$NAMESPACE" --timeout=120s
kubectl rollout status deployment/agent-runtime -n "$NAMESPACE" --timeout=120s
kubectl rollout status deployment/cicd -n "$NAMESPACE" --timeout=120s

echo ""
echo "Deployed. To reach the gateway (the only public entry point) from the harness:"
echo ""
echo "  kubectl port-forward -n $NAMESPACE svc/gateway 8000:8000 &"
echo "  cd ../../harness"
echo "  python run_exercise.py --target http://localhost:8000 --mode scripted"
echo ""
echo "For Branch A (UC4 - CI/CD compromise), forward the cicd service instead:"
echo "  kubectl port-forward -n $NAMESPACE svc/cicd 8010:8000 &"
echo "  python run_exercise.py --uc 4 --target http://localhost:8010 --mode scripted"
echo ""
echo "(or just run: ./port-forward.sh / ./port-forward-cicd.sh)"
echo ""
echo "Try to reach registry directly to confirm the NetworkPolicy is actually enforced:"
echo "  kubectl port-forward -n $NAMESPACE svc/registry 8001:8000 &"
echo "  curl http://localhost:8001/healthz   # should hang or be refused if enforced by your CNI"
