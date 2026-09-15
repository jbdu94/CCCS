#!/bin/bash
# Deploys the purple team target into your own namespace on a Kubernetes
# cluster you have namespace-scoped access to. No container registry
# needed - the app code is mounted in from a ConfigMap generated from
# your actual target/ files, so it's always the code you're really
# testing, never a stale baked-in copy.
set -e

NAMESPACE="${K8S_NAMESPACE:-purple-team-lab}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$SCRIPT_DIR/../target"

echo "Using namespace: $NAMESPACE"
echo "kubectl context: $(kubectl config current-context)"
echo ""

# 1. Namespace (idempotent - fine to re-run)
sed "s/purple-team-lab/$NAMESPACE/" "$SCRIPT_DIR/00-namespace.yaml" | kubectl apply -f -

# 2. ConfigMap generated from the REAL current source files - never
#    hand-edited, never goes stale
echo "Generating ConfigMap from $TARGET_DIR ..."
kubectl create configmap purple-team-target-code \
  --namespace "$NAMESPACE" \
  --from-file=app.py="$TARGET_DIR/app.py" \
  --from-file=logging_utils.py="$TARGET_DIR/logging_utils.py" \
  --from-file=requirements.txt="$TARGET_DIR/requirements.txt" \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Deployment + Service
sed "s/namespace: purple-team-lab/namespace: $NAMESPACE/" "$SCRIPT_DIR/01-deployment.yaml" | kubectl apply -f -
sed "s/namespace: purple-team-lab/namespace: $NAMESPACE/" "$SCRIPT_DIR/02-service.yaml" | kubectl apply -f -

echo ""
echo "Waiting for the target to become ready..."
kubectl rollout status deployment/purple-team-target -n "$NAMESPACE" --timeout=120s

echo ""
echo "Deployed. To reach it from the harness on your machine:"
echo ""
echo "  kubectl port-forward -n $NAMESPACE svc/purple-team-target 8000:8000 &"
echo "  cd ../harness"
echo "  python run_exercise.py --target http://localhost:8000 --mode scripted"
echo ""
echo "(or just run: ./port-forward.sh)"
