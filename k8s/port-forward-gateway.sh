#!/bin/bash
# Forwards localhost:8000 to the gateway - the one public entry point in
# this architecture. Point the harness's --target at this address.
set -e
NAMESPACE="${K8S_NAMESPACE:-purple-team-lab}"
echo "Forwarding localhost:8000 -> $NAMESPACE/svc/gateway:8000"
echo "Leave this running in its own terminal; Ctrl+C to stop."
kubectl port-forward -n "$NAMESPACE" svc/gateway 8000:8000
