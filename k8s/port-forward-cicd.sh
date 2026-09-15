#!/bin/bash
# Forwards localhost:8010 to the cicd service (Branch A / UC4).
set -e
NAMESPACE="${K8S_NAMESPACE:-purple-team-lab}"
echo "Forwarding localhost:8010 -> $NAMESPACE/svc/cicd:8000"
echo "Leave this running in its own terminal; Ctrl+C to stop."
kubectl port-forward -n "$NAMESPACE" svc/cicd 8010:8000
