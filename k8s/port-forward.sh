#!/bin/bash
# Convenience wrapper around kubectl port-forward, so the harness on your
# machine can reach the target running in the cluster the same way it
# reaches the local Docker Compose target - via http://localhost:8000.
set -e
NAMESPACE="${K8S_NAMESPACE:-purple-team-lab}"
echo "Forwarding localhost:8000 -> $NAMESPACE/svc/purple-team-target:8000"
echo "Leave this running in its own terminal; Ctrl+C to stop."
kubectl port-forward -n "$NAMESPACE" svc/purple-team-target 8000:8000
