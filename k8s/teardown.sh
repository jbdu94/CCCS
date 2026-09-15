#!/bin/bash
# Deletes the entire namespace - Deployment, Service, ConfigMap, Pod, all
# of it, in one command. Nothing about this touches any other namespace
# in the cluster, and if your lab only granted you access to this one
# namespace, this is the full extent of what you can (and need to) clean
# up.
set -e
NAMESPACE="${K8S_NAMESPACE:-purple-team-lab}"
echo "Deleting namespace $NAMESPACE (this deletes everything in it)..."
kubectl delete namespace "$NAMESPACE"
echo "Done."
