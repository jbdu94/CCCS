#!/bin/bash
# Deletes the entire namespace - all four services, NetworkPolicies,
# ServiceAccounts, ConfigMaps, everything - in one command.
set -e
NAMESPACE="${K8S_NAMESPACE:-purple-team-lab}"
echo "Deleting namespace $NAMESPACE (this deletes everything in it)..."
kubectl delete namespace "$NAMESPACE"
echo "Done."
