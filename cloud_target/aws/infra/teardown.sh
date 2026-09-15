#!/bin/bash
# Destroys the AWS purple team lab resources. Nothing else in your account
# is touched.
set -e
REGION="${AWS_REGION:-us-east-1}"

if [ -n "$AWS_REGISTRY_ID" ]; then
  echo "Deleting registry $AWS_REGISTRY_ID..."
  aws agent-registry-control delete-registry --region "$REGION" --registry-id "$AWS_REGISTRY_ID" || true
fi

if [ -n "$AWS_WORKLOAD_NAME" ]; then
  echo "Deleting workload identity $AWS_WORKLOAD_NAME..."
  aws bedrock-agentcore-control delete-workload-identity --region "$REGION" --name "$AWS_WORKLOAD_NAME" || true
fi

echo "Done. Verify with: aws agent-registry-control list-registries --region $REGION"
