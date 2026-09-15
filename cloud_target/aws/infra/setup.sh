#!/bin/bash
# Provisions the real AWS resources for UC1 (AWS Agent Registry) and UC2
# (Bedrock AgentCore workload identity). Uses the AWS CLI directly against
# the agent-registry-control and bedrock-agentcore-control service APIs.
#
# NOTE: these are new (2026) service surfaces. If your AWS CLI version
# predates them, upgrade first (`aws --version` — need a build from
# mid-2026 or later) and confirm with:
#   aws agent-registry-control help
#   aws bedrock-agentcore-control help
# before relying on this in front of an audience.
set -e

REGION="${AWS_REGION:-us-east-1}"
REGISTRY_NAME="${REGISTRY_NAME:-purple-team-lab-registry}"
WORKLOAD_NAME="${WORKLOAD_NAME:-purple-team-lab-agent}"

echo "Creating AWS Agent Registry '$REGISTRY_NAME' in $REGION..."
REGISTRY_OUTPUT=$(aws agent-registry-control create-registry \
  --region "$REGION" \
  --name "$REGISTRY_NAME" \
  --description "Disposable purple team workshop registry - safe to delete after")
echo "$REGISTRY_OUTPUT"
REGISTRY_ID=$(echo "$REGISTRY_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['registryId'])")

echo "Creating Bedrock AgentCore workload identity '$WORKLOAD_NAME'..."
WORKLOAD_OUTPUT=$(aws bedrock-agentcore-control create-workload-identity \
  --region "$REGION" \
  --name "$WORKLOAD_NAME")
echo "$WORKLOAD_OUTPUT"

echo ""
echo "Done. Export these before running the cloud attack/detection scripts:"
echo "  export AWS_REGION=$REGION"
echo "  export AWS_REGISTRY_ID=$REGISTRY_ID"
echo "  export AWS_WORKLOAD_NAME=$WORKLOAD_NAME"
