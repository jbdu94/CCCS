# Cloud-realistic targets for UC1 and UC2

The local sandbox (`target/`) is fast and free for rehearsal, but it's a
FastAPI toy, not what a director would recognize as "real." This folder
gives UC1 and UC2 a genuine cloud target instead: real managed services,
real API calls, real IAM/identity flows. UC3 has no cloud target - it
stays on the local mock chat agent.

**Why UC1 and UC2 specifically, and why these services:** as of this
year, both major clouds ship purpose-built, GA (or near-GA) services for
exactly the two things these use cases attack - a governed tool/MCP
registry, and agent workload identity. This isn't a stretch to make the
demo look real; it's what's actually being deployed in production.

| Use case | Azure | AWS |
|---|---|---|
| UC1 - registry poisoning | Azure API Center (`az apic`) | AWS Agent Registry (`agent-registry-control`) |
| UC2 - identity hijacking | Microsoft Entra ID managed identity (`azure-identity`) | Bedrock AgentCore Identity (`bedrock-agentcore`) |

**How detection stays unchanged:** every cloud attack script logs to the
exact same `logs/events.jsonl` schema the local sandbox uses. This means
`blue_team/` and `ai_blue_team/` detectors work completely unchanged
against real cloud telemetry - detection logic genuinely doesn't care
whether an event came from a Python toy or a real Azure/AWS API call.

## What's real vs. what's simulated

**Real, no simulation:**
- Every registration, approval, update, and identity/token call is an
  actual API call against the actual service, using field names and
  operations verified directly against the current SDK/CLI at the time
  this was built (not from memory or guesswork - see the note on the
  AWS `UpdateRegistryRecord` shape below).
- Every credential/token requested in UC2 is a real token from real
  Entra ID / AgentCore Identity.

**Simulated, layered on top of real calls:**
- The "attack pattern" itself - e.g., replaying the same credential from
  4 different source IPs in under a second. The token requests
  themselves are real; the "4 different locations" framing is a label
  applied to real, repeated real calls, not a fabricated event.
- UC1's "downstream agent calls the tool" step - the registry itself
  doesn't execute tools, so this step logs the moment an agent *would*
  read and act on the (by-then-poisoned) registry entry.

## A specific bug I found and fixed while building this

AWS's `UpdateRegistryRecord` operation wraps every field - including
deeply nested ones - in a recursive `{"optionalValue": ...}` update-mask
pattern that is completely different from `CreateRegistryRecord`'s plain
shape. I caught this by inspecting the live botocore service model
before shipping the code, not by guessing from documentation prose. If
you extend these scripts, re-run a shape check the same way before
trusting a new field:

```python
import boto3
op = boto3.client("agent-registry-control", region_name="us-east-1") \
    .meta.service_model.operation_model("UpdateRegistryRecord")
print(op.input_shape.members.keys())
```

## Setup

### Azure
```bash
cd cloud_target/azure/infra
az login
./deploy.sh
# export AZURE_RESOURCE_GROUP and AZURE_APIC_NAME from the printed output
```

### AWS
```bash
cd cloud_target/aws/infra
aws configure   # or your usual credential setup
./setup.sh
# export AWS_REGISTRY_ID and AWS_WORKLOAD_NAME from the printed output
```

## Running

From `harness/`, add `--cloud azure` or `--cloud aws` to any UC1/UC2 run
(local UC1/UC2 and all of UC3 are unaffected and keep working exactly as
before):

```bash
python run_exercise.py --uc 1 --cloud azure --mode scripted
python run_exercise.py --uc 2 --cloud aws --mode ai
python run_exercise.py --uc 1 --cloud azure --mode compare --triage
```

In `--mode compare`, the real cloud attack runs ONCE (it costs real API
calls and, for some services, real money - no reason to double it), and
both the scripted and AI detectors are run against that single real
telemetry set.

## Before you present this

- **APIM is deliberately not included.** Azure API Management is the
  real production gateway layer you'd put in front of API Center, but
  its native MCP-server CLI/Bicep surface is new and still moving fast
  at time of writing. Rather than ship you commands I couldn't verify
  precisely, this lab stops at API Center, which is enough to
  demonstrate the full attack/detection loop on its own. Add APIM once
  you've confirmed current syntax against `az apim --help` for your
  subscription's API version.
- **AWS Agent Registry has no Terraform support yet** (checked against
  the AWS provider's open issues) - that's why AWS setup is a CLI
  script, not Terraform, unlike what you might expect from the rest of
  this lab's IaC-first approach.
- Both `agent-registry` and `bedrock-agentcore` are 2026-era service
  surfaces. Confirm your AWS CLI/boto3 and Azure CLI versions are recent
  enough to know about them (`aws agent-registry-control help`,
  `az apic --help`) before you're in front of an audience.
- I validated every call shape against the live, current service models
  and confirmed each one reaches the real API layer (fails only on
  auth/network, never on a malformed request) - but I could not
  provision real Azure/AWS resources or watch a real end-to-end run from
  where this was built, since that environment has no cloud credentials
  or network access to Azure/AWS. Run a full dry run yourself with your
  real credentials before presenting.

## Teardown

```bash
./cloud_target/azure/infra/teardown.sh
./cloud_target/aws/infra/teardown.sh
```
