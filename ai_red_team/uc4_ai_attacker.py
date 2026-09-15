"""
UC4 — CI/CD Supply Chain Compromise (AI red team)

A real Claude agent, given tools that map to the cicd service's real API,
decides for itself how to simulate a supply-chain compromise. Unlike
red_team/uc4_cicd_attack.py (fixed sequence), this agent plans its own
approach to achieving the objective - it may order the phases
differently, choose different specific values, or skip a step it
decides isn't necessary.
"""
import argparse
import requests
from pentest_agent import PentestAgent

OBJECTIVE = """\
OBJECTIVE: Demonstrate a CI/CD software supply-chain compromise against
the pipeline at the target below.

You have tools to trigger a workflow, publish a package, record token
usage, and report a persistence marker. Your goal is to simulate an
attacker who has compromised part of this pipeline: an unauthorized
actor triggering a workflow with broader permissions than normal, a
poisoned package published under a plausible-looking identity, a stolen
credential/token being used from an unexpected runner or workflow, and
evidence of a persistence mechanism surviving after the package would
be removed.

You do not know the exact "approved" baseline (real attackers don't
either) - use your judgment about what a legitimate release looks like
versus what would stand out as anomalous, and choose values accordingly
(e.g., an actor name that sounds external/unusual, a runner name that
looks improvised rather than a standard production runner, a hash that
doesn't look like it belongs to a real released version).

When you believe you've demonstrated the compromise, stop calling tools
and summarize what you did and why each step would be suspicious to a
real detector.
"""

TOOLS = [
    {
        "name": "trigger_workflow",
        "description": "Trigger a CI/CD workflow run, as GitHub Actions/GitLab CI would when a commit or manual dispatch fires a pipeline.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "actor": {"type": "string", "description": "Who/what triggered this workflow."},
                "commit_before": {"type": "string"},
                "commit_after": {"type": "string"},
                "permissions_requested": {"type": "array", "items": {"type": "string"}},
                "runner_id": {"type": "string"},
            },
            "required": ["repo", "actor", "commit_before", "commit_after", "runner_id"],
        },
    },
    {
        "name": "publish_package",
        "description": "Publish a package version to the internal registry, as a release job would.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
                "sha256": {"type": "string"},
                "publisher_identity": {"type": "string"},
                "runner_id": {"type": "string"},
            },
            "required": ["name", "version", "sha256", "publisher_identity", "runner_id"],
        },
    },
    {
        "name": "use_token",
        "description": "Record a publishing token being used by a runner for a workflow - simulates the CI system's own token-usage audit trail.",
        "input_schema": {
            "type": "object",
            "properties": {
                "token_id": {"type": "string"},
                "scope": {"type": "string"},
                "used_by_runner": {"type": "string"},
                "workflow_id": {"type": "string"},
            },
            "required": ["token_id", "scope", "used_by_runner", "workflow_id"],
        },
    },
    {
        "name": "report_persistence_marker",
        "description": "Reports that a persistence marker (e.g. a startup hook) was found and executed, as file-integrity monitoring would.",
        "input_schema": {
            "type": "object",
            "properties": {
                "marker": {"type": "string"},
                "location": {"type": "string"},
                "reported_by": {"type": "string"},
            },
            "required": ["marker", "location", "reported_by"],
        },
    },
]


def make_dispatch(base_url: str):
    def dispatch(tool_name: str, tool_input: dict) -> str:
        try:
            if tool_name == "trigger_workflow":
                r = requests.post(f"{base_url}/workflows/trigger", json=tool_input)
            elif tool_name == "publish_package":
                r = requests.post(f"{base_url}/packages/publish", json=tool_input)
            elif tool_name == "use_token":
                r = requests.post(f"{base_url}/tokens/use", json=tool_input)
            elif tool_name == "report_persistence_marker":
                r = requests.post(f"{base_url}/markers/report", json=tool_input)
            else:
                return f"ERROR: unknown tool {tool_name}"
            return f"HTTP {r.status_code}: {r.text}"
        except Exception as e:
            return f"ERROR calling target: {e}"
    return dispatch


def run(base_url: str):
    agent = PentestAgent(tools=TOOLS, dispatch_fn=make_dispatch(base_url))
    result = agent.run(OBJECTIVE)
    print(f"[ai-red/uc4] status={result['status']} turns={result['turns']}")
    for entry in result["transcript"]:
        if entry["type"] == "reasoning":
            print(f"  [turn {entry['turn']}] (reasoning) {entry['text'][:200]}")
        elif entry["type"] == "tool_call":
            print(f"  [turn {entry['turn']}] -> {entry['tool']}({entry['input']})")
        elif entry["type"] == "tool_result":
            print(f"  [turn {entry['turn']}]    <- {entry['result'][:200]}")
        elif entry["type"] == "final":
            print(f"  [turn {entry['turn']}] (final) {entry['text']}")
        elif entry["type"] == "api_error":
            print(f"  [turn {entry['turn']}] (api_error) {entry['text']}")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:8000")
    args = p.parse_args()
    run(args.target)
