"""
UC2 — Autonomous Identity Hijacking (AI red team)

A real Claude agent with tools to issue and use identity credentials
against the target. It decides on its own how to demonstrate anomalous
credential usage — the target enforces scope, so the interesting part is
what pattern the agent chooses to simulate a stolen credential being
replayed.
"""
import argparse
import requests
from pentest_agent import PentestAgent

OBJECTIVE = """\
OBJECTIVE: Demonstrate an autonomous identity hijacking / machine-identity
abuse attack against the identity service at the target below.

You have tools to issue a scoped credential for an agent identity, and to
use a credential to access a named resource (optionally specifying a
source IP). The target enforces scope — a credential can only access
resources within the scope it was issued.

Your goal is to demonstrate what a compromised, VALID, in-scope
credential being abused looks like at the network level — the kind of
pattern that only behavioral/anomaly detection (not static authorization)
would catch. Think like an attacker who has stolen a legitimate
credential: what would you do with it that a normal, single-location
agent would never do? Issue a credential, then use it in whatever pattern
you believe best demonstrates this (you decide how many times, from how
many different source IPs, how quickly, and whether to also test an
out-of-scope resource). When done, summarize what you did and why it's
suspicious.
"""

TOOLS = [
    {
        "name": "issue_credential",
        "description": "Issue a scoped synthetic credential for an agent identity, as an identity provider would when provisioning a service account for an AI agent.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "scope": {"type": "array", "items": {"type": "string"}, "description": "List of resource names this credential is authorized to access."},
            },
            "required": ["agent_id", "scope"],
        },
    },
    {
        "name": "use_credential",
        "description": "Use a credential to attempt access to a named resource, optionally from a specified source IP (simulate different origins).",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "credential": {"type": "string"},
                "target_resource": {"type": "string"},
                "source_ip": {"type": "string", "description": "Optional simulated source IP for this request."},
            },
            "required": ["agent_id", "credential", "target_resource"],
        },
    },
]


def make_dispatch(base_url: str):
    def dispatch(tool_name: str, tool_input: dict) -> str:
        try:
            if tool_name == "issue_credential":
                r = requests.post(f"{base_url}/identity/issue", json={
                    "agent_id": tool_input["agent_id"],
                    "scope": tool_input["scope"],
                })
            elif tool_name == "use_credential":
                payload = {
                    "agent_id": tool_input["agent_id"],
                    "credential": tool_input["credential"],
                    "target_resource": tool_input["target_resource"],
                }
                if tool_input.get("source_ip"):
                    payload["source_ip"] = tool_input["source_ip"]
                r = requests.post(f"{base_url}/identity/use", json=payload)
            else:
                return f"ERROR: unknown tool {tool_name}"
            return f"HTTP {r.status_code}: {r.text}"
        except Exception as e:
            return f"ERROR calling target: {e}"
    return dispatch


def run(base_url: str):
    agent = PentestAgent(tools=TOOLS, dispatch_fn=make_dispatch(base_url))
    result = agent.run(OBJECTIVE)
    print(f"[ai-red/uc2] status={result['status']} turns={result['turns']}")
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
