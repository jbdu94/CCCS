"""
UC1 — Tool Registry Poisoning (blue team)

Reads the REAL event log produced by the red team script against the live
target. Two independent checks:
  1. Static: does the tool's implementation/description contain
     suspicious patterns (command-execution-shaped strings)?
  2. Behavioral: did the tool's description change AFTER registration,
     with no re-approval event in between (a "rug pull")?
"""
from common import read_events

SUSPICIOUS_PATTERNS = [
    "subprocess", "os.system", "eval(", "exec(", "rm -rf", "cat /etc",
    "curl ", "wget ", "base64 -d", "/dev/tcp",
]


def detect():
    events = read_events("uc1")
    verdicts = []

    registered = {e["details"]["name"]: e for e in events if e["event_type"] == "tool_registered"}
    changes = [e for e in events if e["event_type"] == "tool_description_changed"]
    calls = [e for e in events if e["event_type"] == "tool_called"]

    # Check 1: static pattern match on implementation string
    for name, e in registered.items():
        impl = e["details"]["implementation"]
        desc = e["details"]["description"]
        hit = next((p for p in SUSPICIOUS_PATTERNS if p in impl), None)
        if hit:
            verdicts.append({
                "rule": "SUSPICIOUS_IMPLEMENTATION_PATTERN",
                "tool": name, "detail": f"implementation contains '{hit}'",
                "status": "DETECTED",
            })
        else:
            verdicts.append({
                "rule": "SUSPICIOUS_IMPLEMENTATION_PATTERN",
                "tool": name, "detail": "no suspicious pattern in implementation string",
                "status": "CLEAN",
            })

    # Check 2: rug pull — description changed post-registration
    for e in changes:
        d = e["details"]
        verdicts.append({
            "rule": "POST_APPROVAL_DESCRIPTION_CHANGE",
            "tool": d["name"],
            "detail": f"description changed from '{d['old_description'][:50]}...' to '{d['new_description'][:50]}...'",
            "status": "DETECTED",
        })

    # Check 3: was a tool called using a description that differs from what
    # was originally registered? (catches the rug-pull actually being exploited)
    for e in calls:
        name = e["details"]["name"]
        original = registered.get(name, {}).get("details", {}).get("description")
        at_call = e["details"]["description_at_call_time"]
        if original and at_call != original:
            verdicts.append({
                "rule": "TOOL_CALLED_WITH_DRIFTED_DESCRIPTION",
                "tool": name,
                "detail": "agent acted on a description that differs from the originally-approved one",
                "status": "DETECTED",
            })

    return verdicts


if __name__ == "__main__":
    results = detect()
    detected = sum(1 for v in results if v["status"] == "DETECTED")
    print(f"=== UC1 Detection Results ({detected}/{len(results)} rules fired) ===")
    for v in results:
        print(f"[{v['status']}] {v['rule']} :: {v['tool']} :: {v['detail']}")
