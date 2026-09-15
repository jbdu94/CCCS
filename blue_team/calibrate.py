"""
Calibration tool — the actual mechanism for "tune against real traffic
before trusting it." Runs the hardened UC1 detector's logic against a
real historical export of tool-registry activity, READ-ONLY: no
quarantine calls, no side effects, nothing written back anywhere. Safe
to point at a real production export.

WHAT YOU NEED TO PROVIDE:
A JSONL file where each line is one historical event, in the same shape
this lab already uses:

    {"event_type": "tool_registered", "use_case": "uc1",
     "details": {"name": "...", "description": "...", "implementation": "...", "actor": "..."}}
    {"event_type": "tool_description_changed", "use_case": "uc1",
     "details": {"name": "...", "old_description": "...", "new_description": "...", "actor": "..."}}
    {"event_type": "tool_called", "use_case": "uc1",
     "details": {"name": "...", "description_at_call_time": "..."}}

If your real registry logs something else (Azure API Center activity
log, AWS CloudTrail for CodeArtifact, your own audit table), the honest
answer is you need a small adapter script that maps YOUR real schema
into this shape — that mapping is specific to your system, not
something this lab can pre-build for you. Once it's in this shape,
everything below works unmodified.

WHAT THIS PRODUCES:
  - How many findings each rule produced across the whole period
  - Which SPECIFIC actors/tools triggered UNAUTHORIZED_ACTOR_CHANGE
    repeatedly - if the same actor shows up 40 times over 30 days and
    every single one was a legitimate release, that's not an attacker,
    that's a missing entry in your approved-actor list
  - A suggested allowlist addition file you review and approve by hand
    before it goes anywhere near the real detector config - this tool
    never edits APPROVED_ACTORS itself
"""
import argparse
import json
import sys
from collections import Counter, defaultdict

sys.path.insert(0, ".")
from uc1_prod_detector import harden_text, SUSPICIOUS_PATTERNS, APPROVED_ACTORS


def load_events(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"WARNING: skipping malformed line {i + 1}: {e}")
    return events


def analyze(events: list[dict]) -> dict:
    registered = {}
    rule_counts = Counter()
    actor_findings = defaultdict(list)  # actor -> [(rule, tool_name), ...]
    tool_findings = defaultdict(list)   # tool_name -> [rule, ...]

    for e in events:
        if e.get("use_case") != "uc1":
            continue
        d = e.get("details", {})
        et = e.get("event_type")

        if et == "tool_registered":
            registered[d.get("name")] = d
            impl = d.get("implementation", "")
            hardened = harden_text(impl)
            hit = next((p for p in SUSPICIOUS_PATTERNS if p in hardened), None)
            if hit:
                rule_counts["SUSPICIOUS_IMPLEMENTATION_PATTERN"] += 1
                tool_findings[d.get("name")].append("SUSPICIOUS_IMPLEMENTATION_PATTERN")
            actor = d.get("actor", "unknown")
            if actor not in APPROVED_ACTORS:
                rule_counts["UNAUTHORIZED_ACTOR_CHANGE"] += 1
                actor_findings[actor].append(("UNAUTHORIZED_ACTOR_CHANGE (register)", d.get("name")))

        elif et == "tool_description_changed":
            rule_counts["POST_APPROVAL_DESCRIPTION_CHANGE"] += 1
            tool_findings[d.get("name")].append("POST_APPROVAL_DESCRIPTION_CHANGE")
            actor = d.get("actor", "unknown")
            if actor not in APPROVED_ACTORS:
                rule_counts["UNAUTHORIZED_ACTOR_CHANGE"] += 1
                actor_findings[actor].append(("UNAUTHORIZED_ACTOR_CHANGE (change)", d.get("name")))

        elif et == "tool_called":
            name = d.get("name")
            original = registered.get(name, {}).get("description")
            at_call = d.get("description_at_call_time")
            if original and at_call and original != at_call:
                rule_counts["TOOL_CALLED_WITH_DRIFTED_DESCRIPTION"] += 1
                tool_findings[name].append("TOOL_CALLED_WITH_DRIFTED_DESCRIPTION")

    REPEAT_THRESHOLD = 5
    candidate_fps = {
        actor: findings for actor, findings in actor_findings.items()
        if len(findings) >= REPEAT_THRESHOLD
    }

    return {
        "total_events": len(events),
        "rule_counts": dict(rule_counts),
        "actor_findings": dict(actor_findings),
        "tool_findings": dict(tool_findings),
        "candidate_false_positives": candidate_fps,
    }


def print_report(result: dict):
    print(f"{'=' * 70}\nCALIBRATION REPORT\n{'=' * 70}")
    print(f"Total UC1 events analyzed: {result['total_events']}\n")

    print("Findings by rule:")
    for rule, count in sorted(result["rule_counts"].items(), key=lambda x: -x[1]):
        print(f"  {count:5d}  {rule}")

    print(f"\n{'-' * 70}")
    if result["candidate_false_positives"]:
        print(f"CANDIDATE FALSE POSITIVES — actors flagged 5+ times "
              f"(review each by hand before trusting this):")
        for actor, findings in sorted(result["candidate_false_positives"].items(),
                                       key=lambda x: -len(x[1])):
            tools = sorted(set(t for _, t in findings))
            print(f"  '{actor}': {len(findings)} findings across {len(tools)} tool(s) — "
                  f"{tools[:5]}{'...' if len(tools) > 5 else ''}")
        print(f"\n  If you confirm these are legitimate, add them to APPROVED_ACTORS in")
        print(f"  blue_team/uc1_baseline-style config yourself — this tool does not edit")
        print(f"  that for you. Every actor added should be a deliberate, reviewed decision.")
    else:
        print("No repeat-offender actors found (nothing crossed the 5-occurrence threshold).")
        print("Either your traffic is genuinely clean, or your sample is too small/short —")
        print("30 days is a floor, not a target. Longer is more trustworthy.")

    print(f"\n{'-' * 70}")
    print("What this report does NOT tell you:")
    print("  - Whether a real attack is hiding among the findings (that still needs a human)")
    print("  - Whether your SUSPICIOUS_IMPLEMENTATION_PATTERN list covers what your real")
    print("    tools actually look like — if legitimate tools in your environment routinely")
    print("    use subprocess/curl/etc. for valid reasons, expect noise there specifically,")
    print("    and consider a narrower, more specific pattern for your environment.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Read-only calibration of the UC1 hardened detector against real historical traffic.")
    p.add_argument("events_file", help="Path to a JSONL file of real historical UC1-shaped events.")
    p.add_argument("--json", action="store_true", help="Output raw JSON instead of the human-readable report.")
    args = p.parse_args()

    events = load_events(args.events_file)
    result = analyze(events)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print_report(result)
