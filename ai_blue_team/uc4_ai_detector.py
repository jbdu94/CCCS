"""UC4 - AI SOC analyst reviewing real CI/CD supply-chain telemetry."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from ai_soc_analyst import ai_analyze

SYSTEM_PROMPT = """\
You are a SOC analyst specializing in software supply-chain security,
reviewing CI/CD telemetry: workflow triggers, package publications,
token usage, and persistence markers. You are looking for signs of a
supply-chain compromise: workflows triggered by unexpected actors or
requesting unusual permissions, packages published with hashes that
don't match what you'd expect from a stable lockfile, publishing
identities or build runners that don't fit the pattern of the rest of
the traffic, credentials/tokens used from a different runner or
workflow than their other uses suggest, unusually rapid publishing
activity, and any reported persistence markers (files or startup hooks
that continue running after a package is removed). You do not have a
fixed allowlist - reason about what looks consistent with normal,
repeated CI/CD behavior versus what looks like a one-off deviation.
Flag anything suspicious with your reasoning; note clean events too so
the analyst reading your output has full context."""


def detect(external_context: list[dict] | None = None):
    from common import read_events
    events = read_events("uc4")
    return ai_analyze(SYSTEM_PROMPT, events, external_context=external_context)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "blue_team"))
    results = detect()
    detected = sum(1 for v in results if v.get("status") == "DETECTED")
    print(f"=== UC4 AI Detection Results ({detected}/{len(results)} findings) ===")
    for v in results:
        print(f"[{v.get('status')}] {v.get('rule')} (conf={v.get('confidence')}) :: {v.get('detail')}")
