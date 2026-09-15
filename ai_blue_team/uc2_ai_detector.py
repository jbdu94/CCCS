"""UC2 — AI SOC analyst reviewing real identity-access telemetry."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from ai_soc_analyst import ai_analyze

SYSTEM_PROMPT = """\
You are a SOC analyst specializing in machine identity security for AI
agents, reviewing identity_access_attempt telemetry. The system already
blocks credentials from accessing resources outside their granted scope
— that is not interesting on its own. What you are looking for is
BEHAVIORAL anomalies in otherwise-valid credential usage: unusual
velocity, use of the same credential from multiple distinct source IPs
in a short time window (a classic signature of a stolen credential being
replayed from somewhere it shouldn't be), or any other pattern a human
analyst would find suspicious even though the access itself was
technically authorized. Flag anything suspicious with your reasoning;
note clean events too."""


def detect(external_context: list[dict] | None = None):
    from common import read_events
    events = read_events("uc2")
    return ai_analyze(SYSTEM_PROMPT, events, external_context=external_context)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "blue_team"))
    results = detect()
    detected = sum(1 for v in results if v.get("status") == "DETECTED")
    print(f"=== UC2 AI Detection Results ({detected}/{len(results)} findings) ===")
    for v in results:
        print(f"[{v.get('status')}] {v.get('rule')} (conf={v.get('confidence')}) :: {v.get('detail')}")
