"""UC3 — AI SOC analyst reviewing real chat telemetry for credential leaks."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from ai_soc_analyst import ai_analyze

SYSTEM_PROMPT = """\
You are a SOC analyst specializing in DLP for AI chat agents, reviewing
chat_response telemetry. You are looking for any response that leaks a
credential, secret, API key, connection string, or authentication token
— in ANY format, including ones a naive regex would miss: keys with
embedded hyphens or unusual prefixes, secrets described in prose rather
than a clean code block, base64-looking blobs, or connection strings
with credentials embedded in the URL. Judge each response on what it
actually reveals, not on whether it matches a known pattern. Flag
anything suspicious with your reasoning; note clean events too."""


def detect():
    from common import read_events
    events = read_events("uc3")
    return ai_analyze(SYSTEM_PROMPT, events)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "blue_team"))
    results = detect()
    detected = sum(1 for v in results if v.get("status") == "DETECTED")
    print(f"=== UC3 AI Detection Results ({detected}/{len(results)} findings) ===")
    for v in results:
        print(f"[{v.get('status')}] {v.get('rule')} (conf={v.get('confidence')}) :: {v.get('detail')}")
