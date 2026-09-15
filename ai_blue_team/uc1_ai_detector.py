"""UC1 — AI SOC analyst reviewing real tool-registry telemetry.

Provider is chosen by the LLM_PROVIDER env var ("anthropic" or "openai",
default "anthropic") - set by --llm-provider on the harness."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic")
if PROVIDER == "openai":
    from ai_soc_analyst_openai import ai_analyze_openai as ai_analyze
else:
    from ai_soc_analyst import ai_analyze

SYSTEM_PROMPT = """\
You are a SOC analyst specializing in AI agent supply-chain security,
reviewing tool-registry telemetry for an enterprise running AI agents
with MCP-style tool registries. You are looking for signs of tool
poisoning: implementations that could execute unauthorized commands,
descriptions that changed after initial registration ("rug pulls"), and
tools being called under a description that differs from what was
originally approved. Flag anything suspicious with your reasoning; note
clean events too so the analyst reading your output has full context."""


def detect(external_context: list[dict] | None = None):
    from common import read_events
    events = read_events("uc1")
    return ai_analyze(SYSTEM_PROMPT, events, external_context=external_context)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "blue_team"))
    results = detect()
    detected = sum(1 for v in results if v.get("status") == "DETECTED")
    print(f"=== UC1 AI Detection Results ({detected}/{len(results)} findings) ===")
    for v in results:
        print(f"[{v.get('status')}] {v.get('rule')} (conf={v.get('confidence')}) :: {v.get('detail')}")
