"""
AI SOC analyst — sends REAL telemetry (the same events.jsonl the scripted
detectors read) to Claude and asks it to reason about what happened,
instead of pattern-matching it. This is the point: a regex only catches
what you thought to write a pattern for; an LLM can catch what "looks
like" a leak or an anomaly semantically, including formats you didn't
anticipate — which is a real, demonstrable gap (see UC3's hyphenated key
that the regex detector missed).
"""
import json
import os
import anthropic

DEFAULT_MODEL = os.environ.get("BLUE_TEAM_MODEL", "claude-sonnet-5")


def ai_analyze(system_prompt: str, events: list[dict], model: str = DEFAULT_MODEL,
                external_context: list[dict] | None = None) -> list[dict]:
    client = anthropic.Anthropic()
    events_json = json.dumps(events, indent=2, default=str)

    context_block = ""
    if external_context:
        context_json = json.dumps(external_context, indent=2, default=str)
        context_block = (
            f"\n\nAdditional external signal pulled from a real EDR/CASB tool for "
            f"correlation (use this to raise or lower your confidence - e.g. a "
            f"matching real alert around the same time/host/IP is corroborating "
            f"evidence, not proof on its own):\n{context_json}"
        )

    try:
        response = client.messages.create(
            model=model,
            max_tokens=2048,
            system=system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"Here is the real event log to analyze:\n\n{events_json}"
                    f"{context_block}\n\n"
                    "Respond with ONLY a JSON array (no prose, no markdown fences) where each "
                    "element has this shape:\n"
                    '{"rule": "<short name you invent for the pattern you found>", '
                    '"detail": "<one sentence explaining your reasoning>", '
                    '"status": "DETECTED" or "CLEAN", '
                    '"confidence": <0.0-1.0>}\n'
                    "Produce at least one verdict per distinct event or closely related group "
                    "of events you examined."
                ),
            }],
        )
    except Exception as e:
        return [{"rule": "API_ERROR", "detail": f"AI analysis call failed: {e}", "status": "CLEAN", "confidence": 0.0}]

    text = "".join(b.text for b in response.content if b.type == "text").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return [{"rule": "PARSE_ERROR", "detail": f"model did not return valid JSON: {text[:300]}", "status": "CLEAN", "confidence": 0.0}]
