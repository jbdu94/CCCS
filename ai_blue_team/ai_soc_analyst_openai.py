"""
ai_analyze_openai — the OpenAI equivalent of ai_blue_team/ai_soc_analyst.py's
ai_analyze(), using the Responses API's plain text output (no tools
needed for pure analysis). Same verification status as
pentest_agent_openai.py: request shape checked against the real
installed SDK, not tested against the live API from this environment
(no network path to api.openai.com from where this was built).
"""
import json
import os

import openai

DEFAULT_MODEL = os.environ.get("BLUE_TEAM_MODEL_OPENAI", "gpt-5.6-terra")


def ai_analyze_openai(system_prompt: str, events: list[dict], model: str = DEFAULT_MODEL,
                       external_context: list[dict] | None = None) -> list[dict]:
    client = openai.OpenAI()
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
        response = client.responses.create(
            model=model,
            instructions=system_prompt,
            input=(
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
        )
    except Exception as e:
        return [{"rule": "API_ERROR", "detail": f"AI analysis call failed: {e}", "status": "CLEAN", "confidence": 0.0}]

    text = (response.output_text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return [{"rule": "PARSE_ERROR", "detail": f"model did not return valid JSON: {text[:300]}", "status": "CLEAN", "confidence": 0.0}]
