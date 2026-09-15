"""
False-positive triage layer.

The problem with "let AI decide what's a false positive": a single AI
judgment can be wrong, and a wrong judgment here means a real attack
gets silently dismissed. Two safeguards fix that:

1. Self-consistency: ask the model the same question N times (default 3).
   A "false_positive" call is only accepted if ALL N answers agree.
   Disagreement = not trusted either way.

2. Evidence grounding: the model must quote, word for word, the exact
   text from the raw log that justifies its answer. We then check in
   plain code (not trusting the model) that the quote actually appears
   in the raw log. A made-up quote gets rejected.

The original detection verdict is NEVER deleted or hidden by triage —
this module only ADDS a "triage_disposition" on top: confirmed /
false_positive / needs_human_review (the default whenever the model
isn't consistent or grounded). A human always sees the full trail.
"""
import json
import os
import anthropic

DEFAULT_MODEL = os.environ.get("TRIAGE_MODEL", "claude-sonnet-5")
DEFAULT_SAMPLES = int(os.environ.get("TRIAGE_SAMPLES", "3"))

SYSTEM_PROMPT = (
    "You are a second-opinion reviewer for security detections. You will "
    "be shown one detection finding and the raw event log it came from. "
    "Decide whether this is a real (confirmed) finding or a false "
    "positive. You MUST quote, word for word, the exact text from the "
    "raw log that supports your decision. The evidence_quote field must "
    "contain ONLY that exact substring, copied character-for-character "
    "from a field's value in the raw log - no surrounding quotation "
    "marks, no JSON key name, no ellipsis, no explanatory text before or "
    "after it. If you cannot find supporting text, say so and answer "
    "'uncertain' - never invent or paraphrase a quote."
)


def _ask_once(client, model: str, verdict: dict, raw_log_text: str) -> dict:
    try:
        response = client.messages.create(
            model=model,
            max_tokens=500,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": (
                    f"Finding under review:\n{json.dumps(verdict, default=str)}\n\n"
                    f"Raw event log:\n{raw_log_text}\n\n"
                    "Respond with ONLY JSON, no other text: "
                    '{"call": "confirmed"|"false_positive"|"uncertain", '
                    '"evidence_quote": "<exact text copied from the raw log, or empty string if uncertain>", '
                    '"reasoning": "<one sentence>"}'
                ),
            }],
        )
    except Exception as e:
        return {"call": "uncertain", "evidence_quote": "", "reasoning": f"API error: {e}"}

    text = "".join(b.text for b in response.content if b.type == "text").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"call": "uncertain", "evidence_quote": "", "reasoning": "model did not return valid JSON"}


def _flatten_strings(obj) -> list[str]:
    """Recursively extracts every string value from a nested dict/list
    structure. Used for grounding checks instead of comparing against
    json.dumps() output directly - JSON serialization introduces escaping
    and formatting artifacts (\\" for quotes, \\uXXXX for some non-ASCII
    characters, forced indentation) that a model's natural-language quote
    of the real field content would never reproduce, even when the quote
    is completely accurate. Comparing against the real string values
    sidesteps that whole class of false "not grounded" results."""
    strings = []
    if isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_flatten_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            strings.extend(_flatten_strings(v))
    elif isinstance(obj, str):
        strings.append(obj)
    return strings


def _strip_quote_wrapping(quote: str) -> str:
    """Models often wrap a quote in its own quotation marks even when
    told not to, or prefix it with the JSON key name it came from (e.g.
    '"implementation": "cat /etc/passwd..."' instead of just
    'cat /etc/passwd...'). Strips both patterns before grounding-checking,
    since neither changes whether the underlying quote is real."""
    q = quote.strip()
    # Strip a leading `"some_key":` style prefix, if present.
    import re
    q = re.sub(r'^"[a-zA-Z0-9_]+"\s*:\s*', "", q)
    # Strip one layer of surrounding quote characters (straight or curly).
    for open_q, close_q in [('"', '"'), ("'", "'"), (""", """), ("'", "'")]:
        if q.startswith(open_q) and q.endswith(close_q) and len(q) >= 2:
            q = q[1:-1]
            break
    return q.strip()


def _is_grounded(quote: str, raw_events: list[dict], raw_log_text: str) -> bool:
    quote = quote.strip()
    if not quote:
        return False
    candidates = {quote, _strip_quote_wrapping(quote)}
    corpora = ["\n".join(_flatten_strings(raw_events)), raw_log_text]

    for candidate in candidates:
        if not candidate:
            continue
        for corpus in corpora:
            if candidate in corpus:
                return True
            normalize = lambda s: " ".join(s.split())
            if normalize(candidate) in normalize(corpus):
                return True
    return False


def triage(verdict: dict, raw_events: list[dict], model: str = DEFAULT_MODEL, samples: int = DEFAULT_SAMPLES) -> dict:
    """Returns the verdict unchanged, plus a triage_disposition field."""
    if verdict.get("status") != "DETECTED":
        return {**verdict, "triage_disposition": "not_applicable"}

    client = anthropic.Anthropic()
    raw_log_text = json.dumps(raw_events, indent=2, default=str, ensure_ascii=False)

    answers = [_ask_once(client, model, verdict, raw_log_text) for _ in range(samples)]
    calls = [a.get("call") for a in answers]
    quotes = [a.get("evidence_quote", "") or "" for a in answers]
    grounded = [_is_grounded(q, raw_events, raw_log_text) for q in quotes]

    all_agree_false_positive = len(calls) > 0 and all(c == "false_positive" for c in calls)
    all_agree_confirmed = len(calls) > 0 and all(c == "confirmed" for c in calls)
    all_grounded = len(grounded) > 0 and all(grounded)
    any_grounded = any(grounded)

    if all_agree_false_positive and all_grounded:
        disposition = "false_positive"
    elif all_agree_confirmed and any_grounded:
        disposition = "confirmed"
    else:
        # Disagreement between samples, an ungrounded/invented quote, or an
        # "uncertain" answer anywhere in the set -> don't trust it either way.
        disposition = "needs_human_review"

    agreement = f"{calls.count(calls[0]) if calls else 0}/{samples}"
    return {
        **verdict,
        "triage_disposition": disposition,
        "triage_agreement": agreement,
        "triage_grounded": all_grounded,
        "triage_samples": answers,
    }


def triage_all(verdicts: list[dict], raw_events: list[dict], model: str = DEFAULT_MODEL, samples: int = DEFAULT_SAMPLES) -> list[dict]:
    return [triage(v, raw_events, model, samples) for v in verdicts]
