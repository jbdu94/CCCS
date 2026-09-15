import json
import os

LOG_PATH = os.environ.get("EVENT_LOG_PATH", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "events.jsonl"))


def read_events(use_case: str | None = None) -> list[dict]:
    if not os.path.exists(LOG_PATH):
        return []
    events = []
    with open(LOG_PATH, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if use_case is None or e["use_case"] == use_case:
                events.append(e)
    return events
