import json
import os
import threading
from datetime import datetime, timezone

LOG_PATH = os.environ.get("EVENT_LOG_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "logs", "events.jsonl"))
_lock = threading.Lock()


def log_event(event_type: str, use_case: str, details: dict) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "use_case": use_case,
        "details": details,
    }
    with _lock:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def reset_log() -> None:
    with _lock:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        open(LOG_PATH, "w", encoding="utf-8").close()


def read_events() -> list[dict]:
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
