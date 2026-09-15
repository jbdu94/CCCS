"""
Same event schema as target/logging_utils.py, so that the EXISTING
blue_team and ai_blue_team detectors work unchanged whether the telemetry
came from the local sandbox or from real Azure/AWS API calls.
"""
import json
import os
import threading
from datetime import datetime, timezone

LOG_PATH = os.environ.get("EVENT_LOG_PATH", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "events.jsonl"
))
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
