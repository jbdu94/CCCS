"""
Structured event logging for the registry service.
Every action the registry takes gets written here as one JSON object
per line - this IS the telemetry blue team detectors read.

Every event is hash-chained (seq, prev_hash, hash) so the log is
tamper-evident: editing or deleting a past entry breaks the chain from
that point forward, and verify_chain() will catch it. Ported from
target/logging_utils.py - this file only ever had the older, unstamped
format until now, which is why --prod's AUDIT_CHAIN_INTEGRITY check
against real Kubernetes telemetry reported "0 events" the first time it
ran: the hash-chaining feature was built for the local sandbox target
and never propagated here. Fixed now.
"""
import hashlib
import json
import os
import threading
from datetime import datetime, timezone

LOG_PATH = os.environ.get("EVENT_LOG_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "logs", "events.jsonl"))
_lock = threading.Lock()

GENESIS_HASH = "0" * 64


def _hash_record(seq: int, timestamp: str, event_type: str, use_case: str, details: dict, prev_hash: str) -> str:
    canonical = json.dumps(
        {"seq": seq, "timestamp": timestamp, "event_type": event_type, "use_case": use_case,
         "details": details, "prev_hash": prev_hash},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_hash_and_seq() -> tuple[str, int]:
    events = read_events()
    if not events:
        return GENESIS_HASH, -1
    last = events[-1]
    return last.get("hash", GENESIS_HASH), last.get("seq", -1)


def log_event(event_type: str, use_case: str, details: dict) -> None:
    with _lock:
        prev_hash, prev_seq = _last_hash_and_seq()
        seq = prev_seq + 1
        timestamp = datetime.now(timezone.utc).isoformat()
        record = {
            "seq": seq,
            "timestamp": timestamp,
            "event_type": event_type,
            "use_case": use_case,
            "details": details,
            "prev_hash": prev_hash,
        }
        record["hash"] = _hash_record(seq, timestamp, event_type, use_case, details, prev_hash)
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


def verify_chain() -> dict:
    """Re-walks the whole log and confirms every hash matches what it
    should be given its content and the previous entry's hash. Returns
    {"valid": bool, "checked": int, "broken_at_seq": int|None}."""
    events = read_events()
    prev_hash = GENESIS_HASH
    for i, e in enumerate(events):
        expected = _hash_record(e.get("seq", i), e["timestamp"], e["event_type"], e["use_case"], e["details"], prev_hash)
        if e.get("prev_hash") != prev_hash or e.get("hash") != expected:
            return {"valid": False, "checked": i, "broken_at_seq": e.get("seq", i)}
        prev_hash = e["hash"]
    return {"valid": True, "checked": len(events), "broken_at_seq": None}
