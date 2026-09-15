"""
Splunk connector - push direction only.

Splunk's HTTP Event Collector (HEC) is the standard way any external tool
feeds Splunk: a token-authenticated POST to /services/collector/event.
This is a stable, long-standing API - not a new 2026 surface like the
cloud identity/registry services elsewhere in this lab.

This forwards our detection VERDICTS (scripted or AI, triaged or not) as
Splunk events, so a real SOC watching a real Splunk instance sees this
lab's findings show up as alerts, the way any other detection source
would feed them.

Usage:
    export SPLUNK_HEC_URL=https://your-splunk:8088/services/collector/event
    export SPLUNK_HEC_TOKEN=xxxx-xxxx-xxxx
    python -c "from connectors.splunk import forward_verdicts; ..."
"""
import json
import os
from datetime import datetime, timezone

import requests


def forward_verdicts(verdicts: list[dict], use_case: str, source: str = "purple-team-lab",
                      sourcetype: str = "purple_team:detection", index: str | None = None) -> dict:
    """POSTs each verdict as a Splunk HEC event. Batches in one request
    (HEC accepts multiple JSON objects concatenated in one POST body)."""
    hec_url = os.environ.get("SPLUNK_HEC_URL")
    hec_token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not hec_url or not hec_token:
        return {"status": "skipped", "reason": "SPLUNK_HEC_URL / SPLUNK_HEC_TOKEN not set"}

    now = datetime.now(timezone.utc).timestamp()
    body_lines = []
    for v in verdicts:
        event = {
            "time": now,
            "source": source,
            "sourcetype": sourcetype,
            "event": {"use_case": use_case, **v},
        }
        if index:
            event["index"] = index
        body_lines.append(json.dumps(event))
    body = "\n".join(body_lines)

    try:
        resp = requests.post(
            hec_url,
            headers={"Authorization": f"Splunk {hec_token}"},
            data=body.encode("utf-8"),
            timeout=10,
            verify=os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() != "false",
        )
        return {"status": "sent" if resp.ok else "error", "http_status": resp.status_code, "body": resp.text[:300]}
    except Exception as e:
        return {"status": "error", "error": str(e)}
