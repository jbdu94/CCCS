"""
CrowdStrike Falcon connector - genuinely bidirectional.

PUSH: confirmed findings (anomalous source IPs from UC2) get pushed into
Falcon as Custom IOCs via the Custom IOC Management API, so real
endpoints start watching for them.

PULL: recent Falcon detections/alerts are pulled and can be handed to the
AI blue team analyst as extra context - e.g. "does CrowdStrike already
have a detection involving this same host/process around this time?"
This is real EDR signal correlated against our findings, not just our
findings in isolation.

Auth: OAuth2 client credentials (client_id/client_secret from a Falcon
API client with the right scopes: iocs-indicators-of-compromise:write
for push, alerts:read for pull).

NOTE: unlike the Azure/AWS scripts elsewhere in this lab, there is no
local SDK/schema I can validate these payload shapes against from where
this was built (no CrowdStrike SDK installed, no network path to
crowdstrike.com from this sandbox). Field names below follow CrowdStrike's
current public API documentation. Test against your real Falcon tenant
before relying on this live.
"""
import os

import requests

BASE_URL = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")


def _get_token() -> str:
    client_id = os.environ["CROWDSTRIKE_CLIENT_ID"]
    client_secret = os.environ["CROWDSTRIKE_CLIENT_SECRET"]
    resp = requests.post(
        f"{BASE_URL}/oauth2/token",
        data={"client_id": client_id, "client_secret": client_secret},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def push_ip_iocs(ip_addresses: list[str], severity: str = "medium", action: str = "detect",
                  source_label: str = "purple-team-lab") -> dict:
    if not os.environ.get("CROWDSTRIKE_CLIENT_ID"):
        return {"status": "skipped", "reason": "CROWDSTRIKE_CLIENT_ID / CROWDSTRIKE_CLIENT_SECRET not set"}
    try:
        token = _get_token()
    except Exception as e:
        return {"status": "error", "stage": "auth", "error": str(e)}

    indicators = [{
        "type": "ipv4",
        "value": ip,
        "action": action,           # no_action | allow | detect | prevent
        "severity": severity,       # informational | low | medium | high | critical
        "source": source_label,
        "description": "Flagged by purple-team-lab UC2 (anomalous credential replay pattern).",
        "platforms": ["windows", "mac", "linux"],
    } for ip in ip_addresses]

    try:
        resp = requests.post(
            f"{BASE_URL}/iocs/entities/indicators/v1",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"indicators": indicators},
            timeout=15,
        )
        return {"status": "sent" if resp.ok else "error", "http_status": resp.status_code, "body": resp.text[:300]}
    except Exception as e:
        return {"status": "error", "stage": "upload", "error": str(e)}


def pull_recent_alerts(limit: int = 20) -> list[dict]:
    """Pulls recent Falcon alerts for use as enrichment context - e.g.
    passed alongside our own telemetry into the AI SOC analyst's prompt
    so it can correlate. Returns [] on any failure rather than raising,
    since this is enrichment, not a required step."""
    if not os.environ.get("CROWDSTRIKE_CLIENT_ID"):
        return []
    try:
        token = _get_token()
        headers = {"Authorization": f"Bearer {token}"}

        query_resp = requests.get(
            f"{BASE_URL}/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": limit, "sort": "created_timestamp.desc"},
            timeout=10,
        )
        query_resp.raise_for_status()
        alert_ids = query_resp.json().get("resources", [])
        if not alert_ids:
            return []

        detail_resp = requests.post(
            f"{BASE_URL}/alerts/entities/alerts/v2",
            headers={**headers, "Content-Type": "application/json"},
            json={"ids": alert_ids},
            timeout=10,
        )
        detail_resp.raise_for_status()
        return detail_resp.json().get("resources", [])
    except Exception:
        return []
