"""
Netskope connector - PULL ONLY. Read this before wiring it in.

Netskope's REST API v2 lets you read DLP/CASB/UBA alerts
(GET /api/v2/events/dataexport/events/alert with a Netskope-API-Token
header) - that part is real and documented.

There is deliberately NO push_* function in this file. Netskope does not
expose a public third-party-facing endpoint for injecting a custom alert
into their platform the way Splunk's HEC or CrowdStrike's Custom IOC API
do. Netskope's own outbound integration tool is called Cloud
Exchange / Log Shipper, and it pushes Netskope's alerts OUT to other
tools (Splunk, Elastic, Azure Log Analytics, etc.) - it is not a channel
for us to push INTO Netskope. If someone asks "can we send our findings
to Netskope," the honest answer is no, not through their public API -
only into whatever downstream tool your Netskope Cloud Exchange instance
is already configured to forward to (e.g. push to Splunk instead, and
let your existing Netskope-to-Splunk pipeline carry it from there).

What this DOES give you: real Netskope DLP/CASB alerts pulled in as
enrichment context for the AI blue team analyst, the same pattern as the
CrowdStrike pull side.
"""
import os

import requests


def pull_recent_alerts(alert_type: str = "dlp", limit: int = 20) -> list[dict]:
    """alert_type: one of Netskope's content types, e.g. dlp, malware,
    policy, compromisedcredential, malsite, securityassessment, uba.
    Returns [] on any failure rather than raising - enrichment, not a
    required step."""
    tenant_hostname = os.environ.get("NETSKOPE_TENANT_HOSTNAME")  # e.g. mytenant.goskope.com
    api_token = os.environ.get("NETSKOPE_API_TOKEN")
    if not tenant_hostname or not api_token:
        return []

    try:
        resp = requests.get(
            f"https://{tenant_hostname}/api/v2/events/dataexport/events/alert",
            headers={"Netskope-API-Token": api_token},
            params={"type": alert_type, "limit": limit},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("result", [])
    except Exception:
        return []
