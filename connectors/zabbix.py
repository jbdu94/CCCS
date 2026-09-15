"""
Zabbix connector - PULL ONLY, same shape as netskope.py and for the same
reason: Zabbix is a monitoring tool, not a security alerting channel.
There's no reason to push our findings into it, and no standard way to.

What this IS good for: pulling real infrastructure signal in as
correlation context for the AI analyst. The concrete case worth having
in mind - a compromised CI runner used to publish a poisoned package
(UC4) may also be running something CPU-intensive it shouldn't be
(cryptomining is the classic example). A CPU utilization spike on the
runner around the same time as a suspicious publish is real
corroborating evidence, the same role CrowdStrike/Netskope alerts play
for UC1-3.

Uses the real Zabbix JSON-RPC API (api_jsonrpc.php), Bearer token auth
(Zabbix 6.4+ - the connector assumes this; older Zabbix expects the
token in the request body instead, not supported here).

Known API gotcha, worth knowing before you build on this: `problem.get`
does not return which host a problem belongs to (no selectHosts option)
- correlating a problem to a host requires a second call to
`trigger.get` with `selectItems`, then reading the item's `hostid`. This
connector does NOT do that correlation - it returns problems and CPU
items as two separate lists, and leaves matching them up to whoever
consumes the enrichment context (the AI analyst can often infer the
connection from timing and hostnames in the raw data; a production
integration would want the extra hop).
"""
import os

import requests

ZABBIX_URL = os.environ.get("ZABBIX_URL")  # e.g. https://zabbix.example.com
ZABBIX_API_TOKEN = os.environ.get("ZABBIX_API_TOKEN")


def _rpc(method: str, params: dict) -> dict | None:
    if not ZABBIX_URL or not ZABBIX_API_TOKEN:
        return None
    try:
        resp = requests.post(
            f"{ZABBIX_URL.rstrip('/')}/api_jsonrpc.php",
            json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
            headers={
                "Content-Type": "application/json-rpc",
                "Authorization": f"Bearer {ZABBIX_API_TOKEN}",
            },
            timeout=10,
        )
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            return None
        return body.get("result")
    except Exception:
        return None


def pull_recent_problems(limit: int = 20) -> list[dict]:
    """Returns [] on any failure or if not configured - this is
    enrichment, not a required step."""
    result = _rpc("problem.get", {
        "output": "extend",
        "recent": "true",
        "sortfield": ["eventid"],
        "sortorder": "DESC",
        "limit": limit,
    })
    return result or []


def pull_cpu_metrics(host_ids: list[str] | None = None, limit: int = 20) -> list[dict]:
    """Returns recent CPU utilization items. Pass host_ids if you know
    which hosts you care about (e.g. your CI runners); omitted, this
    pulls across all hosts the API token can see."""
    params = {
        "output": "extend",
        "search": {"key_": "system.cpu"},
        "sortfield": "name",
        "limit": limit,
    }
    if host_ids:
        params["hostids"] = host_ids
    result = _rpc("item.get", params)
    return result or []
