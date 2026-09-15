"""
UC2 — Identity Hijacking (blue team)

Reads the REAL event log. The target already blocks out-of-scope access
at the API layer — that's not what this detector is for. This detector
combines two layers, the way a real detection stack should:

  1. Signature/IOC layer — check source IPs against a known-bad list,
     the way a real SOC would check against threat-intel feeds (this
     lab uses a static example list; a real deployment would source
     this from something like connectors/crowdstrike.py's
     pull_recent_alerts(), or your own blocklist).
  2. Behavioral layer — a VALID, in-scope credential being used in a
     pattern that looks like a stolen credential being replayed
     (velocity + distinct-source-IP spike in a short window), which a
     signature/IOC check alone would miss if the IP itself isn't on
     any list yet.

Catching it on layer 1 (signature) is faster and cheaper when the IP is
already known-bad. Layer 2 (behavioral) is what catches it when the IP
isn't on anyone's list yet — which is the more common real case.
"""
from collections import defaultdict
from datetime import datetime
from common import read_events

VELOCITY_WINDOW_SECONDS = 60.0
MIN_DISTINCT_IPS_FOR_ALERT = 3

# Signature/IOC layer - example known-bad indicators. In this lab, these
# happen to be IPs the UC2 red team's replay attack actually uses - in a
# real deployment this list would be a live threat-intel feed, not a
# hardcoded set (see connectors/crowdstrike.py for a real pull source).
KNOWN_BAD_IPS = {"45.33.12.9", "203.0.113.77"}


def detect():
    events = [e for e in read_events("uc2") if e["event_type"] == "identity_access_attempt"]
    by_credential = defaultdict(list)
    for e in events:
        by_credential[e["details"]["credential_prefix"]].append(e)

    verdicts = []
    for cred, evs in by_credential.items():
        evs.sort(key=lambda e: e["timestamp"])

        # --- Layer 1: signature/IOC match ---
        matched_ips = {e["details"]["source_ip"] for e in evs} & KNOWN_BAD_IPS
        if matched_ips:
            verdicts.append({
                "rule": "KNOWN_BAD_IP_MATCH",
                "credential": cred,
                "detail": f"source IP(s) {sorted(matched_ips)} match known-bad indicators",
                "status": "DETECTED",
            })
        else:
            verdicts.append({
                "rule": "KNOWN_BAD_IP_MATCH",
                "credential": cred,
                "detail": "no source IP matched the known-bad indicator list",
                "status": "CLEAN",
            })

        # --- Layer 2: behavioral (velocity / multi-source) ---
        # Real "impossible travel" / velocity detection in production
        # systems uses windows measured in minutes, not seconds - a
        # 2-second window (the original value here) is fragile against
        # completely ordinary network latency, EDR/antivirus connection
        # inspection, or a slow load balancer, and would miss a real
        # attack just as easily as it missed this lab's own simulated
        # one on a slow connection. Widened to something realistic, and
        # switched from "reset on any gap" (which lets one slow request
        # wipe out everything counted before it) to a proper sliding
        # window: for every event, count distinct IPs in the N seconds
        # following it, and take the largest count seen anywhere in the
        # sequence - order and individual gaps don't matter, only
        # whether N+ distinct IPs ever appear within any real
        # VELOCITY_WINDOW_SECONDS-wide span.
        timestamps = [datetime.fromisoformat(e["timestamp"]) for e in evs]
        max_ips_in_any_window = set()
        for i, anchor in enumerate(timestamps):
            window_ips = {
                evs[j]["details"]["source_ip"]
                for j, t in enumerate(timestamps)
                if 0 <= (t - anchor).total_seconds() <= VELOCITY_WINDOW_SECONDS
            }
            if len(window_ips) > len(max_ips_in_any_window):
                max_ips_in_any_window = window_ips
        ips = max_ips_in_any_window

        if len(ips) >= MIN_DISTINCT_IPS_FOR_ALERT:
            verdicts.append({
                "rule": "CREDENTIAL_MULTI_SOURCE_VELOCITY",
                "credential": cred,
                "detail": f"{len(ips)} distinct source IPs used this credential within "
                          f"{VELOCITY_WINDOW_SECONDS}s — likely replay of a stolen credential",
                "status": "DETECTED",
            })
        else:
            verdicts.append({
                "rule": "CREDENTIAL_MULTI_SOURCE_VELOCITY",
                "credential": cred,
                "detail": f"only {len(ips)} distinct source IP(s) observed, within normal range",
                "status": "CLEAN",
            })

        out_of_scope = [e for e in evs if e["details"]["valid_credential"] and not e["details"]["in_scope"]]
        if out_of_scope:
            verdicts.append({
                "rule": "VALID_CREDENTIAL_OUT_OF_SCOPE_ATTEMPT",
                "credential": cred,
                "detail": f"{len(out_of_scope)} attempt(s) to use a valid credential outside its granted scope "
                          f"(target: {out_of_scope[0]['details']['target_resource']})",
                "status": "DETECTED",
            })

    return verdicts


if __name__ == "__main__":
    results = detect()
    detected = sum(1 for v in results if v["status"] == "DETECTED")
    print(f"=== UC2 Detection Results ({detected}/{len(results)} rules fired) ===")
    for v in results:
        print(f"[{v['status']}] {v['rule']} :: {v['credential']} :: {v['detail']}")
