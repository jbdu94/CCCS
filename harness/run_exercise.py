"""
Purple team harness — three modes:

  scripted  — deterministic Python attack + regex/rule-based detection
              (fast, free, no API key needed — good for rehearsal)
  ai        — a real Claude tool-calling agent plans and executes the
              attack against the live target; a real Claude SOC analyst
              reasons over the resulting telemetry (needs ANTHROPIC_API_KEY)
  compare   — runs BOTH back-to-back for the same use case and prints a
              side-by-side comparison — this is the demo mode

Usage:
    python run_exercise.py --uc 1 --mode scripted
    python run_exercise.py --uc 1 --mode ai
    python run_exercise.py --uc 1 --mode compare
    python run_exercise.py --uc all --mode compare
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)  # for connectors/

for sub in ("blue_team", "red_team", "ai_red_team", "ai_blue_team"):
    sys.path.insert(0, os.path.join(ROOT, sub))

UC_CONFIG = {
    "1": {
        "name": "UC1 - AI Agent Supply Chain Poisoning",
        "scripted_red": os.path.join(ROOT, "red_team", "uc1_supply_chain_attack.py"),
        "scripted_blue": os.path.join(ROOT, "blue_team", "uc1_tool_registry_detector.py"),
        "prod_blue": os.path.join(ROOT, "blue_team", "uc1_prod_detector.py"),
        "ai_red": os.path.join(ROOT, "ai_red_team", "uc1_ai_attacker.py"),
        "ai_blue": os.path.join(ROOT, "ai_blue_team", "uc1_ai_detector.py"),
    },
    "2": {
        "name": "UC2 - Autonomous Identity Hijacking",
        "scripted_red": os.path.join(ROOT, "red_team", "uc2_identity_hijack_attack.py"),
        "scripted_blue": os.path.join(ROOT, "blue_team", "uc2_identity_anomaly_detector.py"),
        "ai_red": os.path.join(ROOT, "ai_red_team", "uc2_ai_attacker.py"),
        "ai_blue": os.path.join(ROOT, "ai_blue_team", "uc2_ai_detector.py"),
    },
    "3": {
        "name": "UC3 - Prompt-Based Credential Harvesting",
        "scripted_red": os.path.join(ROOT, "red_team", "uc3_credential_harvest_attack.py"),
        "scripted_blue": os.path.join(ROOT, "blue_team", "uc3_credential_leak_detector.py"),
        "ai_red": os.path.join(ROOT, "ai_red_team", "uc3_ai_attacker.py"),
        "ai_blue": os.path.join(ROOT, "ai_blue_team", "uc3_ai_detector.py"),
    },
    "4": {
        "name": "UC4 - CI/CD Supply Chain Compromise (Branch A)",
        "scripted_red": os.path.join(ROOT, "red_team", "uc4_cicd_attack.py"),
        "scripted_blue": os.path.join(ROOT, "blue_team", "uc4_cicd_detector.py"),
        "ai_red": os.path.join(ROOT, "ai_red_team", "uc4_ai_attacker.py"),
        "ai_blue": os.path.join(ROOT, "ai_blue_team", "uc4_ai_detector.py"),
    },
}


CLOUD_ATTACK_SCRIPTS = {
    "azure": {
        "1": os.path.join(ROOT, "cloud_target", "azure", "uc1_registry_attack.py"),
        "2": os.path.join(ROOT, "cloud_target", "azure", "uc2_identity_attack.py"),
        "4": os.path.join(ROOT, "cloud_target", "azure", "uc4_cicd_attack.py"),
    },
    "aws": {
        "1": os.path.join(ROOT, "cloud_target", "aws", "uc1_registry_attack.py"),
        "2": os.path.join(ROOT, "cloud_target", "aws", "uc2_identity_attack.py"),
        "4": os.path.join(ROOT, "cloud_target", "aws", "uc4_cicd_attack.py"),
    },
}


def load_module(path: str, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reset_target(target_url: str):
    try:
        requests.post(f"{target_url}/admin/reset", timeout=10).raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"\nERROR: could not reach the target at {target_url} ({e})")
        print("Is the target actually running? Start it first:")
        print("  docker compose up -d --build")
        print("  curl http://localhost:8000/healthz   (should return immediately)")
        sys.exit(1)


def sync_remote_logs(target_url: str):
    """Fetches the real events the target has logged over HTTP and
    writes them to the local event log so blue team detection - which
    reads a local file - can see them.

    This is now UNCONDITIONAL, not just for targets that "look" remote.
    It used to skip this for any URL containing 'localhost' or
    '127.0.0.1', on the assumption that a local hostname meant a local
    filesystem-sharing target. That assumption breaks for Kubernetes:
    `kubectl port-forward` always presents as localhost:PORT to the
    client, even though the actual target is a remote pod that shares
    no filesystem with the harness at all - the old logic would have
    silently skipped syncing real telemetry from a K8s-deployed gateway.
    Always fetching is safe: the local Docker target also implements
    /admin/logs, so this is a harmless redundant round-trip there,
    and the only way to be correct for every target type without
    having to guess."""
    try:
        resp = requests.get(f"{target_url}/admin/logs", timeout=10)
        resp.raise_for_status()
        events = resp.json().get("events", [])
        log_path = os.environ.get("EVENT_LOG_PATH", os.path.join(ROOT, "logs", "events.jsonl"))
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        print(f"    [sync] pulled {len(events)} real event(s) from target")
    except Exception as e:
        print(f"    [sync] WARNING: could not fetch logs from target ({e}) - "
              f"detection below will see an empty/stale log")


def pull_enrichment_context(enrich_crowdstrike: bool, enrich_netskope: bool, enrich_zabbix: bool = False) -> list[dict]:
    context = []
    if enrich_crowdstrike:
        from connectors.crowdstrike import pull_recent_alerts as cs_pull
        alerts = cs_pull(limit=10)
        print(f"    [enrich] CrowdStrike: pulled {len(alerts)} recent alert(s) for correlation"
              if alerts else "    [enrich] CrowdStrike: no alerts pulled (not configured, or none found)")
        context.extend([{"source": "crowdstrike", **a} for a in alerts])
    if enrich_netskope:
        from connectors.netskope import pull_recent_alerts as ns_pull
        alerts = ns_pull(alert_type="dlp", limit=10)
        print(f"    [enrich] Netskope: pulled {len(alerts)} recent DLP alert(s) for correlation"
              if alerts else "    [enrich] Netskope: no alerts pulled (not configured, or none found)")
        context.extend([{"source": "netskope", **a} for a in alerts])
    if enrich_zabbix:
        from connectors.zabbix import pull_recent_problems, pull_cpu_metrics
        problems = pull_recent_problems(limit=10)
        cpu_items = pull_cpu_metrics(limit=10)
        print(f"    [enrich] Zabbix: pulled {len(problems)} problem(s) and {len(cpu_items)} CPU item(s) for correlation"
              if (problems or cpu_items) else "    [enrich] Zabbix: nothing pulled (not configured, or none found)")
        context.extend([{"source": "zabbix_problem", **p} for p in problems])
        context.extend([{"source": "zabbix_cpu_item", **i} for i in cpu_items])
    return context


def maybe_forward_to_splunk(verdicts: list[dict], uc_key: str, forward: bool):
    if not forward:
        return
    from connectors.splunk import forward_verdicts
    result = forward_verdicts(verdicts, use_case=f"uc{uc_key}")
    extra = f" ({result['reason']})" if "reason" in result else f" (http {result.get('http_status')})" if "http_status" in result else ""
    print(f"    [forward->splunk] {result.get('status')}{extra}")


def rule_set_hash(path: str) -> str:
    """Sha256 of the detector source actually being used this run - so a
    silent edit to the ruleset is visible/auditable, per the 'version and
    review the ruleset like the security control it is' recommendation."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def run_prod_self_test(blue_path: str):
    """Actually calls the hardened detector's self_test() every --prod
    run - not just when someone happens to run the detector file
    standalone. This is 'red-team the detector, not just the target' as
    real, always-on code. Returns None if this detector doesn't expose
    a self_test() (only uc1_prod_detector.py does right now)."""
    mod = load_module(blue_path, "prod_self_test_check")
    if not hasattr(mod, "self_test"):
        return None
    result = mod.self_test()
    print(f"    [prod] self-test — homoglyph bypass defeated: {result['homoglyph_defeated']}, "
          f"multiline bypass defeated: {result['multiline_defeated']}")
    if not result["all_passed"]:
        print("    [prod] WARNING: hardening self-test FAILED — findings below should not be trusted "
              "until this is fixed")
    return result


def auto_quarantine_on_detection(target_url: str, verdicts: list[dict]) -> list[str]:
    """After detection, quarantines any tool with a confirmed unauthorized
    description change, so at least the NEXT call is blocked.

    Be precise about what this is NOT: this is auto-containment AFTER a
    detection pass, not the K8s gateway's true inline prevention (which
    blocks a bad change before it ever takes effect, in the request path
    itself). In this lab's own attack sequence, the malicious call
    already happened once before this runs - this stops it from
    happening again, it does not undo the first one. Real, but a
    genuinely weaker guarantee, and reported as exactly that."""
    tools_to_quarantine = {
        v["tool"] for v in verdicts
        if v.get("status") == "DETECTED"
        and v.get("rule") == "POST_APPROVAL_DESCRIPTION_CHANGE"
        and v.get("tool") not in (None, "-")
    }
    quarantined = []
    for name in tools_to_quarantine:
        try:
            resp = requests.post(f"{target_url}/tools/{name}/quarantine",
                                  params={"reason": "auto-quarantined by --prod after an unauthorized description change was detected"},
                                  timeout=10)
            if resp.ok:
                quarantined.append(name)
                print(f"    [prod] auto-quarantined tool '{name}' — future calls to it will now be blocked (403)")
        except Exception as e:
            print(f"    [prod] WARNING: could not quarantine '{name}' ({e})")
    return quarantined


def run_pass(uc_key: str, target_url: str, engine: str, triage_enabled: bool = False,
             enrich_crowdstrike: bool = False, enrich_netskope: bool = False,
             forward_splunk: bool = False, enrich_zabbix: bool = False, prod: bool = False) -> dict:
    """engine: 'scripted' or 'ai'"""
    cfg = UC_CONFIG[uc_key]
    reset_target(target_url)

    red_path = cfg["scripted_red"] if engine == "scripted" else cfg["ai_red"]
    if prod and engine == "scripted" and "prod_blue" in cfg:
        blue_path = cfg["prod_blue"]
    else:
        blue_path = cfg["scripted_blue"] if engine == "scripted" else cfg["ai_blue"]
        if prod and engine == "scripted":
            print(f"    [prod] WARNING: no hardened prod detector exists yet for UC{uc_key} - "
                  f"falling back to the standard scripted detector")

    print(f"\n--- [{engine.upper()}] red team executing against live target ---")
    red = load_module(red_path, f"{engine}_red_uc{uc_key}")
    t0 = time.time()
    red.run(target_url)
    attack_time = time.time() - t0

    os.environ["EVENT_LOG_PATH"] = os.path.join(ROOT, "logs", "events.jsonl")
    sync_remote_logs(target_url)

    if prod:
        print(f"\n    [prod] rule set: {os.path.basename(blue_path)}  sha256={rule_set_hash(blue_path)}")
        self_test_result = run_prod_self_test(blue_path)
    else:
        self_test_result = None

    print(f"\n--- [{engine.upper()}] blue team analyzing real resulting telemetry ---")
    blue = load_module(blue_path, f"{engine}_blue_uc{uc_key}")
    t0 = time.time()
    if engine == "ai" and (enrich_crowdstrike or enrich_netskope or enrich_zabbix):
        context = pull_enrichment_context(enrich_crowdstrike, enrich_netskope, enrich_zabbix)
        verdicts = blue.detect(external_context=context or None)
    else:
        verdicts = blue.detect()
    detect_time = time.time() - t0

    detected = sum(1 for v in verdicts if v.get("status") == "DETECTED")
    print(f"\n[{engine.upper()}] verdict: {detected}/{len(verdicts)} findings, "
          f"attack {attack_time:.2f}s, detection {detect_time:.2f}s")
    for v in verdicts:
        marker = "OK" if v.get("status") == "DETECTED" else "--"
        conf = f" (conf={v['confidence']})" if "confidence" in v else ""
        print(f"    [{marker}] {v.get('rule')}{conf} :: {v.get('detail')}")

    triage_results = None
    if triage_enabled:
        from fp_triage import triage_all
        from common import read_events
        raw_events = read_events(f"uc{uc_key}")
        print(f"\n--- [TRIAGE] reviewing {detected} DETECTED finding(s), "
              f"{os.environ.get('TRIAGE_SAMPLES', '3')} samples each, evidence-grounded ---")
        triage_results = triage_all(verdicts, raw_events)
        for v in triage_results:
            if v.get("triage_disposition") == "not_applicable":
                continue
            print(f"    [{v['triage_disposition'].upper()}] agreement={v['triage_agreement']} "
                  f"grounded={v['triage_grounded']} :: {v.get('rule')}")
            if not v['triage_grounded'] and os.environ.get("TRIAGE_DEBUG"):
                for i, sample in enumerate(v.get("triage_samples", [])):
                    print(f"        sample {i+1}: call={sample.get('call')!r} "
                          f"evidence_quote={sample.get('evidence_quote')!r} "
                          f"reasoning={sample.get('reasoning')!r}")

    maybe_forward_to_splunk(triage_results or verdicts, uc_key, forward_splunk)

    quarantined = []
    if prod and uc_key == "1":
        quarantined = auto_quarantine_on_detection(target_url, verdicts)

    if prod:
        print_production_readiness(uc_key, engine, verdicts, triage_enabled, forward_splunk,
                                    self_test_result, quarantined)

    return {
        "engine": engine, "detected": detected, "total": len(verdicts),
        "attack_time": attack_time, "detect_time": detect_time,
        "triage": triage_results,
    }


def print_production_readiness(uc_key: str, engine: str, verdicts: list[dict],
                                 triage_enabled: bool, forward_splunk: bool,
                                 self_test_result: dict | None = None, quarantined: list[str] | None = None):
    """Honest checklist against the report's own 'making this
    production-ready' recommendations. Split into two groups: things
    that can actually be code (checked below, pass/fail), and things
    that fundamentally can't be - tuning against real traffic needs
    real traffic this lab doesn't have, and reviewing a rule change is
    a human process, not a script. Those are named, not faked into a
    checkbox."""
    quarantined = quarantined or []
    chain_verdict = next((v for v in verdicts if v.get("rule") == "AUDIT_CHAIN_INTEGRITY"), None)
    actor_checks_present = any(v.get("rule") == "UNAUTHORIZED_ACTOR_CHANGE" for v in verdicts)

    print(f"\n{'=' * 70}\nPRODUCTION READINESS — UC{uc_key} [{engine}]\n{'=' * 70}")

    def line(ok: bool, label: str, note: str):
        print(f"  [{'x' if ok else ' '}] {label}{'' if ok else '  <- ' + note}")

    print("  -- code-checkable --")
    if self_test_result is not None:
        line(self_test_result["all_passed"],
             "Hardened signature check — self-tested against this lab's own bypasses this run",
             "SELF-TEST FAILED — hardening is not actually closing the known bypasses right now")
    else:
        line(False, "Hardened signature check", "no self-test available for this detector")
    line(chain_verdict is not None, "Tamper-evident audit chain checked",
         "target isn't logging with hash-chained events yet")
    if chain_verdict is not None:
        line(chain_verdict.get("status") == "CLEAN", "Audit chain verified intact",
             "CHAIN BROKEN — treat every other finding this run as unverifiable")
    line(actor_checks_present, "Actor tracked on registration/change events",
         "no actor field present in this run's events")
    line(triage_enabled, "AI false-positive triage active",
         "run with --triage (needs ANTHROPIC_API_KEY)")
    line(forward_splunk, "Findings forwarded to SIEM",
         "run with --forward-splunk (needs SPLUNK_HEC_URL/TOKEN)")
    line(bool(quarantined), "Auto-containment: unauthorized changes quarantined after detection",
         "no tool needed quarantining this run" if chain_verdict is not None else "not applicable")
    if quarantined:
        print(f"      quarantined: {', '.join(quarantined)} — future calls to these will 403 "
              f"until manually cleared. This is CONTAINMENT after detection, not the K8s "
              f"gateway's true inline PREVENTION (which blocks a bad change before it ever "
              f"takes effect) — the first malicious call in this run's sequence already happened "
              f"before this fired.")

    print("  -- not code, can't be checked here --")
    print("      Tuning the signature check against 30+ days of real traffic needs real")
    print("      traffic this lab doesn't have. Run it read-only in your environment first.")
    print("      Reviewing a rule-set change is a human process. The sha256 above makes an")
    print("      undisclosed edit visible; it doesn't replace someone approving the edit.")
    print()


def run_cloud_attack(uc_key: str, cloud: str):
    """Dispatches to the right cloud_target script's run() with env-sourced args."""
    script_path = CLOUD_ATTACK_SCRIPTS[cloud][uc_key]
    mod = load_module(script_path, f"cloud_{cloud}_uc{uc_key}")

    if cloud == "azure" and uc_key == "1":
        rg, apic = os.environ.get("AZURE_RESOURCE_GROUP"), os.environ.get("AZURE_APIC_NAME")
        if not rg or not apic:
            raise RuntimeError("Set AZURE_RESOURCE_GROUP and AZURE_APIC_NAME (from cloud_target/azure/infra/deploy.sh output).")
        mod.run(rg, apic)
    elif cloud == "azure" and uc_key == "2":
        scope = os.environ.get("AZURE_TOKEN_SCOPE", "https://management.azure.com/.default")
        agent_id = os.environ.get("AZURE_AGENT_ID", "reporting_agent")
        mod.run(scope, agent_id)
    elif cloud == "azure" and uc_key == "4":
        organization = os.environ.get("AZURE_DEVOPS_ORG")
        project = os.environ.get("AZURE_DEVOPS_PROJECT")
        feed = os.environ.get("AZURE_ARTIFACTS_FEED")
        pipeline_name = os.environ.get("AZURE_PIPELINE_NAME")
        if not organization or not feed:
            raise RuntimeError("Set AZURE_DEVOPS_ORG and AZURE_ARTIFACTS_FEED.")
        mod.run(organization, project, feed, pipeline_name)
    elif cloud == "aws" and uc_key == "1":
        region = os.environ.get("AWS_REGION", "us-east-1")
        registry_id = os.environ.get("AWS_REGISTRY_ID")
        if not registry_id:
            raise RuntimeError("Set AWS_REGISTRY_ID (from cloud_target/aws/infra/setup.sh output).")
        mod.run(region, registry_id)
    elif cloud == "aws" and uc_key == "2":
        region = os.environ.get("AWS_REGION", "us-east-1")
        workload_name = os.environ.get("AWS_WORKLOAD_NAME")
        agent_id = os.environ.get("AWS_AGENT_ID", "reporting_agent")
        if not workload_name:
            raise RuntimeError("Set AWS_WORKLOAD_NAME (from cloud_target/aws/infra/setup.sh output).")
        mod.run(region, workload_name, agent_id)
    elif cloud == "aws" and uc_key == "4":
        region = os.environ.get("AWS_REGION", "us-east-1")
        domain = os.environ.get("AWS_CODEARTIFACT_DOMAIN")
        repository = os.environ.get("AWS_CODEARTIFACT_REPOSITORY")
        pipeline_name = os.environ.get("AWS_CODEPIPELINE_NAME")
        if not domain or not repository:
            raise RuntimeError("Set AWS_CODEARTIFACT_DOMAIN and AWS_CODEARTIFACT_REPOSITORY.")
        mod.run(region, domain, repository, pipeline_name)
    else:
        raise RuntimeError(f"No cloud attack script for cloud={cloud} uc={uc_key}")


def run_cloud_uc(uc_key: str, cloud: str, mode: str, triage_enabled: bool = False,
                  enrich_crowdstrike: bool = False, enrich_netskope: bool = False,
                  forward_splunk: bool = False, enrich_zabbix: bool = False):
    cfg = UC_CONFIG[uc_key]
    print(f"\n{'=' * 70}\n{cfg['name']}  [cloud={cloud}] [mode={mode}]\n{'=' * 70}")

    print(f"\n--- [CLOUD-{cloud.upper()}] executing REAL attack against {cloud} ---")
    os.environ["EVENT_LOG_PATH"] = os.path.join(ROOT, "logs", "events.jsonl")
    t0 = time.time()
    run_cloud_attack(uc_key, cloud)
    attack_time = time.time() - t0
    print(f"\n[CLOUD-{cloud.upper()}] attack sequence finished in {attack_time:.2f}s "
          f"(this was a real API call sequence against {cloud}, not a simulation)")

    engines = ["scripted", "ai"] if mode == "compare" else [mode]
    results = {}
    for engine in engines:
        blue_path = cfg["scripted_blue"] if engine == "scripted" else cfg["ai_blue"]
        print(f"\n--- [{engine.upper()}] blue team analyzing real {cloud} telemetry ---")
        blue = load_module(blue_path, f"{engine}_blue_cloud_uc{uc_key}")
        t0 = time.time()
        if engine == "ai" and (enrich_crowdstrike or enrich_netskope or enrich_zabbix):
            context = pull_enrichment_context(enrich_crowdstrike, enrich_netskope, enrich_zabbix)
            verdicts = blue.detect(external_context=context or None)
        else:
            verdicts = blue.detect()
        detect_time = time.time() - t0
        detected = sum(1 for v in verdicts if v.get("status") == "DETECTED")
        print(f"\n[{engine.upper()}] verdict: {detected}/{len(verdicts)} findings, detection {detect_time:.2f}s")
        for v in verdicts:
            marker = "OK" if v.get("status") == "DETECTED" else "--"
            conf = f" (conf={v['confidence']})" if "confidence" in v else ""
            print(f"    [{marker}] {v.get('rule')}{conf} :: {v.get('detail')}")

        triage_results = None
        if triage_enabled:
            from fp_triage import triage_all
            from common import read_events
            raw_events = read_events(f"uc{uc_key}")
            print(f"\n--- [TRIAGE:{engine}] reviewing {detected} DETECTED finding(s) ---")
            triage_results = triage_all(verdicts, raw_events)
            for v in triage_results:
                if v.get("triage_disposition") == "not_applicable":
                    continue
                print(f"    [{v['triage_disposition'].upper()}] agreement={v['triage_agreement']} "
                      f"grounded={v['triage_grounded']} :: {v.get('rule')}")

        maybe_forward_to_splunk(triage_results or verdicts, uc_key, forward_splunk)

        results[engine] = {
            "engine": engine, "detected": detected, "total": len(verdicts),
            "attack_time": attack_time, "detect_time": detect_time, "triage": triage_results,
        }

    if mode == "compare":
        print(f"\n{'-' * 70}\nSIDE-BY-SIDE (same real {cloud} attack, two detectors) - {cfg['name']}\n{'-' * 70}")
        print(f"{'':20}{'scripted':>15}{'ai':>15}")
        sf = f"{results['scripted']['detected']}/{results['scripted']['total']}"
        af = f"{results['ai']['detected']}/{results['ai']['total']}"
        print(f"{'findings':20}{sf:>15}{af:>15}")
        print(f"{'detection time':20}{results['scripted']['detect_time']:>14.2f}s{results['ai']['detect_time']:>14.2f}s")
        return {"use_case": cfg["name"], "scripted": results["scripted"], "ai": results["ai"]}
    else:
        return {"use_case": cfg["name"], mode: results[mode]}


def run_uc(uc_key: str, target_url: str, mode: str, triage_enabled: bool = False,
           enrich_crowdstrike: bool = False, enrich_netskope: bool = False,
           forward_splunk: bool = False, enrich_zabbix: bool = False, prod: bool = False):
    cfg = UC_CONFIG[uc_key]
    print(f"\n{'=' * 70}\n{cfg['name']}  [mode={mode}]{'  [PROD]' if prod else ''}\n{'=' * 70}")

    if mode == "compare":
        scripted = run_pass(uc_key, target_url, "scripted", triage_enabled, enrich_crowdstrike, enrich_netskope, forward_splunk, enrich_zabbix, prod)
        ai = run_pass(uc_key, target_url, "ai", triage_enabled, enrich_crowdstrike, enrich_netskope, forward_splunk, enrich_zabbix, prod)
        print(f"\n{'-' * 70}\nSIDE-BY-SIDE - {cfg['name']}\n{'-' * 70}")
        print(f"{'':20}{'scripted':>15}{'ai':>15}")
        scripted_findings = f"{scripted['detected']}/{scripted['total']}"
        ai_findings = f"{ai['detected']}/{ai['total']}"
        print(f"{'findings':20}{scripted_findings:>15}{ai_findings:>15}")
        print(f"{'attack time':20}{scripted['attack_time']:>14.2f}s{ai['attack_time']:>14.2f}s")
        print(f"{'detection time':20}{scripted['detect_time']:>14.2f}s{ai['detect_time']:>14.2f}s")
        return {"use_case": cfg["name"], "scripted": scripted, "ai": ai}
    else:
        result = run_pass(uc_key, target_url, mode, triage_enabled, enrich_crowdstrike, enrich_netskope, forward_splunk, enrich_zabbix, prod)
        return {"use_case": cfg["name"], mode: result}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--uc", default="all", choices=["1", "2", "3", "4", "all"])
    p.add_argument("--mode", default="scripted", choices=["scripted", "ai", "compare"])
    p.add_argument("--target", default="http://localhost:8000")
    p.add_argument("--cloud", default="local", choices=["local", "azure", "aws"],
                    help="Run UC1/UC2 against a real deployed Azure or AWS target instead of the local sandbox. Requires cloud_target/<cloud>/infra setup first. UC3 has no cloud target.")
    p.add_argument("--triage", action="store_true", help="Run AI false-positive triage on DETECTED findings (self-consistency + evidence grounding, requires ANTHROPIC_API_KEY).")
    p.add_argument("--runs", type=int, default=1,
                    help="Repeat the exercise N times and report aggregate detection-rate statistics instead of a single-run result. Needed for a defensible number, not an anecdote. Costs N x the API/cloud calls of a single run.")
    p.add_argument("--enrich-crowdstrike", action="store_true", help="Pull recent real CrowdStrike Falcon alerts and hand them to the AI analyst as correlation context (requires CROWDSTRIKE_CLIENT_ID/SECRET). AI mode only.")
    p.add_argument("--enrich-netskope", action="store_true", help="Pull recent real Netskope DLP/CASB alerts and hand them to the AI analyst as correlation context (requires NETSKOPE_TENANT_HOSTNAME/API_TOKEN). AI mode only.")
    p.add_argument("--enrich-zabbix", action="store_true", help="Pull recent real Zabbix problems and CPU metrics and hand them to the AI analyst as correlation context (requires ZABBIX_URL/ZABBIX_API_TOKEN). AI mode only.")
    p.add_argument("--forward-splunk", action="store_true", help="Forward findings (post-triage if --triage is set) to Splunk via HEC (requires SPLUNK_HEC_URL/SPLUNK_HEC_TOKEN).")
    p.add_argument("--llm-provider", default="anthropic", choices=["anthropic", "openai"],
                    help="Which provider powers --mode ai/compare (currently UC1 only; other UCs still use Anthropic "
                         "regardless of this flag). --triage's false-positive review layer is Anthropic-only either way.")
    p.add_argument("--prod", action="store_true",
                    help="Use the hardened production detector where one exists (currently UC1 only): "
                         "homoglyph/whitespace-normalized signature check, actor tracking, tamper-evident "
                         "audit chain verification. Also auto-enables --triage and --forward-splunk if the "
                         "relevant credentials are already set in your environment, and prints a production "
                         "readiness checklist at the end.")
    args = p.parse_args()

    os.environ["LLM_PROVIDER"] = args.llm_provider
    if args.llm_provider == "openai" and args.uc not in ("1", "all"):
        print(f"WARNING: --llm-provider openai is only wired up for UC1 right now — "
              f"UC{args.uc} will still use Anthropic for --mode ai/compare.")

    if args.prod:
        if os.environ.get("ANTHROPIC_API_KEY") and not args.triage:
            args.triage = True
            print("[prod] auto-enabling --triage (ANTHROPIC_API_KEY is set)")
        # --forward-splunk is deliberately NOT auto-enabled here, unlike
        # --triage above. Found via independent code review (CCCS): triage
        # only reads and analyzes locally-held data, but forwarding sends
        # real findings to an EXTERNAL system - auto-triggering that just
        # because SPLUNK_HEC_URL/TOKEN happen to be set in the environment
        # (left over from unrelated work, a shared corporate variable, or
        # anything else) risks silently sending this lab's fake attack
        # data to a real, possibly-production Splunk instance the user
        # never intended to touch in this run. Sending data out always
        # requires the explicit --forward-splunk flag, every time.
        if os.environ.get("SPLUNK_HEC_URL") and os.environ.get("SPLUNK_HEC_TOKEN") and not args.forward_splunk:
            print("    [prod] NOTE: SPLUNK_HEC_URL/TOKEN are set, but --forward-splunk was not "
                  "passed - findings will NOT be forwarded this run. Pass --forward-splunk "
                  "explicitly if you want that.")

    if args.mode in ("ai", "compare"):
        needed_key = "OPENAI_API_KEY" if args.llm_provider == "openai" else "ANTHROPIC_API_KEY"
        if not os.environ.get(needed_key):
            print(f"ERROR: --mode {args.mode} with --llm-provider {args.llm_provider} requires {needed_key} to be set.")
            sys.exit(1)
    if args.triage and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: --triage requires ANTHROPIC_API_KEY (the false-positive review layer is Anthropic-only regardless of --llm-provider).")
        sys.exit(1)

    if args.cloud != "local" and args.uc not in CLOUD_ATTACK_SCRIPTS.get(args.cloud, {}):
        available = ", ".join(sorted(CLOUD_ATTACK_SCRIPTS.get(args.cloud, {}).keys()))
        print(f"ERROR: --cloud {args.cloud} only has attack scripts for UC {available}.")
        sys.exit(1)

    all_run_summaries = []
    for i in range(args.runs):
        if args.runs > 1:
            print(f"\n\n########## RUN {i + 1}/{args.runs} ##########")
        if args.cloud != "local":
            summary = [run_cloud_uc(args.uc, args.cloud, args.mode, args.triage,
                                     args.enrich_crowdstrike, args.enrich_netskope, args.forward_splunk,
                                     args.enrich_zabbix)]
        else:
            keys = ["1", "2", "3", "4"] if args.uc == "all" else [args.uc]
            summary = [run_uc(k, args.target, args.mode, args.triage,
                               args.enrich_crowdstrike, args.enrich_netskope, args.forward_splunk,
                               args.enrich_zabbix, args.prod) for k in keys]
        all_run_summaries.append(summary)

    last = all_run_summaries[-1]
    print(f"\n{'=' * 70}\nSUMMARY ({'last run of ' + str(args.runs) if args.runs > 1 else 'single run'})\n{'=' * 70}")
    for s in last:
        print(f"  {s['use_case']}")
        for eng in ("scripted", "ai"):
            if eng in s:
                print(f"    {eng}: {s[eng]['detected']}/{s[eng]['total']} findings")

    if args.runs > 1:
        from batch_stats import aggregate_runs
        aggregate_runs(all_run_summaries)
