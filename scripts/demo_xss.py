#!/usr/bin/env python3
"""
NeuralOps — XSS Demo (single script, no Redis needed)
Run: python3 scripts/demo_xss.py
"""

import sys, os, json, time, uuid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.parsers import normalize_log
from engine.enricher import GeoEnricher
from engine.matchers import match_rule
from engine.scorer import compute_confidence
from engine.baseline import baseline
from engine.rules import get_rules

RULES_BY_NAME = {r["name"]: r for r in get_rules()}
enricher = GeoEnricher()

# ── XSS attack log ──────────────────────────────────────────────────
raw_log = {
    "source_ip": "198.51.100.15",
    "method": "GET",
    "url": "/search?q=%3Cinput+onmouseover%3D%22alert(1)%22%3E",
    "status": 200,
    "user_agent": "Mozilla/5.0 (XSS PoC)",
    "referer": "http://evil.com",
}

print("=" * 70)
print("  STEP 1 — RAW LOG ENTERS REDIS STREAM (neuralops:logs)")
print("=" * 70)
print(json.dumps(raw_log, indent=2))
time.sleep(0.5)

# ── STEP 2: Normalize + Decode ──────────────────────────────────────
print("\n" + "=" * 70)
print("  STEP 2 — PARSER LAYER (normalize + URL decode)")
print("=" * 70)

norm = normalize_log(raw_log)

print(f"  URL decoded body/query:  {norm['decoded_variants']}")
if norm["b64_decoded"]:
    print(f"  Base64 decoded:         {norm['b64_decoded']}")
print(f"  Normalized fields:       {list(norm['flat'].keys())[:10]}...")
time.sleep(0.5)

# ── STEP 3: Enrichment ─────────────────────────────────────────────
print("\n" + "=" * 70)
print("  STEP 3 — ENRICHMENT LAYER (GeoIP lookup)")
print("=" * 70)
enricher.enrich(norm)
geo = norm.get("geo", {})
if geo.get("country"):
    print(f"  Country: {geo['country']} | City: {geo['city']} | ISP: {geo['isp']}")
else:
    print(f"  (GeoIP DB not loaded — enrichment would add country/city/ASN)")
time.sleep(0.5)

# ── STEP 4: Baseline ────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  STEP 4 — BEHAVIORAL BASELINE (IP profiling)")
print("=" * 70)
baseline.observe(norm)
ba_score = baseline.score(norm)
print(f"  Anomaly score: {ba_score:.3f} {'(abnormal rate/UA/method)' if ba_score > 0 else '(normal — first request)'}")
time.sleep(0.5)

# ── STEP 5: Rule matching ──────────────────────────────────────────
print("\n" + "=" * 70)
print("  STEP 5 — DETECTION ENGINE (63 rules scanned)")
print("=" * 70)

best = best_ci = best_rule = best_matched = None

for rule in get_rules():
    raw_score, matched = match_rule(rule, norm)
    if raw_score <= 0:
        continue
    ci = compute_confidence(raw_score, rule, norm)
    if ci["score"] < 0.15:
        continue

    if matched == "onmouseover=\"alert(1)\"":
        print(f"  ✓ MATCHED: {rule['name']}")
        print(f"    Pattern:     {rule['patterns']}")
        print(f"    Matched:     {matched}")
        print(f"    Raw score:   {raw_score:.4f}")
        print(f"    Confidence:  {ci['score']:.4f} [{ci['severity']}]")
        print(f"    Boost:       +{ci['boost']:.4f} {ci['factors']}")
    else:
        print(f"    MATCH: {rule['name']:30s} → {matched[:60]}")

    if best is None or ci["score"] > best_ci["score"]:
        best = {
            "id": str(uuid.uuid4()),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rule_name": rule["name"],
            "category": rule.get("category", "unknown"),
            "severity": ci["severity"],
            "confidence": ci["score"],
            "confidence_boost": ci.get("boost", 0.0),
            "confidence_factors": ci.get("factors", []),
            "ttp": rule["ttps"][0] if rule.get("ttps") else "T1078",
            "kill_chain": rule.get("kill_chain", "Unknown"),
            "source_ip": norm["flat"].get("source_ip", norm["flat"].get("src_ip", "unknown")),
            "matched_value": matched[:200],
            "matched_pattern": rule.get("pattern", "")[:500] if isinstance(rule.get("pattern"), str) else str(rule.get("patterns", [""])[0])[:500],
            "description": f"{rule['name']} detected",
            "incident_id": "",
            "geo": norm.get("geo", {}),
            "raw_log": raw_log,
        }
        best_ci = ci
        best_rule = rule
        best_matched = matched

time.sleep(0.5)

# ── STEP 6: Final Alert ────────────────────────────────────────────
print("\n" + "=" * 70)
print("  STEP 6 — FINAL ALERT → emitted to neuralops:alerts")
print("=" * 70)
if best:
    print(json.dumps(best, indent=2))
    print("\n" + "=" * 70)
    print("  UI TEAM READS THIS FROM REDIS STREAM: neuralops:alerts")
    print("=" * 70)
    print(f"\n  Fields available: {len(best)}")
    print(f"  Rule: {best['rule_name']} → {best['matched_value']}")
    print(f"  Confidence: {best['confidence']} ({best['severity']})")
    print(f"  Why: {best['confidence_factors']}")
    print(f"  IP: {best['source_ip']}")
    print(f"  Geo: {best['geo']}")
    print()
else:
    print("  No alert (below threshold)")
    sys.exit(1)
