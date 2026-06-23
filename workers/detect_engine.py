#!/usr/bin/env python3
"""
NeuralOps — Detection Engine (continuous)
Run in Terminal 2:  python3 workers/detect_engine.py
Keeps running, detects every attack until Ctrl+C.
No timeout errors. Handles Redis disconnects gracefully.
"""

import sys, os, json, time, uuid, asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import redis.asyncio as aioredis
from config.settings import REDIS_URL, STREAMS

from engine.parsers import normalize_log
from engine.enricher import get_enricher
from engine.matchers import match_rule
from engine.scorer import compute_confidence
from engine.baseline import baseline
from engine.rules import get_rules

enricher = get_enricher()

def process_one(raw: dict) -> dict | None:
    norm = normalize_log(raw)
    enricher.enrich(norm)
    baseline.observe(norm)

    best = best_ci = best_rule = best_matched = None

    for rule in get_rules():
        raw_score, matched = match_rule(rule, norm)
        if raw_score <= 0:
            continue
        ci = compute_confidence(raw_score, rule, norm)
        if ci["score"] < 0.15:
            continue

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
                "matched_value": matched[:500],
                "matched_pattern": rule.get("pattern", "")[:500] if isinstance(rule.get("pattern"), str) else str(rule.get("patterns", [""])[0])[:500],
                "description": f"{rule['name']} detected",
                "incident_id": "",
                "geo": norm.get("geo", {}),
                "raw_log": raw,
            }
            best_ci = ci
            best_rule = rule
            best_matched = matched

    return best

async def get_connection():
    return aioredis.from_url(
        REDIS_URL,
        decode_responses=True,
        socket_connect_timeout=3,
        socket_timeout=None,
    )

async def main():
    print("=" * 60, flush=True)
    print("  NEURALOPS — Detection Engine (continuous)", flush=True)
    print("  Waiting for attacks on neuralops:logs ...", flush=True)
    print("  Press Ctrl+C to stop", flush=True)
    print("=" * 60, flush=True)

    last_id = "0"
    r = None

    try:
        r = await get_connection()

        while True:
            try:
                result = await r.xread(
                    {STREAMS["logs"]: last_id},
                    count=1,
                    block=2000,
                )
            except (ConnectionError, OSError, aioredis.TimeoutError) as e:
                print(f"  [reconnecting] Redis: {e}", flush=True)
                await asyncio.sleep(1)
                try:
                    if r:
                        await r.aclose()
                except Exception:
                    pass
                r = await get_connection()
                continue

            if not result:
                continue

            _, entries = result[0]
            for eid, data in entries:
                last_id = eid
                raw = dict(data)

                try:
                    await r.xdel(STREAMS["logs"], eid)
                except Exception:
                    pass

                print(f"\n{'='*60}", flush=True)
                print(f"  LOG — {raw.get('method','')} {raw.get('path','') or raw.get('url','')} from {raw.get('source_ip','?')}", flush=True)
                print(f"{'='*60}", flush=True)

                alert = process_one(raw)

                if alert:
                    try:
                        flat = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in alert.items()}
                        await r.xadd(STREAMS["alerts"], flat, maxlen=20000)
                    except Exception:
                        pass

                    print(f"\n  ► ALERT: {alert['rule_name']} — conf={alert['confidence']:.3f} [{alert['severity']}]", flush=True)
                    print(f"    Matched: {alert['matched_value'][:80]}", flush=True)
                    print(f"    Factors: {alert['confidence_factors']}", flush=True)
                    print(f"    ID: {alert['id']}", flush=True)
                    print(f"    TTP: {alert['ttp']}  Kill Chain: {alert['kill_chain']}", flush=True)
                    print(f"    IP: {alert['source_ip']}", flush=True)
                    print(f"    Geo: {json.dumps(alert['geo'], indent=4)}", flush=True)
                    print(f"\n    ── Raw Log ──", flush=True)
                    print(f"{json.dumps(alert['raw_log'], indent=4)}", flush=True)
                    print(f"\n    ── Full Alert JSON ──", flush=True)
                    print(f"{json.dumps(alert, indent=4)}", flush=True)
                else:
                    print(f"  (below threshold)", flush=True)

    except asyncio.CancelledError:
        pass
    finally:
        if r:
            try:
                await r.aclose()
            except Exception:
                pass
        print("\n  Engine stopped.", flush=True)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n  Engine stopped.", flush=True)
