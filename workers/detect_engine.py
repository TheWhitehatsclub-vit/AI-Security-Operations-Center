#!/usr/bin/env python3
# NeuralOps - Detection Engine (continuous)
# Now reads from all 3 streams: neuralops:logs, neuralops:network, neuralops:system

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
from engine.dedup import DedupEngine

enricher = get_enricher()

def process_one(raw: dict, source_label: str = "web") -> dict | None:
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
                "source": source_label,
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

STREAM_NAMES = {
    STREAMS["logs"]: "logs",
    STREAMS["network"]: "network",
    STREAMS["system"]: "system",
}

STREAM_LABELS = {
    "logs": "web",
    "network": "network",
    "system": "system",
}

STREAM_DISPLAY = {
    "logs": "LOG",
    "network": "NET",
    "system": "SYS",
}

async def main():
    print("=" * 60, flush=True)
    print("  NEURALOPS — Detection Engine (multi-stream)", flush=True)
    print("  Watching: web-logs | network | system", flush=True)
    print("  Press Ctrl+C to stop", flush=True)
    print("=" * 60, flush=True)

    last_ids = {STREAMS["logs"]: "$", STREAMS["network"]: "$", STREAMS["system"]: "$"}
    local_dedup = DedupEngine(window=60)
    r = None

    try:
        r = await get_connection()

        # Drain any existing entries from all 3 streams so we only process NEW events
        for sname in [STREAMS["logs"], STREAMS["network"], STREAMS["system"]]:
            try:
                last = await r.xrevrange(sname, count=1)
                if last:
                    last_ids[sname] = last[0][0]
                    print(f"  [drain] {sname} — skipping {last[0][0]} entries", flush=True)
            except Exception:
                pass

        while True:
            try:
                result = await r.xread(
                    {k: v for k, v in last_ids.items()},
                    count=5,
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

            for stream_name, entries in result:
                stream_key = STREAM_NAMES.get(stream_name, "logs")
                source_label = STREAM_LABELS.get(stream_key, "web")
                display = STREAM_DISPLAY.get(stream_key, "LOG")

                for eid, data in entries:
                    last_ids[stream_name] = eid
                    raw = dict(data)

                    try:
                        await r.xdel(stream_name, eid)
                    except Exception:
                        pass

                    ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("hostname") or "?"
                    method = raw.get("method") or raw.get("protocol") or raw.get("unit") or ""
                    path = raw.get("path") or raw.get("dst_ip") or raw.get("message", "")[:60]

                    print(f"\n{'='*60}", flush=True)
                    print(f"  [{display}] {method} {path} from {ip}", flush=True)
                    print(f"{'='*60}", flush=True)

                    alert = process_one(raw, source_label)

                    if alert:
                        # Two-layer dedup: 1) local in-memory fingerprint, 2) Redis cross-process fence
                        if local_dedup.is_duplicate(alert):
                            print(f"  (dedup: {alert['rule_name']} from {alert['source_ip']} — already fired, skipping)", flush=True)
                            continue
                        dedup_key = f"dedup:{alert['rule_name']}:{alert['source_ip']}"
                        try:
                            already = await r.get(dedup_key)
                            if already:
                                print(f"  (dedup(redis): {alert['rule_name']} from {alert['source_ip']} already fired)", flush=True)
                                continue
                            await r.set(dedup_key, "1", ex=60)
                        except Exception as e:
                            print(f"  [warning] Redis dedup check failed: {e}", flush=True)
                        try:
                            flat = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in alert.items()}
                            await r.xadd(STREAMS["alerts"], flat, maxlen=20000)
                        except Exception:
                            pass

                        print(f"\n  ► ALERT: {alert['rule_name']} — conf={alert['confidence']:.3f} [{alert['severity']}]", flush=True)
                        print(f"    Source: {alert['source']}  IP: {alert['source_ip']}", flush=True)
                        print(f"    Matched: {alert['matched_value'][:80]}", flush=True)
                        print(f"    TTP: {alert['ttp']}  Kill Chain: {alert['kill_chain']}", flush=True)
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
