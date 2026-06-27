#!/usr/bin/env python3
# NeuralOps - Detection Engine (continuous)
# Now reads from all 3 streams: neuralops:logs, neuralops:network, neuralops:system

import sys, os, json, time, uuid, asyncio, hashlib
from collections import defaultdict
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
from engine.feedback import load_fp_adjustments, get_fp_adjustment

enricher = get_enricher()

def process_one(raw: dict, source_label: str = "web", fp_adjustments: dict | None = None) -> list[dict]:
    norm = normalize_log(raw)
    enricher.enrich(norm)
    baseline.observe(norm)

    candidates = []

    for rule in get_rules():
        raw_score, matched = match_rule(rule, norm)
        if raw_score <= 0:
            continue
        adj = (fp_adjustments or {}).get(rule["name"], 1.0)
        ci = compute_confidence(raw_score, rule, norm, fp_adjustment=adj)
        if ci["score"] < 0.15:
            continue

        candidates.append({
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
            "rule_score": ci["score"],
        })

    # Return top 3 by confidence
    candidates.sort(key=lambda x: x["rule_score"], reverse=True)
    return candidates[:3]

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
    local_dedup = DedupEngine(window=30)
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

        # ── Health monitor: check heartbeats every 15s ──
        async def health_check():
            reported = set()
            while True:
                try:
                    keys = await r.keys("neuralops:heartbeat:*")
                    now = time.time()
                    for key in keys:
                        raw = await r.get(key)
                        if not raw:
                            continue
                        try:
                            data = json.loads(raw)
                            age = now - data.get("time", 0)
                            name = key.split(":", 2)[-1]
                        except Exception:
                            continue
                        if age > 45 and name not in reported:
                            reported.add(name)
                            flat = {"id": str(uuid.uuid4()),
                                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                    "rule_name": "HEALTH-001",
                                    "category": "health",
                                    "severity": "high",
                                    "confidence": 0.95,
                                    "source_ip": "127.0.0.1",
                                    "matched_value": f"SERVICE_DOWN: {name} (heartbeat {age:.0f}s stale)",
                                    "description": f"{name} has not reported in {age:.0f}s",
                                    "incident_id": "",
                                    "source": "engine"}
                            try:
                                await r.xadd(STREAMS["alerts"], flat, maxlen=20000)
                                print(f"  ⚠ HEALTH-001: {name} DOWN (stale {age:.0f}s)", flush=True)
                            except Exception:
                                pass
                        elif age <= 45:
                            reported.discard(name)
                except Exception:
                    pass
                await asyncio.sleep(15)

        asyncio.create_task(health_check())

        # ── Engine heartbeat ──
        async def engine_heartbeat():
            while True:
                try:
                    await r.setex("neuralops:heartbeat:engine", 30,
                                  json.dumps({"pid": os.getpid(), "time": time.time()}))
                except Exception:
                    pass
                await asyncio.sleep(15)

        asyncio.create_task(engine_heartbeat())

        # ── FP auto-tuning loader (every 30s) ──
        fp_adjustments = {}

        async def fp_tuner():
            nonlocal fp_adjustments
            while True:
                try:
                    await load_fp_adjustments()
                    fp_adjustments = dict(__import__("engine.feedback").ADJUSTMENTS)
                except Exception:
                    pass
                await asyncio.sleep(30)

        asyncio.create_task(fp_tuner())

        # ── Per-rule rate limiter ──
        rule_rate_limits = defaultdict(list)
        RATE_LIMIT = 5       # max alerts per rule per window
        RATE_WINDOW = 60     # seconds

        # ── Repeat / escalation tracker ──
        repeat_counts: dict[str, int] = {}
        ESCALATION_THRESHOLDS = {3, 5, 10}

        async def cleanup_repeat_counts():
            while True:
                await asyncio.sleep(120)
                repeat_counts.clear()

        asyncio.create_task(cleanup_repeat_counts())

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

                    alerts = process_one(raw, source_label, fp_adjustments)

                    if not alerts:
                        print(f"  (below threshold)", flush=True)

                    for alert in alerts:
                        # Rate limit: max 5 alerts per rule per 60s
                        rn = alert["rule_name"]
                        now_ts = time.time()
                        ts_list = rule_rate_limits[rn]
                        ts_list[:] = [t for t in ts_list if now_ts - t < RATE_WINDOW]
                        if len(ts_list) >= RATE_LIMIT:
                            print(f"  (rate-limited: {rn} — {len(ts_list)} in {RATE_WINDOW}s, suppressing)", flush=True)
                            continue
                        ts_list.append(now_ts)

                        # Dedup + escalation
                        fp_raw = f"{alert['rule_name']}|{alert['source_ip']}|{(alert.get('matched_value') or '')[:100]}"
                        fp = hashlib.md5(fp_raw.encode()).hexdigest()

                        is_dup = local_dedup.is_duplicate(alert)
                        dedup_key = f"dedup:{alert['rule_name']}:{alert['source_ip']}"
                        try:
                            is_redis_dup = bool(await r.get(dedup_key))
                        except Exception:
                            is_redis_dup = False

                        if is_dup or is_redis_dup:
                            esc = repeat_counts.get(fp, 0) + 1
                            repeat_counts[fp] = esc
                            if esc in (3, 5, 10):
                                alert["confidence"] = min(alert.get("confidence", 0) + 0.1, 1.0)
                                alert["description"] = f"{alert['rule_name']} ESCALATED (repeat #{esc})"
                                alert["severity"] = "CRITICAL" if alert["confidence"] >= 0.8 else "HIGH"
                                esc_ts_list = rule_rate_limits.get(f"{rn}_ESC", [])
                                esc_ts_list[:] = [t for t in esc_ts_list if now_ts - t < RATE_WINDOW]
                                if len(esc_ts_list) >= RATE_LIMIT:
                                    print(f"  (rate-limited escalation: {rn})", flush=True)
                                    continue
                                esc_ts_list.append(now_ts)
                                rule_rate_limits[f"{rn}_ESC"] = esc_ts_list
                            elif esc > 10:
                                repeat_counts.pop(fp, None)
                                continue
                            else:
                                print(f"  (dedup + repeat#{esc}: {alert['rule_name']} from {alert['source_ip']})", flush=True)
                                continue

                        repeat_counts[fp] = 0
                        try:
                            await r.set(dedup_key, "1", ex=30)
                        except Exception as e:
                            print(f"  [warning] Redis dedup check failed: {e}", flush=True)
                        try:
                            flat = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in alert.items() if k != "rule_score"}
                            await r.xadd(STREAMS["alerts"], flat, maxlen=20000)
                        except Exception:
                            pass

                        print(f"\n  ► ALERT: {alert['rule_name']} — conf={alert['confidence']:.3f} [{alert['severity']}]", flush=True)
                        print(f"    Source: {alert['source']}  IP: {alert['source_ip']}", flush=True)
                        print(f"    Matched: {alert['matched_value'][:80]}", flush=True)
                        print(f"    TTP: {alert['ttp']}  Kill Chain: {alert['kill_chain']}", flush=True)

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
