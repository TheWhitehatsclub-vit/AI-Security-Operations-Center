import asyncio
import json
import logging
from config.redis import get_redis
from config.settings import STREAMS, BATCH_SIZE, BLOCK_MS, RULE_REFRESH_INTERVAL, ALERT_STREAMS
from shared.schema import make_alert, make_incident
from engine.parsers import normalize_log
from engine.matchers import match_rule
from engine.scorer import compute_confidence
from engine.baseline import baseline
from engine.correlator import get_correlator
from engine.dedup import dedup
from engine.feedback import feedback_engine
from engine.persistence import persistence
from engine.enricher import get_enricher
from engine.loader import get_loader

logging.basicConfig(level=logging.INFO, format="[engine] %(message)s")
log = logging.getLogger(__name__)

rule_loader = get_loader()
enricher = get_enricher()
GROUP_WINDOW = 60
_pending_alerts = {}

async def process_log(raw: dict, r):
    norm = normalize_log(raw)
    enricher.enrich(norm)
    baseline.observe(norm)

    best = best_ci = best_rule = best_matched = None
    for rule in rule_loader.get_rules():
        score, matched = match_rule(rule, norm)
        if score <= 0:
            continue
        ci = compute_confidence(score, rule, norm)
        if ci["score"] < 0.15:
            continue

        alert = make_alert(
            rule_name=rule["name"],
            category=rule.get("category", "unknown"),
            severity=ci["severity"],
            ttp=rule["ttps"][0] if rule.get("ttps") else "T1078",
            kill_chain=rule.get("kill_chain", "Unknown"),
            source_ip=norm["flat"].get("source_ip", norm["flat"].get("src_ip", "unknown")),
            matched_value=matched,
            raw_log=raw,
            confidence=ci["score"],
            description=rule.get("description", f"{rule['name']} detected"),
        )

        if best is None or ci["score"] > best["confidence"]:
            best = alert
            best_ci = ci
            best_rule = rule
            best_matched = matched

    if not best:
        return

    best["geo"] = norm.get("geo", {})
    best["confidence_factors"] = best_ci.get("factors", [])
    best["confidence_boost"] = best_ci.get("boost", 0.0)
    best["matched_pattern"] = best_rule.get("pattern", "")[:500] if isinstance(best_rule.get("pattern"), str) else str(best_rule.get("patterns", [""])[0])[:500]

    # FP check
    if await feedback_engine.is_false_positive(best):
        return

    # Dedup
    if dedup.is_duplicate(best):
        return

    get_correlator().record(best)

    # Group similar alerts into incidents
    gk = (best["rule_name"], best["source_ip"])
    if gk in _pending_alerts:
        existing = _pending_alerts[gk]
        existing["alerts"].append(best)
        existing["last_ts"] = asyncio.get_event_loop().time()
        if len(existing["alerts"]) >= 10:
            await _flush_group(gk, r)
    else:
        _pending_alerts[gk] = {
            "alerts": [best],
            "last_ts": asyncio.get_event_loop().time(),
            "created": asyncio.get_event_loop().time(),
        }

async def _flush_group(gk: tuple, r):
    group = _pending_alerts.pop(gk, None)
    if not group:
        return
    alerts = group["alerts"]
    if len(alerts) == 1:
        await r.xadd(STREAMS["alerts"], alerts[0], maxlen=20000)
    else:
        severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        max_sev = max(alerts, key=lambda a: severity_order.get(a["severity"], 0))
        incident = make_incident(
            alerts=alerts,
            source_ip=gk[1],
            category=max_sev["category"],
            severity=max_sev["severity"],
            ttp=max_sev["ttp"],
        )
        for a in alerts:
            a["incident_id"] = incident["id"]
        await r.xadd(STREAMS["incidents"], incident, maxlen=10000)
        await r.xadd(STREAMS["alerts"], incident, maxlen=20000)

async def _flush_expired_groups(r):
    now = asyncio.get_event_loop().time()
    for gk in list(_pending_alerts.keys()):
        if now - _pending_alerts[gk]["last_ts"] > GROUP_WINDOW:
            await _flush_group(gk, r)

async def main():
    r = await get_redis()
    last_ids = {STREAMS[s]: "$" for s in ["logs", "network", "system"]}

    asyncio.ensure_future(rule_loader.start_background_refresh(RULE_REFRESH_INTERVAL))
    await rule_loader.refresh()
    log.info(f"Watching {len(last_ids)} streams, {rule_loader.get_count()} rules (source: {rule_loader.get_source()})")

    persist_counter = 0
    while True:
        try:
            result = await r.xread(last_ids, count=BATCH_SIZE, block=BLOCK_MS)
            for stream, entries in result:
                for eid, data in entries:
                    last_ids[stream] = eid
                    await process_log(dict(data), r)

            if _pending_alerts:
                await _flush_expired_groups(r)

            persist_counter += 1
            if persist_counter % 20 == 0:
                asyncio.ensure_future(persistence.save())
        except Exception as e:
            log.error(f"Error: {e}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
