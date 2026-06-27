import json
import hashlib
from config.redis import get_redis

FP_KEY = "neuralops:fp"
FP_FEEDBACK_KEY = "neuralops:fp_feedback"
FP_COUNTS_KEY = "neuralops:fp_rule_counts"

FP_ADJUSTMENT_KEY = "neuralops:fp_tuning"

ADJUSTMENTS = {}
LAST_LOAD = 0.0

async def load_fp_adjustments():
    global ADJUSTMENTS, LAST_LOAD
    now = __import__("time").time()
    if now - LAST_LOAD < 30:
        return
    r = await get_redis()
    try:
        raw = await r.hgetall(FP_ADJUSTMENT_KEY)
        ADJUSTMENTS = {k: float(v) for k, v in raw.items()}
        LAST_LOAD = now
    finally:
        await r.aclose()

def get_fp_adjustment(rule_name: str) -> float:
    return ADJUSTMENTS.get(rule_name, 1.0)

class FeedbackEngine:
    async def is_false_positive(self, alert: dict) -> bool:
        r = await get_redis()
        fp = self._fingerprint(alert)
        exists = await r.sismember(FP_KEY, fp)
        await r.aclose()
        return exists

    async def _incr_fp_count(self, rule_name: str):
        r = await get_redis()
        try:
            count = await r.hincrby(FP_COUNTS_KEY, rule_name, 1)
            if count > 3:
                factor = max(0.4, 1.0 - (count - 3) * 0.05)
                await r.hset(FP_ADJUSTMENT_KEY, rule_name, str(round(factor, 2)))
        finally:
            await r.aclose()

    async def mark_false_positive(self, alert: dict, reason: str = ""):
        r = await get_redis()
        fp = self._fingerprint(alert)
        await r.sadd(FP_KEY, fp)
        feedback = {
            "fingerprint": fp,
            "rule_name": alert.get("rule_name", ""),
            "source_ip": alert.get("source_ip", ""),
            "matched_value": alert.get("matched_value", ""),
            "reason": reason,
            "timestamp": __import__("time").time(),
        }
        await r.xadd(FP_FEEDBACK_KEY, feedback, maxlen=5000)
        await r.aclose()
        await self._incr_fp_count(alert.get("rule_name", ""))

    async def submit_feedback(self, alert_id: str, is_fp: bool, analyst: str = "", note: str = ""):
        r = await get_redis()
        feedback = {
            "alert_id": alert_id,
            "is_false_positive": is_fp,
            "analyst": analyst,
            "note": note,
            "timestamp": __import__("time").time(),
        }
        await r.xadd(FP_FEEDBACK_KEY, feedback, maxlen=10000)
        await r.aclose()

    def _fingerprint(self, alert: dict) -> str:
        raw = f"{alert.get('rule_name','')}|{alert.get('source_ip','')}|{alert.get('matched_value','')[:100]}"
        return hashlib.md5(raw.encode()).hexdigest()

feedback_engine = FeedbackEngine()
