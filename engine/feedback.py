import json
import hashlib
from config.redis import get_redis

FP_KEY = "neuralops:fp"
FP_FEEDBACK_KEY = "neuralops:fp_feedback"

class FeedbackEngine:
    async def is_false_positive(self, alert: dict) -> bool:
        r = await get_redis()
        fp = self._fingerprint(alert)
        exists = await r.sismember(FP_KEY, fp)
        await r.aclose()
        return exists

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
