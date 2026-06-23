from engine.baseline import baseline
from engine.correlator import get_correlator

def compute_confidence(rule_score: float, rule: dict, log_norm: dict) -> dict:
    base = rule.get("base_score", 50) / 100.0
    if rule_score <= 0:
        return {"score": 0.0, "severity": "INFO", "boost": 0.0}

    boost = 0.0
    factors = []

    ba = baseline.score(log_norm)
    if ba > 0:
        boost += ba
        factors.append(("baseline", round(ba, 4)))

    ip = log_norm["flat"].get("source_ip", log_norm["flat"].get("src_ip", "unknown"))
    cb = get_correlator().get_boost(ip)
    if cb > 0:
        boost += cb
        factors.append(("chain", round(cb, 4)))

    if log_norm["decoded_variants"]:
        ob = min(0.15, len(log_norm["decoded_variants"]) * 0.05)
        boost += ob
        factors.append(("obfuscation", round(ob, 4)))

    if log_norm["b64_decoded"]:
        boost += 0.1
        factors.append(("base64", 0.1))

    if len(log_norm["decoded_variants"]) >= 2:
        boost += 0.1
        factors.append(("double_enc", 0.1))

    final = min(rule_score + boost, 1.0)

    if final >= 0.8:
        sev = "CRITICAL"
    elif final >= 0.55:
        sev = "HIGH"
    elif final >= 0.35:
        sev = "MEDIUM"
    elif final > 0:
        sev = "LOW"
    else:
        sev = "INFO"

    return {"score": round(final, 4), "severity": sev, "boost": round(boost, 4), "factors": factors}
