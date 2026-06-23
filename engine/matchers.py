import re
import time
from collections import defaultdict
from datetime import datetime
from engine.parsers import normalize_log

threshold_state = defaultdict(lambda: defaultdict(list))
threshold_unique_state = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
correlation_state = defaultdict(lambda: defaultdict(list))

def _get_ip(log_norm: dict, config: dict) -> str:
    key = config.get("group_by", "source_ip")
    return log_norm["flat"].get(key, log_norm["flat"].get("src_ip", "unknown"))

def match_regex(rule: dict, log_norm: dict) -> tuple[float, str]:
    best_score, best_match = 0.0, ""
    patterns = rule.get("patterns", [])
    fields = rule.get("fields", [])
    texts = [log_norm["fields"].get(f, "") for f in fields]
    texts.append(log_norm["all_text"])
    texts.extend(log_norm["decoded_variants"])
    texts.extend(log_norm["b64_decoded"])

    for text in texts:
        if not text:
            continue
        for p in patterns:
            try:
                m = re.search(p, text)
                if m:
                    raw = max(0.22, min(1.0, len(m.group()) / 50.0))
                    score = raw * (rule["base_score"] / 100.0)
                    if score > best_score:
                        best_score, best_match = score, m.group()[:200]
            except re.error:
                continue
    return best_score, best_match

def match_threshold(rule: dict, log_norm: dict) -> tuple[float, str]:
    cfg = rule.get("config", {})
    ip = _get_ip(log_norm, cfg)
    now = time.time()
    window = cfg.get("window", 60)
    field_val = log_norm["flat"].get(cfg.get("field"))

    value = cfg.get("value")
    value_gt = cfg.get("value_gt")
    if value is not None and field_val != value:
        return 0.0, ""
    if value_gt is not None:
        try:
            if (field_val is None) or (isinstance(field_val, str) and not field_val.lstrip('-').isdigit()) or (not isinstance(field_val, (int, float)) and not str(field_val).lstrip('-').isdigit()):
                return 0.0, ""
            val = int(field_val) if isinstance(field_val, str) else field_val
            if val <= value_gt:
                return 0.0, ""
        except (ValueError, TypeError):
            return 0.0, ""

    name = rule["id"]
    state = threshold_state[name][ip]
    state.append(now)
    state[:] = [t for t in state if now - t < window]

    needed = cfg.get("count", 10)
    if len(state) >= needed:
        ratio = min(1.0, len(state) / (needed * 2))
        return ratio * (rule["base_score"] / 100.0), f"{len(state)} events in {window}s"
    return 0.0, ""

def match_threshold_unique(rule: dict, log_norm: dict) -> tuple[float, str]:
    cfg = rule.get("config", {})
    ip = _get_ip(log_norm, cfg)
    now = time.time()
    window = cfg.get("window", 60)
    field = cfg.get("field")
    field_val = str(log_norm["flat"].get(field, ""))
    if not field_val:
        return 0.0, ""

    if "path_prefix" in cfg and not field_val.startswith(cfg["path_prefix"]):
        return 0.0, ""
    if "status_values" in cfg:
        actual = log_norm["flat"].get("status", "")
        if actual not in cfg["status_values"]:
            return 0.0, ""

    name = rule["id"]
    state = threshold_unique_state[name][ip]
    state[field_val].add(now)
    for k in list(state):
        state[k] = {t for t in state[k] if now - t < window}
        if not state[k]:
            del state[k]

    needed = cfg.get("unique_count", 20)
    if len(state) >= needed:
        ratio = min(1.0, len(state) / (needed * 2))
        return ratio * (rule["base_score"] / 100.0), f"{len(state)} unique {field} values"
    return 0.0, ""

def match_time_based(rule: dict, log_norm: dict) -> tuple[float, str]:
    cfg = rule.get("config", {})
    now = datetime.utcnow()
    if now.hour not in cfg.get("hours", []):
        return 0.0, ""
    url = log_norm["fields"].get("url", "")
    for sp in cfg.get("sensitive_patterns", []):
        if re.search(sp, url, re.IGNORECASE):
            return rule["base_score"] / 100.0, f"Off-hours: {url[:100]}"
    return 0.0, ""

def match_correlation(rule: dict, log_norm: dict) -> tuple[float, str]:
    cfg = rule.get("config", {})
    ip = _get_ip(log_norm, cfg)
    now = time.time()
    window = cfg.get("window", 10)
    actual = log_norm["flat"].get(cfg.get("trigger_field", "status"))
    if actual == cfg.get("trigger_value", "500"):
        name = rule["id"]
        state = correlation_state[name][ip]
        state.append(now)
        state[:] = [t for t in state if now - t < window]
        needed = cfg.get("count", 5)
        if len(state) >= needed:
            ratio = min(1.0, len(state) / (needed * 2))
            return ratio * (rule["base_score"] / 100.0), f"{len(state)} errors in {window}s"
    return 0.0, ""

def match_geo_regex(rule: dict, log_norm: dict) -> tuple[float, str]:
    base_score, match = match_regex(rule, log_norm)
    if base_score <= 0:
        return 0.0, ""

    geo = log_norm.get("geo", {})
    if geo.get("is_private"):
        return 0.0, ""

    suspicious = rule.get("suspicious_countries", [])
    country = geo.get("country", "")
    if suspicious and country and country in suspicious:
        base_score += 0.2
        match = f"{match} [{country}]"

    if not country:
        base_score = max(base_score, 0.1)

    return min(base_score, 1.0), match

MATCHER_FN = {
    "regex": match_regex,
    "threshold": match_threshold,
    "threshold_unique": match_threshold_unique,
    "time_based": match_time_based,
    "correlation": match_correlation,
    "geo_regex": match_geo_regex,
}

def match_rule(rule: dict, log_norm: dict) -> tuple[float, str]:
    return MATCHER_FN.get(rule.get("type", "regex"), match_regex)(rule, log_norm)
