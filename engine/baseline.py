import time
import re
from collections import defaultdict, deque

class IPBaseline:
    def __init__(self):
        self._profiles = {}

    def _get(self, ip: str) -> dict:
        if ip not in self._profiles:
            self._profiles[ip] = {
                "first_seen": time.time(),
                "total": 0,
                "methods": defaultdict(int),
                "paths": defaultdict(int),
                "statuses": defaultdict(int),
                "body_lens": deque(maxlen=100),
                "timestamps": deque(maxlen=200),
                "hours": defaultdict(int),
                "uas": set(),
            }
        return self._profiles[ip]

    def observe(self, log_norm: dict):
        flat = log_norm["flat"]
        ip = flat.get("source_ip", flat.get("src_ip", "unknown"))
        if ip == "unknown":
            return
        p = self._get(ip)
        p["total"] += 1
        p["methods"][flat.get("method", "GET")] += 1
        p["paths"][flat.get("path", "")] += 1
        p["statuses"][flat.get("status", "200")] += 1
        p["hours"][time.localtime().tm_hour] += 1
        ua = flat.get("user_agent", "")
        if ua:
            p["uas"].add(ua[:100])
        p["body_lens"].append(len(flat.get("body", "")))
        p["timestamps"].append(time.time())

    def score(self, log_norm: dict) -> float:
        flat = log_norm["flat"]
        ip = flat.get("source_ip", flat.get("src_ip", "unknown"))
        if ip == "unknown" or ip not in self._profiles:
            return 0.0
        p = self._profiles[ip]
        if p["total"] < 10:
            return 0.0

        score, total = 0.0, p["total"]

        m = flat.get("method", "GET")
        if p["methods"][m] / total < 0.01 and total > 20:
            score += 0.15

        s = flat.get("status", "200")
        if p["statuses"][s] / total < 0.01 and total > 20:
            score += 0.15

        ua = flat.get("user_agent", "")
        if ua and ua[:100] not in p["uas"] and len(p["uas"]) > 3:
            score += 0.1

        hour = time.localtime().tm_hour
        h_avg = sum(p["hours"].values()) / max(len(p["hours"]), 1)
        if h_avg > 0 and p["hours"].get(hour, 0) > h_avg * 3:
            score += 0.2

        if len(p["body_lens"]) > 10:
            bl = len(flat.get("body", ""))
            avg = sum(p["body_lens"]) / len(p["body_lens"])
            if avg > 0:
                if bl > avg * 10:
                    score += 0.25
                elif bl > avg * 5:
                    score += 0.15

        ts = list(p["timestamps"])
        if len(ts) > 10:
            gaps = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
            avg_gap = sum(gaps) / len(gaps)
            if avg_gap > 0 and (time.time() - ts[-1]) < avg_gap * 0.1:
                score += 0.2

        return min(score, 0.9)

    def serialize(self) -> dict:
        out = {}
        for ip, p in self._profiles.items():
            out[ip] = {
                "total": p["total"],
                "methods": dict(p["methods"]),
                "statuses": dict(p["statuses"]),
                "hours": dict(p["hours"]),
                "ua_count": len(p["uas"]),
                "avg_body_len": round(sum(p["body_lens"]) / max(len(p["body_lens"]), 1), 2),
            }
        return out

baseline = IPBaseline()
