import time
from collections import defaultdict, deque
from dataclasses import dataclass

CHAINS = [
    {"name": "Recon → Exploit → Install", "stages": ["recon", "web", "malware"], "window": 120, "boost": 0.3},
    {"name": "Recon → Brute Force → Exfil", "stages": ["recon", "auth", "exfiltration"], "window": 180, "boost": 0.25},
    {"name": "Web Exploit → C2", "stages": ["web", "malware"], "window": 60, "boost": 0.2},
    {"name": "Auth Attack → Exfiltration", "stages": ["auth", "exfiltration"], "window": 120, "boost": 0.2},
    {"name": "Cloud Recon → Cloud Exploit", "stages": ["recon", "cloud"], "window": 90, "boost": 0.2},
]

class AttackChainCorrelator:
    def __init__(self):
        self.events: defaultdict[str, deque] = defaultdict(lambda: deque(maxlen=50))

    def record(self, alert: dict):
        ip = alert.get("source_ip", "unknown")
        self.events[ip].append({
            "category": alert.get("category", ""),
            "ts": time.time(),
        })

    def get_boost(self, ip: str) -> float:
        if ip not in self.events:
            return 0.0
        evts = list(self.events[ip])
        now = time.time()
        boost = 0.0

        for chain in CHAINS:
            stages = chain["stages"]
            for i in range(len(evts) - len(stages) + 1):
                if all(evts[i+j]["category"] == stages[j] and now - evts[i+j]["ts"] < chain["window"] for j in range(len(stages))):
                    boost += chain["boost"]
                    break

        cats = defaultdict(int)
        for e in evts:
            if now - e["ts"] < 300:
                cats[e["category"]] += 1
        for v in cats.values():
            if v >= 5:
                boost += 0.1
                break

        return min(boost, 0.5)

_correlator = AttackChainCorrelator()

def get_correlator():
    return _correlator
