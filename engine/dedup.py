import time
import hashlib
import json

DEDUP_KEY = "neuralops:dedup"

class DedupEngine:
    def __init__(self, window: int = 300):
        self.window = window
        self._cache = {}

    def _fingerprint(self, alert: dict) -> str:
        raw = f"{alert.get('rule_name','')}|{alert.get('source_ip','')}|{alert.get('matched_value','')[:100]}"
        return hashlib.md5(raw.encode()).hexdigest()

    def is_duplicate(self, alert: dict) -> bool:
        fp = self._fingerprint(alert)
        now = time.time()
        if fp in self._cache and now - self._cache[fp] < self.window:
            return True
        self._cache[fp] = now
        for k in list(self._cache):
            if now - self._cache[k] > self.window:
                del self._cache[k]
        return False

    def flush_old(self):
        now = time.time()
        self._cache = {k: v for k, v in self._cache.items() if now - v < self.window}

dedup = DedupEngine()
