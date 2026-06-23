import asyncio
import json
import logging
import time
from config.redis import get_redis
from config.settings import RULE_REFRESH_INTERVAL
from engine.rules import get_rules as get_static_rules

RULE_HASH_KEY = "neuralops:rules_config"
RULE_INDEX_KEY = "neuralops:rules:index"

log = logging.getLogger(__name__)

class RuleLoader:
    def __init__(self):
        self._rules = get_static_rules()
        self._last_refresh = 0.0
        self._source = "static"

    async def refresh(self):
        try:
            r = await get_redis()
            exists = await r.exists(RULE_HASH_KEY)
            if not exists:
                await r.aclose()
                return

            raw_json = await r.hget(RULE_HASH_KEY, "rules")
            await r.aclose()

            if not raw_json:
                return

            parsed = json.loads(raw_json)
            if not isinstance(parsed, list) or len(parsed) < 1:
                return

            self._rules = parsed
            self._last_refresh = time.time()
            self._source = "redis"
            log.info(f"Rules hot-reloaded from Redis: {len(parsed)} rules")
        except Exception as e:
            log.warning(f"Rule reload failed, using static rules: {e}")

    def get_rules(self) -> list:
        return self._rules

    def get_count(self) -> int:
        return len(self._rules)

    def get_source(self) -> str:
        return self._source

    async def start_background_refresh(self, interval: int = None):
        interval = interval or RULE_REFRESH_INTERVAL
        while True:
            await asyncio.sleep(interval)
            await self.refresh()

_loader = None

def get_loader():
    global _loader
    if _loader is None:
        _loader = RuleLoader()
    return _loader
