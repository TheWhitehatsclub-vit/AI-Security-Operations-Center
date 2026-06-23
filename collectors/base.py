import asyncio
import json
import logging
from config.redis import get_redis
from config.settings import STREAMS

log = logging.getLogger(__name__)

class BaseCollector:
    name = "base"

    async def emit(self, entry: dict):
        r = await get_redis()
        try:
            await r.xadd(STREAMS.get(self.name, STREAMS["logs"]), entry, maxlen=10000)
        except Exception as e:
            log.error(f"[{self.name}] Redis error: {e}")
        finally:
            await r.aclose()

    async def run(self):
        raise NotImplementedError
