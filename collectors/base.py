import asyncio, json, logging, os, time
from config.redis import get_redis
from config.settings import STREAMS

log = logging.getLogger(__name__)

HEARTBEAT_PREFIX = "neuralops:heartbeat:"

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

    async def heartbeat(self):
        r = await get_redis()
        try:
            await r.setex(f"{HEARTBEAT_PREFIX}{self.name}", 30,
                          json.dumps({"pid": os.getpid(), "time": time.time()}))
        except Exception:
            pass
        finally:
            await r.aclose()

    async def run(self):
        raise NotImplementedError
