import json
import time
from config.redis import get_redis
from config.settings import PERSIST_INTERVAL
from engine.baseline import baseline
from engine.matchers import threshold_state, threshold_unique_state

STATE_KEY = "neuralops:state:engine"

class Persistence:
    async def save(self):
        data = {
            "baseline": baseline.serialize(),
            "saved_at": time.time(),
        }
        r = await get_redis()
        await r.set(STATE_KEY, json.dumps(data))
        await r.expire(STATE_KEY, PERSIST_INTERVAL * 3)
        await r.aclose()

    async def load(self):
        r = await get_redis()
        raw = await r.get(STATE_KEY)
        await r.aclose()
        if not raw:
            return
        try:
            data = json.loads(raw)
            if "baseline" in data:
                for ip, info in data["baseline"].items():
                    p = baseline._get(ip)
                    p["total"] = info.get("total", 0)
                    p["methods"].update(info.get("methods", {}))
                    p["statuses"].update(info.get("statuses", {}))
                    p["hours"].update(info.get("hours", {}))
        except (json.JSONDecodeError, TypeError):
            pass

persistence = Persistence()
