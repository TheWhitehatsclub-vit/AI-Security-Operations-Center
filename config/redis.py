import redis.asyncio as aioredis
from config.settings import REDIS_URL

_pool = None

async def get_redis():
    global _pool
    if _pool is None:
        _pool = aioredis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
    return aioredis.Redis(connection_pool=_pool)

async def close_redis():
    global _pool
    if _pool:
        await _pool.disconnect()
        _pool = None
