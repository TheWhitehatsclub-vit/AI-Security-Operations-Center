import asyncio, uuid, time
from collectors.base import BaseCollector
from fastapi import FastAPI, Request

app = FastAPI()

class MiddlewareCollector(BaseCollector):
    name = "logs"

middleware_collector = MiddlewareCollector()

@app.on_event("startup")
async def start_heartbeat():
    async def heart():
        while True:
            try:
                await middleware_collector.heartbeat()
            except Exception:
                pass
            await asyncio.sleep(15)
    asyncio.create_task(heart())

@app.middleware("http")
async def log_middleware(request: Request, call_next):
    body = await request.body()
    start = time.time()
    response = await call_next(request)
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "fastapi-middleware",
        "source_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "path": request.url.path,
        "query": str(request.url.query),
        "body": body.decode(errors="replace")[:500],
        "status": response.status_code,
        "user_agent": request.headers.get("user-agent", ""),
        "latency_ms": round((time.time() - start) * 1000, 2),
    }
    await middleware_collector.emit(entry)
    return response
