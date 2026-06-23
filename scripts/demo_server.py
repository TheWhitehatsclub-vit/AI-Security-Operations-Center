#!/usr/bin/env python3
"""
NeuralOps — Demo Target Web Server
Run in Terminal 1:  python3 scripts/demo_server.py
This is the "target" website the attacker hits.
Every request is captured by middleware → pushed to Redis → detected by engine.
"""

import sys, os, time, uuid, uvicorn
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, Request
from collectors.base import BaseCollector

app = FastAPI(title="NeuralOps Demo Target", version="1.0")
collector = BaseCollector()
collector.name = "logs"

@app.middleware("http")
async def capture_request(request: Request, call_next):
    body = await request.body()
    start = time.time()
    response = await call_next(request)
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "demo-server",
        "source_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "path": request.url.path,
        "query": str(request.url.query),
        "body": body.decode(errors="replace")[:500],
        "status": response.status_code,
        "user_agent": request.headers.get("user-agent", ""),
        "latency_ms": round((time.time() - start) * 1000, 2),
    }
    await collector.emit(entry)
    return response

# ── Routes (vulnerable-looking endpoints) ──────────────────────────

@app.get("/")
def home():
    return {"message": "Welcome to NeuralOps Demo", "endpoints": ["/login", "/search", "/products", "/upload"]}

@app.get("/login")
def login(user: str = "", passwd: str = ""):
    if not user or not passwd:
        return {"status": "provide user and passwd params"}
    # Always return 401 to simulate failed auth
    return {"status": "login failed"}, 401

@app.get("/search")
def search(q: str = ""):
    return {"query": q, "results": 0}

@app.get("/products")
def products(id: str = ""):
    return {"product_id": id, "name": "Demo Product"}

@app.post("/upload")
async def upload(request: Request):
    body = await request.body()
    return {"uploaded": len(body), "status": "received"}

if __name__ == "__main__":
    print("=" * 60)
    print("  NEURALOPS — Demo Target Server")
    print("  Open Terminal 2 and start the engine:")
    print("    python3 workers/detect_engine.py")
    print()
    print("  Then attack this server from Terminal 3:")
    print('    curl "http://127.0.0.1:8080/login?user=admin&pass=1%27%2BOR%2B%271%27%3D%271"')
    print('    curl "http://127.0.0.1:8080/search?q=<script>alert(1)</script>"')
    print('    curl "http://127.0.0.1:8080/products?id=../../../etc/passwd"')
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8080)
