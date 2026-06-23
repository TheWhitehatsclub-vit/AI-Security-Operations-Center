#!/usr/bin/env python3
"""
NeuralOps — Payload Injector
Run in Terminal 1:  python3 scripts/inject_payload.py
Asks for a payload, wraps it in HTTP, pushes to Redis.
"""

import json, urllib.parse, uuid, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import redis.asyncio as aioredis
from config.settings import REDIS_URL, STREAMS

async def main():
    print("=" * 60)
    print("  NEURALOPS — Payload Injector")
    print("  Pushes a log to neuralops:logs for the engine to detect")
    print("=" * 60)

    payload = input("\nEnter payload (e.g. onmouseover=\"alert(1)\"): ").strip()
    if not payload:
        print("No payload entered. Exiting.")
        return

    ip = input("Source IP (Enter for default 198.51.100.99): ").strip() or "198.51.100.99"

    encoded = urllib.parse.quote(payload)
    url = f"/search?q={encoded}"

    raw_log = {
        "source_ip": ip,
        "method": "GET",
        "url": url,
        "status": 200,
        "user_agent": "Mozilla/5.0 (injected payload)",
        "body": payload,
    }

    print(f"\n  Raw log to be pushed:")
    print(json.dumps(raw_log, indent=2))

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    eid = await r.xadd(STREAMS["logs"], raw_log, maxlen=100000)
    await r.aclose()

    print(f"\n  ✓ Injected into Redis stream: {STREAMS['logs']}")
    print(f"  ✓ Entry ID: {eid}")
    print(f"\n  Now run the detector in another terminal:")
    print(f"    python3 workers/detect_engine.py")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
