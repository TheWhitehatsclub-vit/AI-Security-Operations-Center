#!/usr/bin/env python3
"""Pipeline integration test — injects events and checks alerts appear."""
import sys, os, json, time, uuid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import redis.asyncio as aioredis
from config.settings import REDIS_URL, STREAMS

PASS = 0
FAIL = 0

def ok(msg):
    global PASS; PASS += 1
    print(f"  ✓ {msg}")

def fail(msg):
    global FAIL; FAIL += 1
    print(f"  ✗ {msg}")

async def main():
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await r.ping()
        ok("Redis is alive")
    except Exception as e:
        fail(f"Redis not reachable: {e}")
        return

    tests = [
        {"stream": "logs", "event": {"id": str(uuid.uuid4()), "method": "GET", "path": "/?q=<script>alert(1)</script>", "source_ip": "10.0.0.1", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, "expect": "rule"},
        {"stream": "network", "event": {"id": str(uuid.uuid4()), "alert_type": "port_scan_detected", "src_ip": "10.0.0.2", "dst_ip": "10.0.0.3", "scanned_ports": "22,80,443,8080,8443,3306,5432,6379,9200", "port_count": 9, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, "expect": "rule"},
        {"stream": "system", "event": {"id": str(uuid.uuid4()), "message": "Failed password for root from 10.0.0.4 port 22 ssh2", "source_ip": "10.0.0.4", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, "expect": "rule"},
    ]

    for t in tests:
        stream = STREAMS[t["stream"]]
        await r.xadd(stream, t["event"], maxlen=1000)
        print(f"\n  Injected into {t['stream']} stream")

    print(f"\n  Waiting 5s for engine to process...")
    await asyncio.sleep(5)

    alerts = await r.xrevrange(STREAMS["alerts"], count=100)
    if alerts:
        ok(f"{len(alerts)} alerts found in neuralops:alerts")
        for eid, data in alerts[:5]:
            print(f"    - {data.get('rule_name','?'):30s}  src={data.get('source_ip','?'):15s}  conf={data.get('confidence','?'):>8s}  src={data.get('source','?'):>8s}")
    else:
        fail("No alerts found — is the engine running?")

    # Test FP feedback endpoint
    if alerts:
        alert_id = alerts[0][1].get("id", "")
        if alert_id:
            print("\n  Testing FP feedback API...")
            try:
                import httpx
                async with httpx.AsyncClient() as client:
                    resp = await client.post(f"http://localhost:8002/api/alerts/{alert_id}/fp",
                                             json={"reason": "test"})
                    if resp.status_code == 200:
                        ok("FP feedback API works")
                    else:
                        fail(f"FP feedback API returned {resp.status_code}")
            except Exception as e:
                fail(f"FP feedback API call failed: {e}")

    print(f"\n{'='*50}")
    print(f"  RESULTS: {PASS} passed, {FAIL} failed")
    print(f"{'='*50}")
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
