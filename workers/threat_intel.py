import asyncio
import re
import time
import aiohttp
from config.redis import get_redis
from config.settings import STREAMS, ABUSEIPDB_KEY, VIRUSTOTAL_KEY, GREYNOISE_KEY
from shared.schema import make_alert

HASH_RE = re.compile(r"[a-fA-F0-9]{32,64}")
CACHE_TTL = 300
cache = {}

async def check_abuseipdb(session, ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {}
    ck = f"abuse:{ip}"
    if ck in cache and time.time() - cache[ck]["ts"] < CACHE_TTL:
        return cache[ck]["data"]
    try:
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30},
        ) as resp:
            if resp.status == 200:
                data = (await resp.json()).get("data", {})
                cache[ck] = {"data": data, "ts": time.time()}
                return data
    except Exception:
        pass
    return {}

async def check_greynoise(session, ip: str) -> dict:
    if not GREYNOISE_KEY:
        return {}
    ck = f"grey:{ip}"
    if ck in cache and time.time() - cache[ck]["ts"] < CACHE_TTL:
        return cache[ck]["data"]
    try:
        async with session.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": GREYNOISE_KEY},
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                cache[ck] = {"data": data, "ts": time.time()}
                return data
    except Exception:
        pass
    return {}

async def check_vt(session, h: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {}
    ck = f"vt:{h}"
    if ck in cache and time.time() - cache[ck]["ts"] < CACHE_TTL:
        return cache[ck]["data"]
    try:
        async with session.get(
            f"https://www.virustotal.com/api/v3/files/{h}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
        ) as resp:
            if resp.status == 200:
                data = (await resp.json()).get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                result = {"malicious": stats.get("malicious", 0), "total": stats.get("total", 0)}
                cache[ck] = {"data": result, "ts": time.time()}
                return result
    except Exception:
        pass
    return {}

def extract_ips(log: dict) -> list[str]:
    seen = set()
    for k in ["source_ip", "src_ip", "dst_ip", "ip"]:
        v = log.get(k)
        if v and v != "unknown" and v not in seen:
            seen.add(v)
    return list(seen)[:3]

def extract_hashes(log: dict) -> list[str]:
    return list(set(HASH_RE.findall(str(log.values()))))[:3]

async def main():
    r = await get_redis()
    last_ids = {STREAMS[s]: "$" for s in ["logs", "network", "system"]}

    async with aiohttp.ClientSession() as session:
        while True:
            try:
                result = await r.xread(last_ids, count=100, block=5000)
                for stream, entries in result:
                    for eid, data in entries:
                        last_ids[stream] = eid
                        data = dict(data)

                        for ip in extract_ips(data):
                            info = await check_abuseipdb(session, ip)
                            score = info.get("abuseConfidenceScore", 0)
                            if score > 50:
                                alert = make_alert(
                                    rule_name="ThreatIntel",
                                    category="threat_intel",
                                    severity="CRITICAL" if score > 80 else "HIGH",
                                    ttp="T1078",
                                    kill_chain="Delivery",
                                    source_ip=ip,
                                    matched_value=f"AbuseIPDB:{score}%",
                                    raw_log=data,
                                    confidence=score / 100.0,
                                )
                                await r.xadd(STREAMS["alerts"], alert, maxlen=20000)

                            gn = await check_greynoise(session, ip)
                            if gn.get("classification") in ("malicious", "suspicious"):
                                alert = make_alert(
                                    rule_name="GreyNoiseIntel",
                                    category="threat_intel",
                                    severity="HIGH",
                                    ttp="T1078",
                                    kill_chain="Delivery",
                                    source_ip=ip,
                                    matched_value=f"GreyNoise:{gn['classification']}",
                                    raw_log=data,
                                    confidence=0.7,
                                )
                                await r.xadd(STREAMS["alerts"], alert, maxlen=20000)

                        for h in extract_hashes(data):
                            vt = await check_vt(session, h)
                            if vt.get("malicious", 0) > 0:
                                alert = make_alert(
                                    rule_name="VirusTotalIntel",
                                    category="threat_intel",
                                    severity="CRITICAL" if vt["malicious"] > 5 else "HIGH",
                                    ttp="T1204",
                                    kill_chain="Delivery",
                                    source_ip=data.get("source_ip", "unknown"),
                                    matched_value=f"VT:{vt['malicious']}/{vt['total']}",
                                    raw_log=data,
                                    confidence=min(1.0, vt["malicious"] / 20.0),
                                )
                                await r.xadd(STREAMS["alerts"], alert, maxlen=20000)

            except Exception:
                await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
