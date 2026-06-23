import asyncio
import json
import logging
from config.redis import get_redis
from config.settings import STREAMS, OUTPUT_FILE, SLACK_WEBHOOK

log = logging.getLogger("output")

async def log_to_file(alert: dict):
    with open(OUTPUT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

async def send_slack(alert: dict):
    if not SLACK_WEBHOOK:
        return
    try:
        import aiohttp
        emoji = {"CRITICAL": ":red_circle:", "HIGH": ":orange_circle:", "MEDIUM": ":large_yellow_circle:", "LOW": ":large_blue_circle:"}
        async with aiohttp.ClientSession() as session:
            await session.post(SLACK_WEBHOOK, json={
                "text": f"{emoji.get(alert['severity'], ':question:')} *{alert['severity']}* {alert['rule_name']}\nIP: `{alert['source_ip']}`\n{alert['matched_value'][:200]}",
            })
    except Exception:
        pass

async def main():
    r = await get_redis()
    last_id = "$"
    log.info(f"Writing alerts to {OUTPUT_FILE}")

    while True:
        try:
            result = await r.xread({"neuralops:alerts": last_id}, count=10, block=5000)
            for stream, entries in result:
                for eid, data in entries:
                    last_id = eid
                    await log_to_file(dict(data))
                    if SLACK_WEBHOOK:
                        await send_slack(dict(data))
        except Exception:
            await asyncio.sleep(1)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
