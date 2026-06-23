import asyncio, re, uuid, time
from pathlib import Path
from collectors.base import BaseCollector

FILES = ["/var/log/nginx/access.log", "/var/log/auth.log", "/var/log/apache2/access.log"]
NGINX_RE = re.compile(r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<t>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+)')

class FileTailCollector(BaseCollector):
    name = "logs"

    async def tail(self, path: str):
        if not Path(path).exists():
            return
        with open(path, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.1)
                    continue
                yield line.strip()

    async def run(self):
        tasks = [self._consume(p) for p in FILES]
        await asyncio.gather(*tasks)

    async def _consume(self, path: str):
        async for line in self.tail(path):
            m = NGINX_RE.search(line)
            await self.emit({
                "id": str(uuid.uuid4()),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source": "filetail",
                "source_file": path,
                "source_ip": m.group("ip") if m else "unknown",
                "method": m.group("method") if m else "",
                "path": m.group("path") if m else "",
                "status": int(m.group("status")) if m else 0,
                "raw": line,
            })
