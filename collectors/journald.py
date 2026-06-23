import asyncio, uuid, time
from collectors.base import BaseCollector

class JournaldCollector(BaseCollector):
    name = "system"

    async def run(self):
        try:
            from systemd import journal
        except ImportError:
            return
        j = journal.Reader()
        j.seek_tail()
        for unit in ["ssh.service", "sshd.service", "sudo.service", "auth.service"]:
            j.add_match(_SYSTEMD_UNIT=unit)

        for entry in j:
            await self.emit({
                "id": str(uuid.uuid4()),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source": "journald",
                "unit": entry.get("_SYSTEMD_UNIT", "unknown"),
                "pid": entry.get("_PID", ""),
                "hostname": entry.get("_HOSTNAME", ""),
                "message": entry.get("MESSAGE", ""),
                "priority": entry.get("PRIORITY", 6),
            })
            await asyncio.sleep(0)
