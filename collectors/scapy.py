import asyncio, uuid, time
from collections import defaultdict
from collectors.base import BaseCollector

class ScapyCollector(BaseCollector):
    name = "network"

    async def run(self):
        try:
            from scapy.all import sniff, IP, TCP, ARP
        except ImportError:
            return
        sniff(iface="eth0", prn=lambda p: asyncio.run(self._process(p)), store=False)

    async def _process(self, pkt):
        try:
            from scapy.all import IP, TCP, ARP
            entry = {
                "id": str(uuid.uuid4()),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source": "scapy",
            }
            if IP in pkt and TCP in pkt:
                entry.update(src_ip=pkt[IP].src, dst_ip=pkt[IP].dst, dst_port=pkt[TCP].dport,
                             protocol="TCP", flags=str(pkt[TCP].flags), length=len(pkt))
            elif ARP in pkt:
                entry.update(src_ip=pkt[ARP].psrc, dst_ip=pkt[ARP].pdst, protocol="ARP", op=int(pkt[ARP].op))
            else:
                return
            await self.emit(entry)
        except Exception:
            pass
