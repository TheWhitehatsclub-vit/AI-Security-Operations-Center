import asyncio, uuid, time, os, re, subprocess
from collections import defaultdict
from collectors.base import BaseCollector

PROC_NET_TCP = "/proc/net/tcp"
PROC_NET_TCP6 = "/proc/net/tcp6"
PROC_NET_ARP = "/proc/net/arp"

SCAN_TOOLS = {"nmap", "masscan", "zmap", "zgrab", "rustscan", "bettercap",
              "ettercap", "arpspoof", "dsniff", "mitmproxy", "responder"}
# Comm names that don't match the binary name — map to canonical tool
COMM_TO_TOOL = {"bettercap": "bettercap", "python3": None}  # python3 checked via cmdline

IP_EXPIRE_SECS = 300
SCAN_WINDOW_SECS = 3
SCAN_PORT_THRESHOLD = 6
LOCAL_SCAN_PORT_THRESHOLD = 5
ARP_POLL_SECS = 3

def parse_proc_net(path):
    entries = []
    try:
        with open(path) as f:
            next(f)
            for line in f:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                loc = parts[1].split(":")
                rem = parts[2].split(":")
                state = int(parts[3], 16)
                uid = parts[7]
                src_port = int(loc[1], 16)
                dst_port = int(rem[1], 16) if rem[1] != "0000" else 0
                entries.append({
                    "src_ip": ".".join(str(int(loc[0][i:i+2], 16)) for i in range(6, -1, -2)),
                    "src_port": src_port,
                    "dst_ip": ".".join(str(int(rem[0][i:i+2], 16)) for i in range(6, -1, -2)),
                    "dst_port": dst_port,
                    "state": state,
                    "uid": uid,
                })
    except (FileNotFoundError, PermissionError):
        pass
    return entries

def parse_proc_arp():
    entries = []
    try:
        with open(PROC_NET_ARP) as f:
            next(f)
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    ip = parts[0]
                    hw_type = parts[1]
                    flags = parts[2]
                    mac = parts[3]
                    if mac and mac != "00:00:00:00:00:00" and ip:
                        entries.append({"ip": ip, "mac": mac, "flags": flags})
    except (FileNotFoundError, PermissionError):
        pass
    return entries

STATE_MAP = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
             5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
             9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING"}

class ScapyCollector(BaseCollector):
    name = "network"

    def __init__(self):
        super().__init__()
        self.prev_set = set()
        self.scan_reported_procs = {}
        self.scan_reported_ips = {}

        self.conn_log = defaultdict(list)
        self.local_burst = []
        self.syn_log = defaultdict(list)
        self.est_log = defaultdict(list)
        self.conn_rate_baseline = defaultdict(lambda: {"window": [], "avg": 0, "std": 0})

        self.arp_map = {}
        self.arp_reported = set()

        self.last_check = time.time()
        self.last_arp_check = 0.0

    def _to_key(self, e):
        return (e["src_ip"], e["src_port"], e["dst_ip"], e["dst_port"], e["state"])

    # ── Process Detection (5ms) ───────────────────────────────────

    async def detect_scan_tools(self):
        try:
            pids = os.listdir("/proc")
        except Exception:
            return False

        found = False
        now = time.time()
        for name in pids:
            if not name.isdigit():
                continue
            tool = await self._identify_proc(name)
            if tool is None:
                continue
            last = self.scan_reported_procs.get(tool, 0)
            if now - last >= 60:
                self.scan_reported_procs[tool] = now
                entry = self._mk("proc_monitor", "scan_tool_detected", tool=tool, src_ip="127.0.0.1")
                await self.emit(entry)
                found = True

        return found

    async def _identify_proc(self, pid):
        """Check comm, exe symlink, and cmdline for scan tool identity."""
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
        except (FileNotFoundError, PermissionError):
            return None
        if name in SCAN_TOOLS:
            return name
        if name in COMM_TO_TOOL:
            return COMM_TO_TOOL[name]

        # Check exe symlink for tools that rename their process name
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            base = os.path.basename(exe)
            if base in SCAN_TOOLS:
                return base
        except (FileNotFoundError, PermissionError, OSError):
            pass

        # Check cmdline for python-based tools (e.g., bettercap via python3)
        try:
            with open(f"/proc/{pid}/cmdline") as f:
                raw = f.read().replace("\0", " ").strip().lower()
        except (FileNotFoundError, PermissionError):
            return None
        for tool in SCAN_TOOLS:
            if tool in raw:
                return tool
        return None

    # ── ARP Spoofing Detection (3s) ──────────────────────────────

    async def check_arp(self):
        entries = parse_proc_arp()
        for e in entries:
            ip, mac = e["ip"], e["mac"]
            prev = self.arp_map.get(ip)
            if prev is not None and prev != mac and ip not in self.arp_reported:
                self.arp_reported.add(ip)
                entry = self._mk("arp_monitor", "arp_spoof_detected",
                                 ip=ip, previous_mac=prev, current_mac=mac)
                await self.emit(entry)
            self.arp_map[ip] = mac

    # ── TCP Analysis (500ms) ─────────────────────────────────────

    def _rate_baseline(self, ip, now, val):
        bl = self.conn_rate_baseline[ip]
        bl["window"].append((now, val))
        cutoff = now - 60
        bl["window"] = [(t, v) for t, v in bl["window"] if t > cutoff]
        vals = [v for _, v in bl["window"]]
        if len(vals) >= 5:
            bl["avg"] = sum(vals) / len(vals)
            bl["std"] = (sum((x - bl["avg"])**2 for x in vals) / len(vals))**0.5
        return bl

    async def _poll(self):
        now = time.time()

        # Expire stale scanner IPs
        for ip in list(self.scan_reported_ips.keys()):
            if now > self.scan_reported_ips[ip]:
                del self.scan_reported_ips[ip]

        tcp4 = parse_proc_net(PROC_NET_TCP)
        tcp6 = parse_proc_net(PROC_NET_TCP6)
        entries = tcp4 + tcp6

        current_set = set()
        for e in entries:
            key = self._to_key(e)
            current_set.add(key)

            src, dst = e["src_ip"], e["dst_ip"]
            dport = e["dst_port"]
            sport = e["src_port"]
            st = e["state"]

            if not dport or src == "0.0.0.0":
                continue

            # External IP connections (ESTABLISHED or TIME_WAIT)
            if st in (1, 6) and src not in ("127.0.0.1", "::1"):
                self.conn_log[src].append((now, dport))

            # Localhost TIME_WAIT as scan evidence
            if st == 6 and src in ("127.0.0.1", "::1"):
                self.local_burst.append((now, dport))

            # Track SYN_SENT / ESTABLISHED ratio per source
            if st == 2:
                self.syn_log[src].append(now)
            if st == 1:
                self.est_log[src].append(now)

        # ── New connections (external IPs only) ──
        new_keys = current_set - self.prev_set
        for key in new_keys:
            src_ip, src_port, dst_ip, dst_port, state = key
            if not dst_port or src_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                continue
            entry = self._mk("tcp_monitor", "connection",
                             src_ip=src_ip, src_port=src_port,
                             dst_ip=dst_ip, dst_port=dst_port,
                             state=STATE_MAP.get(state, "UNKNOWN"))
            await self.emit(entry)

        # ── Scan / anomaly detection every 1s ──
        if now - self.last_check >= 1:
            self.last_check = now
            cutoff = now - SCAN_WINDOW_SECS
            c5 = now - 5

            # External IP burst scan
            for ip, events in list(self.conn_log.items()):
                if ip in self.scan_reported_ips:
                    continue
                events[:] = [(t, p) for t, p in events if t > cutoff]
                ports = {p for _, p in events if p}
                if len(ports) >= SCAN_PORT_THRESHOLD:
                    self.scan_reported_ips[ip] = now + IP_EXPIRE_SECS
                    await self._emit_scan(ip, sorted(ports), "external")

            # Localhost scan evidence (TIME_WAIT burst)
            self.local_burst[:] = [(t, p) for t, p in self.local_burst if t > cutoff]
            local_ports = {p for _, p in self.local_burst if p}
            if len(local_ports) >= LOCAL_SCAN_PORT_THRESHOLD:
                if "127.0.0.1" not in self.scan_reported_ips:
                    self.scan_reported_ips["127.0.0.1"] = now + IP_EXPIRE_SECS
                    await self._emit_scan("127.0.0.1", sorted(local_ports), "localhost")

            # SYN/EST ratio anomaly (high SYN with low ESTABLISHED = scan)
            for ip in list(self.syn_log.keys()):
                syns = [t for t in self.syn_log[ip] if t > c5]
            for ip in list(self.est_log.keys()):
                ests = [t for t in self.est_log[ip] if t > c5]
            common = set(list(self.syn_log.keys())[:50]) & set(list(self.est_log.keys())[:50])
            for ip in common:
                syn_count = len([t for t in self.syn_log[ip] if t > c5])
                est_count = len([t for t in self.est_log[ip] if t > c5])
                if syn_count >= 8 and (est_count == 0 or syn_count / max(est_count, 1) > 5):
                    bl = self.conn_rate_baseline.get(ip, {}).get("avg", 0)
                    bl_std = self.conn_rate_baseline.get(ip, {}).get("std", 0)
                    anom = ""
                    if bl > 0 and bl_std > 0 and syn_count > bl + 3 * bl_std:
                        anom = " [baseline deviation]"
                    entry = self._mk("tcp_monitor", "syn_scan_pattern",
                                     src_ip=ip, syn_count=syn_count, est_count=est_count,
                                     ratio=round(syn_count / max(est_count, 1), 1),
                                     detail=f"SYN:{syn_count} EST:{est_count}{anom}")
                    await self.emit(entry)

        self.prev_set = current_set

    async def _emit_scan(self, ip, ports, scan_type):
        entry = self._mk("tcp_monitor", "port_scan_detected",
                         src_ip=ip, scanned_ports=",".join(str(p) for p in ports[:50]),
                         port_count=len(ports),
                         window_seconds=SCAN_WINDOW_SECS,
                         scan_type=scan_type)
        await self.emit(entry)

    def _mk(self, source, alert_type, **kw):
        entry = {"id": str(uuid.uuid4()),
                 "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "source": source, "alert_type": alert_type}
        entry.update(kw)
        return entry

    # ── Run Loop ──────────────────────────────────────────────────

    async def run(self):
        async def heart():
            while True:
                try:
                    await self.heartbeat()
                except Exception:
                    pass
                await asyncio.sleep(15)

        async def fast_watcher():
            while True:
                try:
                    await self.detect_scan_tools()
                except Exception:
                    pass
                await asyncio.sleep(0.005)

        async def tcp_poller():
            while True:
                try:
                    await self._poll()
                except Exception:
                    pass
                await asyncio.sleep(0.5)

        async def arp_poller():
            while True:
                try:
                    await self.check_arp()
                except Exception:
                    pass
                await asyncio.sleep(1.0)

        await asyncio.gather(heart(), fast_watcher(), tcp_poller(), arp_poller())


async def main():
    c = ScapyCollector()
    c.name = "network"
    print("  Network Monitor started. Watching /proc/net/tcp + arp + processes...")
    await c.run()

if __name__ == "__main__":
    asyncio.run(main())
