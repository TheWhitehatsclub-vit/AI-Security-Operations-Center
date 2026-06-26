#!/usr/bin/env python3
"""
NeuralOps — Real System Log Collector (journalctl)
Uses journalctl -f to stream logs (more reliable than systemd Python module).
Run:  sudo PYTHONPATH=. python3 collectors/journald.py
"""

import sys, os, json, uuid, time, subprocess, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import redis

r = redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)

STREAM = "neuralops:system"

KEYWORDS = re.compile(
    r"(Failed password|Accepted password|authentication failure|"
    r"sudo\b|COMMAND=|session opened|session closed|"
    r"Invalid user|BREAK-IN|Failed publickey|"
    r"pam_unix|incorrect password|authentication error|"
    r"auth could not identify|conversation failed|"
    r"ncorrect password|unknown user|refused|"
    r"permission denied|authorized)", re.I
)

print("=" * 60)
print("  NEURALOPS — Real System Log Collector")
print("  Streaming: journalctl -f (sudo | auth | ssh)")
print("  Press Ctrl+C to stop")
print("=" * 60)
print()

cmd = ["journalctl", "-f", "-o", "cat", "--no-tail"]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

count = 0
matched = 0

try:
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue

        count += 1
        if count % 50 == 0:
            print(f"  [heartbeat] read={count} matched={matched}", flush=True)

        if KEYWORDS.search(line):
            matched += 1
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            # Try to extract unit name from the line
            unit_match = re.match(r"(\w[\w.-]*)", line)
            unit = unit_match.group(1) if unit_match else "system"

            data = {
                "id": str(uuid.uuid4()),
                "timestamp": ts,
                "source": "journald",
                "unit": unit,
                "message": line,
            }

            try:
                r.xadd(STREAM, data, maxlen=10000)
                print(f"  [system] {line[:150]}", flush=True)
            except Exception as e:
                print(f"  [error] Redis: {e}", flush=True)

except KeyboardInterrupt:
    print("\n  Stopping...")
    proc.terminate()
    print("  Done.")
