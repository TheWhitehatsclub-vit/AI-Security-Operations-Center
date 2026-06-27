#!/usr/bin/env python3
"""
NeuralOps — Launch Script
Detects dependencies, sets up paths, starts services, shows live logs.
Usage:  python3 launch.py
"""

import os, sys, subprocess, time, signal, shutil

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_DIR)
os.environ["PYTHONPATH"] = PROJECT_DIR

LOG_DIR = "/tmp/neuralops"
os.makedirs(LOG_DIR, exist_ok=True)

SERVICES = {
    "redis": {"cmd": None, "check": "redis-cli ping"},
    "server": {
        "cmd": ["python3", "scripts/demo_server.py"],
        "log": f"{LOG_DIR}/server.log",
        "label": "Web Server (port 8080)",
    },
    "engine": {
        "cmd": ["python3", "workers/detect_engine.py"],
        "log": f"{LOG_DIR}/engine.log",
        "label": "Detection Engine (all streams)",
    },
    "dashboard": {
        "cmd": ["python3", "gemini/dashboard.py"],
        "log": f"{LOG_DIR}/dashboard.log",
        "label": "SOC Dashboard (port 8002)",
    },
    "gemini": {
        "cmd": ["python3", "gemini/worker.py"],
        "log": f"{LOG_DIR}/gemini.log",
        "label": "Gemini Analyzer (needs API key)",
    },
    "journald": {
        "cmd": ["python3", "collectors/journald.py"],
        "log": f"{LOG_DIR}/journald.log",
        "label": "System Log Collector (journald)",
    },
    "scapy": {
        "cmd": ["python3", "collectors/scapy.py"],
        "log": f"{LOG_DIR}/scapy.log",
        "label": "Network Sniffer (scapy)",
    },
}

def check_deps():
    missing = []
    try:
        import redis
    except ImportError:
        missing.append("redis")
    try:
        import fastapi
    except ImportError:
        missing.append("fastapi")
    try:
        import httpx
    except ImportError:
        missing.append("httpx")

    if missing:
        print(f"  [!] Missing: {', '.join(missing)}")
        print(f"  -> pip install -r requirements.txt")
        ans = input("  Install now? [Y/n]: ").strip().lower()
        if ans in ("", "y", "yes"):
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("  [✓] Dependencies installed")
            return True
        return False
    return True

def check_redis():
    try:
        result = subprocess.run(["redis-cli", "ping"], capture_output=True, text=True, timeout=3)
        if "PONG" in result.stdout:
            return True
    except:
        pass
    print("  [!] Redis not running")
    ans = input("  Start Redis? [Y/n]: ").strip().lower()
    if ans in ("", "y", "yes"):
        subprocess.run(["redis-server", "--daemonize", "yes"])
        time.sleep(1)
        try:
            result = subprocess.run(["redis-cli", "ping"], capture_output=True, text=True, timeout=3)
            if "PONG" in result.stdout:
                print("  [✓] Redis started")
                return True
        except:
            pass
        print("  [✗] Failed to start Redis. Start manually: redis-server --daemonize yes")
        return False
    return False

def start_service(name, svc):
    if os.path.exists(svc["log"]):
        open(svc["log"], "w").close()

    with open(svc["log"], "a") as f:
        proc = subprocess.Popen(
            svc["cmd"],
            stdout=f, stderr=f,
            env={**os.environ, "PYTHONPATH": PROJECT_DIR},
        )
    return proc

def tail_log(logfile, lines=5):
    if not os.path.exists(logfile):
        return "  (no log yet)"
    with open(logfile) as f:
        content = f.read().strip().split("\n")
    last = content[-lines:] if len(content) > lines else content
    return "\n".join(f"  {l}" for l in last)

def main():
    print()
    print("=" * 60)
    print("  NEURALOPS — Launch Script")
    print("=" * 60)
    print()

    if not check_deps():
        print("  Install dependencies and retry.")
        sys.exit(1)

    if not check_redis():
        print("  Start Redis and retry.")
        sys.exit(1)

    print()
    print("  Select services to start (space-separated numbers):")
    print()
    options = [
        ("1", "server", "Web Target Server (port 8080)"),
        ("2", "engine", "Detection Engine (required)"),
        ("3", "dashboard", "SOC Dashboard (port 8002)"),
        ("4", "gemini", "Gemini Analyzer (needs GEMINI_API_KEY)"),
        ("5", "journald", "System Log Collector (journald)"),
        ("6", "scapy", "Network Monitor (connections)"),
    ]
    for key, _, desc in options:
        print(f"    [{key}] {desc}")
    print(f"    [a] All")
    print(f"    [q] Quit")
    print()

    choice = input("  Choose: ").strip()

    if choice == "q":
        print("  Bye.")
        return

    selected = []
    if choice == "a":
        selected = [name for _, name, _ in options]
    else:
        for ch in choice.split():
            for key, name, _ in options:
                if ch == key:
                    selected.append(name)

    if not selected:
        print("  No services selected.")
        return

    # Clear old alert data for a fresh start
    subprocess.run(["redis-cli", "DEL", "neuralops:logs", "neuralops:network",
                    "neuralops:system", "neuralops:alerts", "neuralops:gemini_analysis"],
                   capture_output=True)

    procs = {}
    for name in selected:
        svc = SERVICES.get(name)
        if not svc:
            continue
        print(f"  Starting [{svc['label']}] ...", end=" ", flush=True)
        try:
            procs[name] = start_service(name, svc)
            time.sleep(1)
            if procs[name].poll() is None:
                print("✓")
            else:
                print("✗ (crashed)")
                print(tail_log(svc["log"]))
        except Exception as e:
            print(f"✗ {e}")

    print()
    print("=" * 60)
    print("  NeuralOps Running")
    print("=" * 60)
    print()
    if "server" in procs:
        print(f"  Web Target:  http://localhost:8080")
    if "dashboard" in procs:
        print(f"  Dashboard:   http://localhost:8002")
    print()
    print("  Send attacks:")
    print(f"    curl 'http://localhost:8080/search?q=<script>alert(1)</script>'")
    print(f"    curl 'http://localhost:8080/products?id=1%27+OR+%271%27=%271'")
    print()
    print("  View logs:")
    for name, proc in procs.items():
        svc = SERVICES.get(name, {})
        if "log" in svc:
            print(f"    tail -f {svc['log']}")
    print()
    print("  Stop all:  Ctrl+C")
    print()

    try:
        while procs:
            for name in list(procs.keys()):
                proc = procs[name]
                if proc.poll() is not None:
                    svc = SERVICES.get(name, {})
                    print(f"  [{svc.get('label', name)}] crashed")
                    print(tail_log(svc.get("log", "")))
                    del procs[name]
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n  Shutting down...")
        for name, proc in procs.items():
            proc.terminate()
            proc.wait()
        print("  All stopped.")

if __name__ == "__main__":
    main()
