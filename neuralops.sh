#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
LOGDIR="/tmp/neuralops"
pids=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTION]

Start/stop NeuralOps services. No sudo needed.

Options (pick one):
  --all       Start all services (default if no option given)
  --engine    Start only the detection engine
  --dashboard Start only the SOC dashboard (port 8002)
  --network   Start only the network monitor
  --system    Start only the journald collector
  --server    Start only the demo web server (port 8080)
  --list      Show running services and their PIDs
  --logs      Tail combined live logs (Ctrl+C to stop)
  --stop      Stop all running NeuralOps services
  --help, -h  Show this help

Examples:
  $(basename "$0")                  # start everything
  $(basename "$0") --network        # just network monitor
  $(basename "$0") --stop           # stop all
EOF
    exit 0
}

check_redis() {
    if ! redis-cli ping &>/dev/null; then
        echo -e "  [${YELLOW}*${NC}] Starting Redis..."
        redis-server --daemonize yes
        sleep 1
        if ! redis-cli ping &>/dev/null; then
            echo -e "  [${RED}✗${NC}] Redis failed to start — is it installed?"
            exit 1
        fi
    fi
    echo -e "  [${GREEN}✓${NC}] Redis ready"
}

start_service() {
    local name="$1" cmd="$2" log="$3"
    echo -e "  [${YELLOW}*${NC}] Starting $name..."
    PYTHONPATH="$DIR" nohup python3 "$cmd" &>"$LOGDIR/$log" &
    local pid=$!
    pids+=("$pid")
    sleep 0.5
    if kill -0 "$pid" 2>/dev/null; then
        echo -e "  [${GREEN}✓${NC}] $name (PID $pid)"
    else
        echo -e "  [${RED}✗${NC}] $name failed — check $LOGDIR/$log"
    fi
}

start_all() {
    mkdir -p "$LOGDIR"
    check_redis

    start_service "Demo Web Server (8080)"  "scripts/demo_server.py"    "server.log"
    start_service "Detection Engine"        "workers/detect_engine.py"  "engine.log"
    start_service "SOC Dashboard (8002)"    "gemini/dashboard.py"       "dashboard.log"
    start_service "System Collector"        "collectors/journald.py"    "journald.log"
    start_service "Network Monitor"         "collectors/scapy.py"       "scapy.log"

    # Save PIDs for --stop
    echo "${pids[*]}" > "$LOGDIR/pids"

    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}  NEURALOPS — FULL SYSTEM RUNNING${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo -e "  Dashboard:   ${YELLOW}http://localhost:8002${NC}"
    echo -e "  Web Target:  ${YELLOW}http://localhost:8080${NC}"
    echo ""
    echo "  Send attacks:"
    echo '    curl "http://localhost:8080/search?q=<script>alert(1)</script>"'
    echo '    curl "http://localhost:8080/products?id=1%27+OR+%271%27=%271"'
    echo ""
    echo "  View logs:"
    echo -e "    ${GREEN}$(basename "$0") --logs${NC}"
    echo ""
    echo "  Stop all:"
    echo -e "    ${GREEN}$(basename "$0") --stop${NC}"
    echo -e "${CYAN}============================================================${NC}"
}

stop_all() {
    if [ -f "$LOGDIR/pids" ]; then
        read -ra SAVED_PIDS < "$LOGDIR/pids"
        for pid in "${SAVED_PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        rm -f "$LOGDIR/pids"
    fi
    # Kill all neuralops-related Python processes (SIGTERM first, then SIGKILL)
    for pattern in "workers/detect_engine" "gemini/dashboard" "collectors/scapy" "collectors/journald" "scripts/demo_server" "gemini/worker"; do
        for pid in $(pgrep -f "$pattern" 2>/dev/null); do
            kill "$pid" 2>/dev/null || true
        done
    done
    sleep 1
    for pattern in "workers/detect_engine" "gemini/dashboard" "collectors/scapy" "collectors/journald" "scripts/demo_server" "gemini/worker"; do
        for pid in $(pgrep -f "$pattern" 2>/dev/null); do
            kill -9 "$pid" 2>/dev/null || true
        done
    done
    echo -e "  [${GREEN}✓${NC}] All services stopped"
    exit 0
}

list_status() {
    echo -e "${CYAN}Running NeuralOps services:${NC}"
    found=0
    for proc in \
        "workers/detect_engine:Detection Engine" \
        "gemini/dashboard:SOC Dashboard" \
        "collectors/scapy:Network Monitor" \
        "collectors/journald:System Collector" \
        "scripts/demo_server:Web Server"
    do
        pattern="${proc%%:*}"
        label="${proc##*:}"
        pid=$(pgrep -f "$pattern" 2>/dev/null | head -1)
        if [ -n "$pid" ]; then
            echo -e "  [${GREEN}✓${NC}] $label (PID $pid)"
            found=1
        else
            echo -e "  [${RED}✗${NC}] $label (stopped)"
        fi
    done
    if [ "$found" -eq 0 ]; then
        echo "  (none running)"
    fi
}

case "${1:---all}" in
    --all)
        start_all
        wait
        ;;
    --engine)   check_redis; start_service "Detection Engine" "workers/detect_engine.py" "engine.log"; wait ;;
    --dashboard) check_redis; start_service "SOC Dashboard" "gemini/dashboard.py" "dashboard.log"; wait ;;
    --network)  check_redis; start_service "Network Monitor" "collectors/scapy.py" "scapy.log"; wait ;;
    --system)   check_redis; start_service "System Collector" "collectors/journald.py" "journald.log"; wait ;;
    --server)   start_service "Demo Web Server" "scripts/demo_server.py" "server.log"; wait ;;
    --list)     list_status ;;
    --logs)     mkdir -p "$LOGDIR"; tail -f "$LOGDIR"/*.log 2>/dev/null || echo "No logs yet" ;;
    --stop)     stop_all ;;
    --help|-h)  usage ;;
    *)
        echo -e "  [${RED}✗${NC}] Unknown option: $1"
        usage
        ;;
esac
