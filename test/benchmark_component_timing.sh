#!/usr/bin/env bash
# ==============================================================================
# Firewall Component Execution Timing Benchmark Suite
# ==============================================================================
# Measures and outputs exact hardware nanosecond timings for each individual
# stage of the eBPF packet processing pipeline:
#
#   1. Header Parsing & 5-Tuple Extraction (L2, L3, L4)
#   2. Flow Key & Hash Calculation
#   3. Conntrack Table Lookup (or L1 Cache + L2 Fallback)
#   4. Dynamic Rule Engine Evaluation
#   5. Conntrack State Update / Insert / Delete
#   6. Statistics Counter Increment
#   7. Telemetry RingBuffer Submission
#   8. Total Dataplane Pipeline Duration & Peak Single-Core MPPS
#
# Usage: sudo ./test/benchmark_component_timing.sh [OPTIONS] [NAME]
#   e.g. sudo ./test/benchmark_component_timing.sh --name statefull_timing
#        sudo ./test/benchmark_component_timing.sh --quick
# ==============================================================================

set -euo pipefail

# Terminal colors
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FW_CTL="$ROOT_DIR/build/fw-ctl"
RESULTS_DIR="$ROOT_DIR/benchmark_results"
TXT_BASE_DIR="$RESULTS_DIR/txt"
JSON_BASE_DIR="$RESULTS_DIR/json"

# CLI defaults
BENCH_NAME=""
DATE_STR="$(date +%Y-%m-%d)"
QUICK_MODE=0
JSON_ONLY=0
HTTP_COUNT=50
PING_COUNT=50
UDP_DURATION=3
WEBSERVER_IP="10.10.2.10"

show_help() {
    echo -e "${BOLD}Usage:${RESET} sudo $0 [OPTIONS] [NAME]"
    echo ""
    echo "Options:"
    echo "  -n, --name <name>       Benchmark run name (e.g. statefull_timing, dual_map_timing)"
    echo "  -d, --date <YYYY-MM-DD> Date folder name (default: $(date +%Y-%m-%d))"
    echo "  -q, --quick             Quick mode (20 HTTP requests, 20 pings, 1s UDP)"
    echo "  -j, --json              Output only JSON to stdout"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Output Directories:"
    echo "  TXT Reports:  $TXT_BASE_DIR/<date>/<name>.txt"
    echo "  JSON Results: $JSON_BASE_DIR/<date>/<name>.json"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --quick|-q)
            QUICK_MODE=1
            HTTP_COUNT=20
            PING_COUNT=20
            UDP_DURATION=1
            shift
            ;;
        --name|-n)
            if [ -n "${2:-}" ]; then
                BENCH_NAME="$2"
                shift 2
            else
                echo -e "${RED}[-] Error: --name requires an argument.${RESET}" >&2
                exit 1
            fi
            ;;
        --date|-d)
            if [ -n "${2:-}" ]; then
                DATE_STR="$2"
                shift 2
            else
                echo -e "${RED}[-] Error: --date requires an argument.${RESET}" >&2
                exit 1
            fi
            ;;
        --json|-j)
            JSON_ONLY=1
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        -*)
            echo -e "${RED}[-] Unknown option: $1${RESET}" >&2
            show_help
            exit 1
            ;;
        *)
            if [ -z "$BENCH_NAME" ]; then
                BENCH_NAME="$1"
            else
                echo -e "${RED}[-] Unexpected extra argument: $1${RESET}" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] Please run with sudo: sudo $0 [OPTIONS] [NAME]${RESET}" >&2
    exit 1
fi

if [ ! -x "$FW_CTL" ]; then
    echo -e "${RED}[-] Error: fw-ctl not found at '$FW_CTL'. Run 'make' first.${RESET}" >&2
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -z "$BENCH_NAME" ]; then
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    BENCH_NAME="${CURRENT_BRANCH}_timing_${TIMESTAMP}"
fi
BENCH_NAME="${BENCH_NAME%.json}"
BENCH_NAME="${BENCH_NAME%.txt}"

TXT_DIR="$TXT_BASE_DIR/$DATE_STR"
JSON_DIR="$JSON_BASE_DIR/$DATE_STR"
mkdir -p "$TXT_DIR" "$JSON_DIR"

RESULTS_FILE="$JSON_DIR/${BENCH_NAME}.json"
REPORT_FILE="$TXT_DIR/${BENCH_NAME}.txt"

# Resolve Incus
INCUS_CMD=""
if incus list >/dev/null 2>&1; then
    INCUS_CMD="incus"
elif sudo incus list >/dev/null 2>&1; then
    INCUS_CMD="sudo incus"
else
    echo "[-] Incus not available." >&2
    exit 1
fi

CLIENT_VETH=$($INCUS_CMD config get client volatile.eth0.host_name 2>/dev/null || true)
if [ -z "$CLIENT_VETH" ]; then
    echo "[-] Client container not running." >&2
    exit 1
fi

# Ensure services
$INCUS_CMD exec webserver -- systemctl start nginx 2>/dev/null || true
$INCUS_CMD exec webserver -- pkill -f "iperf3 -s" 2>/dev/null || true
sleep 0.2
$INCUS_CMD exec webserver -- sh -c 'iperf3 -s -D >/dev/null 2>&1' 2>/dev/null || true

# Reset statistics and performance timing map
"$FW_CTL" stats reset >/dev/null 2>&1 || true
"$FW_CTL" perf reset >/dev/null 2>&1 || true

if [ "$JSON_ONLY" -eq 0 ]; then
    echo -e "${BOLD}========================================================================================${RESET}"
    echo -e "${BOLD}         FIREWALL COMPONENT EXECUTION TIMING BENCHMARK (${BENCH_NAME})${RESET}"
    echo -e "${BOLD}========================================================================================${RESET}"
    echo -e "  Branch:     $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'N/A')"
    echo -e "  Date:       $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  Target:     $WEBSERVER_IP (Nginx HTTP, iperf3, ICMP)"
    echo -e "  Workload:   $HTTP_COUNT HTTP requests, $PING_COUNT ICMP pings, ${UDP_DURATION}s UDP stream"
    echo ""
    echo -e "  ${CYAN}[1/3] Generating $HTTP_COUNT HTTP requests...${RESET}"
fi

# 1. HTTP Workload
$INCUS_CMD exec client -- sh -c "
    for i in \$(seq 1 $HTTP_COUNT); do
        curl -s -o /dev/null \"http://${WEBSERVER_IP}/\" --connect-timeout 2 || true
    done
" 2>/dev/null || true

if [ "$JSON_ONLY" -eq 0 ]; then
    echo -e "  ${CYAN}[2/3] Generating $PING_COUNT ICMP Echo requests...${RESET}"
fi

# 2. ICMP Workload
$INCUS_CMD exec client -- ping -c "$PING_COUNT" -i 0.05 "$WEBSERVER_IP" >/dev/null 2>&1 || true

if [ "$JSON_ONLY" -eq 0 ]; then
    echo -e "  ${CYAN}[3/3] Generating ${UDP_DURATION}s UDP packet stream (512B)...${RESET}"
fi

# 3. UDP Workload
$INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -u -b 100M -l 512 -t "$UDP_DURATION" >/dev/null 2>&1 || true

sleep 0.5

# Collect perf timing data
PERF_TEXT=$("$FW_CTL" perf show 2>/dev/null || true)
STATS_JSON=$("$FW_CTL" stats show --json 2>/dev/null || echo "{}")

# Save reports
echo "$PERF_TEXT" > "$REPORT_FILE"
echo "$STATS_JSON" > "$RESULTS_FILE"

# Fix permissions
if [ -n "${SUDO_USER:-}" ]; then
    chown -R "$SUDO_USER:$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")" "$RESULTS_DIR" 2>/dev/null || true
fi

if [ "$JSON_ONLY" -eq 1 ]; then
    cat "$RESULTS_FILE"
else
    echo ""
    cat "$REPORT_FILE"
    echo ""
    echo -e "${GREEN}[+] Benchmark results saved successfully:${RESET}"
    echo -e "    Text Report: $REPORT_FILE"
    echo -e "    JSON Result: $RESULTS_FILE"
    echo -e "${BOLD}========================================================================================${RESET}"
fi
