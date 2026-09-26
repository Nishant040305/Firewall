#!/usr/bin/env bash
# ==============================================================================
# Comprehensive XDP/eBPF Stateful Firewall Performance Benchmark Suite
# ==============================================================================
# Systematically evaluates the performance characteristics of the stateful
# XDP/eBPF firewall across multiple dimensions:
#
#   Phase 1: Normal Traffic Baseline
#   Phase 2: UDP PPS at Multiple Packet Sizes
#   Phase 3: Stateful Engine Characterization
#   Phase 4: SYN Flood Resilience
#   Phase 5: UDP Flood Resilience
#   Phase 6: Recovery Time Measurement
#
# Environment:
#   - Client (10.10.1.20) on incus-untrust via veth
#   - Attacker (10.10.1.10) on incus-untrust via veth
#   - Webserver (10.10.2.10) on incus-protect via veth
#   - XDP firewall attached on client/attacker veth (Native Driver Mode)
#
# Usage: sudo ./test/benchmark_xdp_firewall.sh [--quick]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FW_CTL="$ROOT_DIR/build/fw-ctl"
RESULTS_DIR="$ROOT_DIR/benchmark_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$RESULTS_DIR/benchmark_${TIMESTAMP}.json"
REPORT_FILE="$RESULTS_DIR/benchmark_${TIMESTAMP}.txt"

# Test parameters (can be overridden)
IPERF_DURATION="${IPERF_DURATION:-10}"
PING_COUNT="${PING_COUNT:-50}"
HTTP_COUNT="${HTTP_COUNT:-50}"
FLOOD_DURATION="${FLOOD_DURATION:-8}"
CONCURRENT_STREAMS="${CONCURRENT_STREAMS:-1 4 8 16 32 64}"
PACKET_SIZES="${PACKET_SIZES:-64 128 512 1024 1500}"
QUICK_MODE=0

WEBSERVER_IP="10.10.2.10"

# Quick mode: shorter tests
if [ "${1:-}" = "--quick" ]; then
    QUICK_MODE=1
    IPERF_DURATION=5
    PING_COUNT=20
    HTTP_COUNT=20
    FLOOD_DURATION=5
    CONCURRENT_STREAMS="1 4 16 64"
    PACKET_SIZES="64 512 1500"
fi

# ==============================================================================
# SETUP & VALIDATION
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run with sudo: sudo $0"
    exit 1
fi

if [ ! -x "$FW_CTL" ]; then
    echo "[-] Error: fw-ctl not found at '$FW_CTL'. Run 'make' first."
    exit 1
fi

mkdir -p "$RESULTS_DIR"

# Automatically restore file ownership to the invoking non-root user upon exit
fix_permissions() {
    if [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER:$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")" "$RESULTS_DIR" 2>/dev/null || true
    fi
}
trap fix_permissions EXIT

# Resolve incus command
INCUS_CMD=""
if incus list >/dev/null 2>&1; then
    INCUS_CMD="incus"
elif sudo incus list >/dev/null 2>&1; then
    INCUS_CMD="sudo incus"
else
    echo "[-] Incus not available."
    exit 1
fi

# Resolve interfaces
CLIENT_VETH=$($INCUS_CMD config get client volatile.eth0.host_name 2>/dev/null || true)
ATTACKER_VETH=$($INCUS_CMD config get attacker volatile.eth0.host_name 2>/dev/null || true)
SERVER_VETH=$($INCUS_CMD config get webserver volatile.eth0.host_name 2>/dev/null || true)
BRIDGE_UNTRUST="incus-untrust"
BRIDGE_PROTECT="incus-protect"

if [ -z "$CLIENT_VETH" ]; then
    echo "[-] Client container not running."
    exit 1
fi

disable_offloads() {
    # Disable TSO/GSO/GRO on all host interfaces to remove virtual 64KB RAM copy distortion
    # for dev in "$CLIENT_VETH" "${ATTACKER_VETH:-}" "${SERVER_VETH:-}" "$BRIDGE_UNTRUST" "$BRIDGE_PROTECT"; do
    #     if [ -n "$dev" ] && ip link show "$dev" >/dev/null 2>&1; then
    #         ethtool -K "$dev" tso off gso off gro off rx off tx off 2>/dev/null || true
    #     fi
    # done
    # # Disable on container eth0 interfaces
    # for c in client attacker webserver; do
    #     $INCUS_CMD exec "$c" -- ethtool -K eth0 tso off gso off gro off rx off tx off 2>/dev/null || true
    #     $INCUS_CMD exec "$c" -- ip link set eth0 txqueuelen 3000 2>/dev/null || true
    # done

    # Optimize host queue lengths and enable RPS to eliminate veth packet drops under multi-stream load
    local num_cpus
    num_cpus=$(nproc 2>/dev/null || echo "20")
    local rps_mask
    rps_mask=$(printf "%x" $(( (1 << num_cpus) - 1 )) 2>/dev/null || echo "fffff")
    sysctl -w net.core.rps_sock_flow_entries=32768 >/dev/null 2>&1 || true

    for dev in "$CLIENT_VETH" "${ATTACKER_VETH:-}" "${SERVER_VETH:-}"; do
        if [ -n "$dev" ] && ip link show "$dev" >/dev/null 2>&1; then
            ip link set "$dev" txqueuelen 3000 2>/dev/null || true
            if [ -d "/sys/class/net/$dev/queues/rx-0" ]; then
                echo "$rps_mask" > "/sys/class/net/$dev/queues/rx-0/rps_cpus" 2>/dev/null || true
                echo 4096 > "/sys/class/net/$dev/queues/rx-0/rps_flow_cnt" 2>/dev/null || true
            fi
        fi
    done

    for c in client attacker webserver; do
        $INCUS_CMD exec "$c" -- ip link set eth0 txqueuelen 3000 2>/dev/null || true
    done

    echo "[+] Queue lengths and RPS multi-core steering applied."
}

# Terminal colors
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
RESET="\033[0m"

# JSON result accumulator
declare -A RESULTS

store_result() {
    local key="$1"
    local value="$2"
    RESULTS["$key"]="$value"
    echo "      -> $key = $value"
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

ensure_services() {
    # Restore container IPs if DHCP lease expired
    $INCUS_CMD exec client -- sh -c '
        if ! ip addr show eth0 | grep -q "10.10.1.20"; then
            ip addr add 10.10.1.20/24 dev eth0 2>/dev/null || true
            ip route add default via 10.10.1.1 2>/dev/null || true
        fi
    ' 2>/dev/null || true
    $INCUS_CMD exec attacker -- sh -c '
        if ! ip addr show eth0 | grep -q "10.10.1.10"; then
            ip addr add 10.10.1.10/24 dev eth0 2>/dev/null || true
            ip route add default via 10.10.1.1 2>/dev/null || true
        fi
    ' 2>/dev/null || true

    # Kill stale iperf3 and restart fresh
    $INCUS_CMD exec webserver -- pkill -f "iperf3 -s" 2>/dev/null || true
    sleep 0.3
    $INCUS_CMD exec webserver -- sh -c 'iperf3 -s -D >/dev/null 2>&1' 2>/dev/null || true

    # Ensure nginx is running
    $INCUS_CMD exec webserver -- systemctl start nginx 2>/dev/null || true
    sleep 0.5

    # Enforce discrete Ethernet frame semantics (disable virtual TSO/GRO/GSO super-packets)
    disable_offloads
}

reset_fw_stats() {
    "$FW_CTL" stats reset >/dev/null 2>&1 || true
}

flush_conntrack() {
    "$FW_CTL" conntrack flush >/dev/null 2>&1 || true
}

get_fw_stats_json() {
    "$FW_CTL" stats show --json 2>/dev/null || echo "{}"
}

count_conntrack_entries() {
    # If firewall is off, conntrack map does not exist
    if ! bpftool map show name conntrack_map >/dev/null 2>&1; then
        echo "N/A"
        return
    fi
    local raw
    raw=$("$FW_CTL" conntrack list 2>/dev/null | grep -E -c "^(TCP|UDP|ICMP)" 2>/dev/null || true)
    local val
    val=$(echo "$raw" | head -1 | tr -dc '0-9')
    echo "${val:-0}"
}

get_active_xdp_prog_id() {
    local pid=""
    if [ -n "${CLIENT_VETH:-}" ]; then
        pid=$(bpftool net show dev "$CLIENT_VETH" 2>/dev/null | awk '/id/ {for(i=1;i<=NF;i++) if($i=="id") {print $(i+1); exit}}')
    fi
    if [ -z "$pid" ] && [ -n "${ATTACKER_VETH:-}" ]; then
        pid=$(bpftool net show dev "$ATTACKER_VETH" 2>/dev/null | awk '/id/ {for(i=1;i<=NF;i++) if($i=="id") {print $(i+1); exit}}')
    fi
    if [ -z "$pid" ]; then
        pid=$(bpftool prog show name xdp_firewall_prog 2>/dev/null | grep -E '^[0-9]+:' | awk -F: '{print $1}' | tail -1)
    fi
    echo "$pid"
}

get_bpf_memory() {
    local pid
    pid=$(get_active_xdp_prog_id)
    local total=0

    if [ -n "$pid" ]; then
        local map_ids
        map_ids=$(bpftool prog show id "$pid" 2>/dev/null | grep -oP 'map_ids \K[0-9,]+' | tr ',' ' ' || true)
        if [ -n "$map_ids" ]; then
            for mid in $map_ids; do
                local mem
                mem=$(bpftool map show id "$mid" 2>/dev/null | grep -oP 'memlock \K[0-9]+' | head -1 || echo "0")
                total=$((total + ${mem:-0}))
            done
            echo "$total"
            return
        fi
    fi

    for map_name in stats_map events_ringbuf rules_map conntrack_map flow_cache_map; do
        local mem=""
        if [ -f "/sys/fs/bpf/firewall/$map_name" ]; then
            mem=$(bpftool map show pinned "/sys/fs/bpf/firewall/$map_name" 2>/dev/null | grep -oP 'memlock \K[0-9]+' | head -1 || echo "0")
        else
            mem=$(bpftool map show name "$map_name" 2>/dev/null | grep -oP 'memlock \K[0-9]+' | tail -1 || echo "0")
        fi
        total=$((total + ${mem:-0}))
    done
    echo "$total"
}

get_bpf_prog_memory() {
    local pid
    pid=$(get_active_xdp_prog_id)
    if [ -n "$pid" ]; then
        local mem
        mem=$(bpftool prog show id "$pid" 2>/dev/null | grep -oP 'memlock \K[0-9]+' | head -1 || echo "0")
        echo "${mem:-0}"
        return
    fi
    local mem
    mem=$(bpftool prog show name xdp_firewall_prog 2>/dev/null | grep -oP 'memlock \K[0-9]+' | tail -1 || echo "0")
    echo "${mem:-0}"
}

measure_cpu_during() {
    # Runs a command while measuring CPU with mpstat
    # Usage: measure_cpu_during <duration> <command...>
    local duration="$1"
    shift
    local cpu_log
    cpu_log=$(mktemp)

    mpstat 1 "$duration" > "$cpu_log" 2>/dev/null &
    local mpstat_pid=$!

    # Run the actual workload
    "$@" 2>/dev/null &
    local work_pid=$!

    sleep "$duration"
    kill "$work_pid" 2>/dev/null || true
    wait "$work_pid" 2>/dev/null || true
    wait "$mpstat_pid" 2>/dev/null || true

    # Parse mpstat output: get average line
    local avg_usr avg_sys avg_sirq avg_idle
    avg_idle=$(tail -1 "$cpu_log" | awk '{print $NF}' || echo "95")
    avg_sirq=$(tail -1 "$cpu_log" | awk '{print $(NF-2)}' || echo "0")
    avg_usr=$(tail -1 "$cpu_log" | awk '{print $4}' || echo "0")
    avg_sys=$(tail -1 "$cpu_log" | awk '{print $6}' || echo "0")

    rm -f "$cpu_log"
    echo "$avg_idle $avg_sirq $avg_usr $avg_sys"
}

# ==============================================================================
# PHASE 1: NORMAL TRAFFIC BASELINE
# ==============================================================================

run_phase1() {
    echo ""
    echo -e "${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  PHASE 1: NORMAL TRAFFIC BASELINE${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    ensure_services
    reset_fw_stats
    flush_conntrack

    # 1.1 TCP Throughput (iperf3)
    echo -e "\n  ${CYAN}[1.1] TCP Throughput (iperf3, ${IPERF_DURATION}s, single stream)${RESET}"
    local tcp_json
    tcp_json=$($INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -t "$IPERF_DURATION" -J 2>/dev/null || echo '{}')
    local tcp_sender tcp_receiver
    tcp_sender=$(echo "$tcp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d['end']['sum_sent']['bits_per_second']/1e6,2))" 2>/dev/null || echo "0")
    tcp_receiver=$(echo "$tcp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d['end']['sum_received']['bits_per_second']/1e6,2))" 2>/dev/null || echo "0")
    tcp_retransmits=$(echo "$tcp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['end']['sum_sent'].get('retransmits',0))" 2>/dev/null || echo "0")
    store_result "tcp_throughput_sender_mbps" "$tcp_sender"
    store_result "tcp_throughput_receiver_mbps" "$tcp_receiver"
    store_result "tcp_retransmits" "$tcp_retransmits"

    # 1.2 ICMP Latency
    echo -e "\n  ${CYAN}[1.2] ICMP Latency (ping, ${PING_COUNT} packets)${RESET}"
    local ping_output
    ping_output=$($INCUS_CMD exec client -- ping -c "$PING_COUNT" -i 0.1 "$WEBSERVER_IP" 2>/dev/null || echo "")
    local rtt_line rtt_min rtt_avg rtt_max rtt_mdev
    rtt_line=$(echo "$ping_output" | grep "rtt\|round-trip" | tail -1)
    rtt_min=$(echo "$rtt_line" | awk -F'[/ ]' '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+$/) {print $i; exit}}' || echo "0")
    rtt_avg=$(echo "$rtt_line" | awk -F '/' '{print $5}' || echo "0")
    rtt_max=$(echo "$rtt_line" | awk -F '/' '{print $6}' || echo "0")
    rtt_mdev=$(echo "$rtt_line" | awk -F '/' '{print $7}' | awk '{print $1}' || echo "0")
    local ping_loss
    ping_loss=$(echo "$ping_output" | grep "packet loss" | grep -oP '\d+(\.\d+)?(?=%)' || echo "0")
    store_result "icmp_rtt_min_ms" "$rtt_min"
    store_result "icmp_rtt_avg_ms" "$rtt_avg"
    store_result "icmp_rtt_max_ms" "$rtt_max"
    store_result "icmp_rtt_mdev_ms" "$rtt_mdev"
    store_result "icmp_packet_loss_pct" "$ping_loss"

    # 1.3 HTTP Transaction Latency
    echo -e "\n  ${CYAN}[1.3] HTTP Transaction Latency (${HTTP_COUNT} sequential requests)${RESET}"
    local http_times_file
    http_times_file=$(mktemp)
    local http_success=0
    for i in $(seq 1 "$HTTP_COUNT"); do
        local t
        t=$($INCUS_CMD exec client -- curl -s -o /dev/null -w '%{time_total}' "http://${WEBSERVER_IP}/" --connect-timeout 2 2>/dev/null || echo "0")
        if [ "$t" != "0" ]; then
            echo "$t" >> "$http_times_file"
            http_success=$((http_success + 1))
        fi
    done

    local http_avg="0" http_p50="0" http_p95="0" http_p99="0"
    if [ "$http_success" -gt 0 ]; then
        http_avg=$(awk '{s+=$1} END {printf "%.4f", s/NR}' "$http_times_file" || echo "0")
        http_p50=$(sort -n "$http_times_file" | awk -v p=0.50 'NR==1{n=int(p*FNR)} NR==n{print; exit}' || echo "$http_avg")
        http_p95=$(sort -n "$http_times_file" | awk -v p=0.95 '{a[NR]=$1} END {print a[int(p*NR)+1]}' || echo "$http_avg")
        http_p99=$(sort -n "$http_times_file" | awk -v p=0.99 '{a[NR]=$1} END {print a[int(p*NR)+1]}' || echo "$http_avg")
    fi
    rm -f "$http_times_file"

    # Convert to milliseconds
    http_avg_ms=$(awk "BEGIN {printf \"%.2f\", $http_avg * 1000}")
    http_p50_ms=$(awk "BEGIN {printf \"%.2f\", ${http_p50:-0} * 1000}")
    http_p95_ms=$(awk "BEGIN {printf \"%.2f\", ${http_p95:-0} * 1000}")
    http_p99_ms=$(awk "BEGIN {printf \"%.2f\", ${http_p99:-0} * 1000}")

    store_result "http_success_rate" "$http_success / $HTTP_COUNT"
    store_result "http_latency_avg_ms" "$http_avg_ms"
    store_result "http_latency_p50_ms" "$http_p50_ms"
    store_result "http_latency_p95_ms" "$http_p95_ms"
    store_result "http_latency_p99_ms" "$http_p99_ms"

    # 1.4 Baseline CPU
    echo -e "\n  ${CYAN}[1.4] Baseline CPU Utilization (idle system, 5s sample)${RESET}"
    local cpu_data
    cpu_data=$(mpstat 1 5 2>/dev/null | tail -1)
    local cpu_idle cpu_sirq
    cpu_idle=$(echo "$cpu_data" | awk '{print $NF}' || echo "99")
    cpu_sirq=$(echo "$cpu_data" | awk '{print $(NF-2)}' || echo "0")
    store_result "baseline_cpu_idle_pct" "$cpu_idle"
    store_result "baseline_cpu_softirq_pct" "$cpu_sirq"

    # 1.5 Memory Baseline
    echo -e "\n  ${CYAN}[1.5] BPF Memory Footprint${RESET}"
    local map_mem prog_mem
    map_mem=$(get_bpf_memory)
    prog_mem=$(get_bpf_prog_memory)
    local total_mem=$((map_mem + prog_mem))
    store_result "bpf_map_memory_bytes" "$map_mem"
    store_result "bpf_prog_memory_bytes" "$prog_mem"
    store_result "bpf_total_memory_bytes" "$total_mem"
    store_result "bpf_total_memory_mb" "$(awk "BEGIN {printf \"%.2f\", $total_mem / 1048576}")"

    # Capture kernel stats snapshot
    local stats_json
    stats_json=$(get_fw_stats_json)
    store_result "phase1_fw_stats" "$stats_json"
}

# ==============================================================================
# PHASE 2: UDP PPS AT MULTIPLE PACKET SIZES
# ==============================================================================

run_phase2() {
    echo ""
    echo -e "${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  PHASE 2: UDP PPS AT MULTIPLE PACKET SIZES${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    ensure_services

    for pkt_size in $PACKET_SIZES; do
        echo -e "\n  ${CYAN}[2.x] UDP PPS with ${pkt_size}-byte packets (iperf3, ${IPERF_DURATION}s)${RESET}"
        reset_fw_stats

        local udp_json
        udp_json=$($INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -u -b 500M -l "$pkt_size" -t "$IPERF_DURATION" -J 2>/dev/null || echo '{}')

        local udp_bps udp_pps udp_jitter udp_lost_pct udp_packets
        udp_bps=$(echo "$udp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d['end']['sum']['bits_per_second']/1e6,2))" 2>/dev/null || echo "0")
        udp_jitter=$(echo "$udp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d['end']['sum']['jitter_ms'],4))" 2>/dev/null || echo "0")
        udp_lost_pct=$(echo "$udp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d['end']['sum']['lost_percent'],2))" 2>/dev/null || echo "0")
        udp_packets=$(echo "$udp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['end']['sum']['packets'])" 2>/dev/null || echo "0")
        udp_pps=$(echo "$udp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); s=d['end']['sum']; print(int(s['packets']/s['seconds']))" 2>/dev/null || echo "0")

        store_result "udp_${pkt_size}B_throughput_mbps" "$udp_bps"
        store_result "udp_${pkt_size}B_pps" "$udp_pps"
        store_result "udp_${pkt_size}B_jitter_ms" "$udp_jitter"
        store_result "udp_${pkt_size}B_loss_pct" "$udp_lost_pct"
        store_result "udp_${pkt_size}B_total_packets" "$udp_packets"

        # CPU during this test (next run with mpstat)
        echo -e "    ${YELLOW}(Measuring CPU during ${pkt_size}B UDP stream...)${RESET}"
        local cpu_log
        cpu_log=$(mktemp)
        mpstat 1 "$IPERF_DURATION" > "$cpu_log" 2>/dev/null &
        local mpstat_pid=$!
        $INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -u -b 500M -l "$pkt_size" -t "$IPERF_DURATION" >/dev/null 2>&1 || true
        wait "$mpstat_pid" 2>/dev/null || true
        local cpu_idle_udp cpu_sirq_udp
        cpu_idle_udp=$(tail -1 "$cpu_log" | awk '{print $NF}' || echo "95")
        cpu_sirq_udp=$(tail -1 "$cpu_log" | awk '{print $(NF-2)}' || echo "0")
        rm -f "$cpu_log"
        store_result "udp_${pkt_size}B_cpu_idle_pct" "$cpu_idle_udp"
        store_result "udp_${pkt_size}B_cpu_softirq_pct" "$cpu_sirq_udp"

        sleep 1
    done
}

# ==============================================================================
# PHASE 3: STATEFUL ENGINE CHARACTERIZATION
# ==============================================================================

run_phase3() {
    echo ""
    echo -e "${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  PHASE 3: STATEFUL ENGINE CHARACTERIZATION${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    ensure_services
    flush_conntrack
    reset_fw_stats

    # 3.1 New Connection Rate (TCP connections/sec)
    echo -e "\n  ${CYAN}[3.1] New TCP Connection Rate (rapid sequential connections)${RESET}"
    local conn_count=200
    if [ "$QUICK_MODE" -eq 1 ]; then conn_count=100; fi

    flush_conntrack
    reset_fw_stats
    local start_time
    start_time=$(date +%s%N)

    # Fire N rapid HTTP connections from client
    $INCUS_CMD exec client -- sh -c "
        for i in \$(seq 1 $conn_count); do
            curl -s -o /dev/null http://${WEBSERVER_IP}/ --connect-timeout 1 &
            if [ \$((i % 20)) -eq 0 ]; then wait; fi
        done
        wait
    " 2>/dev/null || true

    local end_time
    end_time=$(date +%s%N)
    local elapsed_ns=$((end_time - start_time))
    local elapsed_s
    elapsed_s=$(awk "BEGIN {printf \"%.3f\", $elapsed_ns / 1000000000}")
    local conn_per_sec
    conn_per_sec=$(awk "BEGIN {printf \"%.1f\", $conn_count / $elapsed_s}")

    local actual_conns
    actual_conns=$(count_conntrack_entries)
    store_result "new_conn_rate_conns_per_sec" "$conn_per_sec"
    store_result "new_conn_rate_total_fired" "$conn_count"
    store_result "new_conn_rate_elapsed_sec" "$elapsed_s"
    store_result "new_conn_rate_state_entries" "$actual_conns"

    # Get stats to see how many NEW flows were created
    local stats_after
    stats_after=$(get_fw_stats_json)
    local new_flows
    new_flows=$(echo "$stats_after" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('connections_new',0))" 2>/dev/null || echo "0")
    store_result "new_conn_rate_new_flows_tracked" "$new_flows"

    sleep 2

    # 3.2 Concurrent Connection Scalability (iperf3 parallel streams)
    echo -e "\n  ${CYAN}[3.2] Concurrent Connection Scalability (iperf3 parallel streams)${RESET}"
    for streams in $CONCURRENT_STREAMS; do
        echo -e "    ${YELLOW}Testing with -P $streams parallel streams...${RESET}"
        flush_conntrack
        reset_fw_stats

        local iperf_out_tmp
        iperf_out_tmp=$(mktemp)

        # Launch parallel streams in background
        $INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -t 5 -P "$streams" -J 2>/dev/null > "$iperf_out_tmp" &
        local iperf_pid=$!

        # Sample conntrack mid-flight at second 2.5 while all streams are actively transmitting
        sleep 2.5
        local conns_after
        conns_after=$(count_conntrack_entries)

        wait "$iperf_pid" 2>/dev/null || true
        local multi_json
        multi_json=$(cat "$iperf_out_tmp" 2>/dev/null || echo '{}')
        rm -f "$iperf_out_tmp"

        local multi_bps multi_retrans
        multi_bps=$(echo "$multi_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d['end']['sum_sent']['bits_per_second']/1e6,2))" 2>/dev/null || echo "0")
        multi_retrans=$(echo "$multi_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['end']['sum_sent'].get('retransmits',0))" 2>/dev/null || echo "0")

        store_result "scalability_${streams}P_throughput_mbps" "$multi_bps"
        store_result "scalability_${streams}P_retransmits" "$multi_retrans"
        store_result "scalability_${streams}P_conntrack_entries" "$conns_after"

        sleep 1
    done

    # 3.3 State Table Memory Analysis
    echo -e "\n  ${CYAN}[3.3] State Table Memory Analysis${RESET}"
    local mem_0conn mem_after_load
    flush_conntrack
    sleep 0.5
    mem_0conn=$(get_bpf_memory)
    store_result "memory_0_connections_bytes" "$mem_0conn"

    # Generate a burst of connections to fill state table
    $INCUS_CMD exec client -- sh -c "
        for i in \$(seq 1 100); do
            curl -s -o /dev/null http://${WEBSERVER_IP}/ --connect-timeout 1 &
        done
        wait
    " 2>/dev/null || true
    sleep 1

    local conns_now
    conns_now=$(count_conntrack_entries)
    mem_after_load=$(get_bpf_memory)

    store_result "memory_after_load_bytes" "$mem_after_load"
    store_result "memory_after_load_connections" "$conns_now"

    # Memory per connection estimate (from BPF map definition)
    # flow_key=16B + flow_entry=64B = 80B per hash entry, 2 entries per connection = 160B
    store_result "memory_per_connection_bytes" "160"
    store_result "conntrack_map_max_entries" "65536"
    store_result "conntrack_map_max_memory_mb" "$(awk "BEGIN {printf \"%.2f\", 65536 * 160 / 1048576}")"
}

# ==============================================================================
# PHASE 4: SYN FLOOD RESILIENCE
# ==============================================================================

run_phase4() {
    echo ""
    echo -e "${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  PHASE 4: SYN FLOOD ATTACK RESILIENCE${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    ensure_services
    flush_conntrack
    reset_fw_stats

    echo -e "\n  ${CYAN}[4.1] Launching SYN Flood from Attacker (hping3 --flood, ${FLOOD_DURATION}s)${RESET}"
    echo "       Attack: hping3 -S -p 80 --flood $WEBSERVER_IP"

    # Start CPU monitoring
    local cpu_log
    cpu_log=$(mktemp)
    mpstat 1 "$((FLOOD_DURATION + 2))" > "$cpu_log" 2>/dev/null &
    local mpstat_pid=$!

    # Start SYN flood from attacker
    $INCUS_CMD exec attacker -- timeout "$FLOOD_DURATION" hping3 -S -p 80 --flood "$WEBSERVER_IP" >/dev/null 2>&1 &
    local flood_pid=$!

    sleep 1

    # 4.2 Measure client ICMP latency during flood
    echo -e "\n  ${CYAN}[4.2] Client ICMP Latency During SYN Flood${RESET}"
    local ping_flood_output
    ping_flood_output=$($INCUS_CMD exec client -- ping -c 20 -i 0.2 "$WEBSERVER_IP" 2>/dev/null || echo "")
    local flood_rtt_avg flood_rtt_max flood_ping_loss
    flood_rtt_avg=$(echo "$ping_flood_output" | grep "rtt\|round-trip" | tail -1 | awk -F '/' '{print $5}' || echo "N/A")
    flood_rtt_max=$(echo "$ping_flood_output" | grep "rtt\|round-trip" | tail -1 | awk -F '/' '{print $6}' || echo "N/A")
    flood_ping_loss=$(echo "$ping_flood_output" | grep "packet loss" | grep -oP '\d+(\.\d+)?(?=%)' || echo "0")
    store_result "synflood_icmp_rtt_avg_ms" "$flood_rtt_avg"
    store_result "synflood_icmp_rtt_max_ms" "$flood_rtt_max"
    store_result "synflood_icmp_packet_loss_pct" "$flood_ping_loss"

    # 4.3 Measure client HTTP success during flood
    echo -e "\n  ${CYAN}[4.3] Client HTTP Success Rate During SYN Flood${RESET}"
    local flood_http_success=0
    local flood_http_total=20
    local flood_http_time=0
    for i in $(seq 1 $flood_http_total); do
        local res
        res=$($INCUS_CMD exec client -- curl -s -o /dev/null -w '%{http_code} %{time_total}' "http://${WEBSERVER_IP}/" --connect-timeout 2 2>/dev/null || echo "000 0")
        local code t
        code=$(echo "$res" | awk '{print $1}')
        t=$(echo "$res" | awk '{print $2}')
        if [ "$code" = "200" ]; then
            flood_http_success=$((flood_http_success + 1))
            flood_http_time=$(awk "BEGIN {printf \"%.6f\", $flood_http_time + $t}")
        fi
    done
    local flood_http_avg="0"
    if [ "$flood_http_success" -gt 0 ]; then
        flood_http_avg=$(awk "BEGIN {printf \"%.2f\", ($flood_http_time / $flood_http_success) * 1000}")
    fi
    store_result "synflood_http_success_rate" "$flood_http_success / $flood_http_total"
    store_result "synflood_http_success_pct" "$(awk "BEGIN {printf \"%.1f\", $flood_http_success * 100.0 / $flood_http_total}")"
    store_result "synflood_http_avg_latency_ms" "$flood_http_avg"

    # Wait for flood to finish
    wait "$flood_pid" 2>/dev/null || true
    wait "$mpstat_pid" 2>/dev/null || true

    # 4.4 CPU during flood
    echo -e "\n  ${CYAN}[4.4] Host CPU Utilization During SYN Flood${RESET}"
    local flood_cpu_idle flood_cpu_sirq
    flood_cpu_idle=$(tail -1 "$cpu_log" | awk '{print $NF}' || echo "90")
    flood_cpu_sirq=$(tail -1 "$cpu_log" | awk '{print $(NF-2)}' || echo "0")
    local flood_cpu_usage
    flood_cpu_usage=$(awk "BEGIN {printf \"%.1f\", 100 - $flood_cpu_idle}")
    rm -f "$cpu_log"
    store_result "synflood_cpu_usage_pct" "$flood_cpu_usage"
    store_result "synflood_cpu_idle_pct" "$flood_cpu_idle"
    store_result "synflood_cpu_softirq_pct" "$flood_cpu_sirq"

    # 4.5 Firewall drop statistics
    echo -e "\n  ${CYAN}[4.5] Firewall Drop Statistics After SYN Flood${RESET}"
    local fw_stats_flood
    fw_stats_flood=$(get_fw_stats_json)
    local total_pkts dropped_pkts dropped_rule dropped_unsolicited
    total_pkts=$(echo "$fw_stats_flood" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_packets',0))" 2>/dev/null || echo "0")
    dropped_pkts=$(echo "$fw_stats_flood" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dropped_packets',0))" 2>/dev/null || echo "0")
    dropped_rule=$(echo "$fw_stats_flood" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dropped_rule',0))" 2>/dev/null || echo "0")
    dropped_unsolicited=$(echo "$fw_stats_flood" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dropped_unsolicited',0))" 2>/dev/null || echo "0")

    local drop_rate="0"
    if [ "$total_pkts" -gt 0 ]; then
        drop_rate=$(awk "BEGIN {printf \"%.1f\", $dropped_pkts * 100.0 / $total_pkts}")
    fi
    local pps_estimate
    pps_estimate=$(awk "BEGIN {printf \"%.0f\", $total_pkts / $FLOOD_DURATION}")

    store_result "synflood_total_packets_processed" "$total_pkts"
    store_result "synflood_packets_dropped" "$dropped_pkts"
    store_result "synflood_dropped_by_rule" "$dropped_rule"
    store_result "synflood_dropped_unsolicited" "$dropped_unsolicited"
    store_result "synflood_drop_rate_pct" "$drop_rate"
    store_result "synflood_estimated_pps" "$pps_estimate"
    store_result "synflood_state_entries_after" "$(count_conntrack_entries)"
}

# ==============================================================================
# PHASE 5: UDP FLOOD RESILIENCE
# ==============================================================================

run_phase5() {
    echo ""
    echo -e "${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  PHASE 5: UDP FLOOD ATTACK RESILIENCE${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    ensure_services
    flush_conntrack
    reset_fw_stats

    echo -e "\n  ${CYAN}[5.1] Launching UDP Flood to Blocked Port 9999 (hping3 --flood, ${FLOOD_DURATION}s)${RESET}"
    echo "       Attack: hping3 --udp -p 9999 --flood $WEBSERVER_IP"

    local cpu_log
    cpu_log=$(mktemp)
    mpstat 1 "$((FLOOD_DURATION + 2))" > "$cpu_log" 2>/dev/null &
    local mpstat_pid=$!

    $INCUS_CMD exec attacker -- timeout "$FLOOD_DURATION" hping3 --udp -p 9999 --flood "$WEBSERVER_IP" >/dev/null 2>&1 &
    local flood_pid=$!

    sleep 1

    # Concurrent legitimate HTTP
    echo -e "\n  ${CYAN}[5.2] Client HTTP During UDP Flood${RESET}"
    local udpflood_http_success=0
    local udpflood_http_total=15
    for i in $(seq 1 $udpflood_http_total); do
        local code
        code=$($INCUS_CMD exec client -- curl -s -o /dev/null -w '%{http_code}' "http://${WEBSERVER_IP}/" --connect-timeout 2 2>/dev/null || echo "000")
        if [ "$code" = "200" ]; then
            udpflood_http_success=$((udpflood_http_success + 1))
        fi
    done
    store_result "udpflood_http_success_rate" "$udpflood_http_success / $udpflood_http_total"
    store_result "udpflood_http_success_pct" "$(awk "BEGIN {printf \"%.1f\", $udpflood_http_success * 100.0 / $udpflood_http_total}")"

    # Concurrent ping
    echo -e "\n  ${CYAN}[5.3] Client ICMP Latency During UDP Flood${RESET}"
    local udpflood_ping
    udpflood_ping=$($INCUS_CMD exec client -- ping -c 10 -i 0.2 "$WEBSERVER_IP" 2>/dev/null || echo "")
    local udpflood_rtt_avg udpflood_ping_loss
    udpflood_rtt_avg=$(echo "$udpflood_ping" | grep "rtt\|round-trip" | tail -1 | awk -F '/' '{print $5}' || echo "N/A")
    udpflood_ping_loss=$(echo "$udpflood_ping" | grep "packet loss" | grep -oP '\d+(\.\d+)?(?=%)' || echo "0")
    store_result "udpflood_icmp_rtt_avg_ms" "$udpflood_rtt_avg"
    store_result "udpflood_icmp_packet_loss_pct" "$udpflood_ping_loss"

    wait "$flood_pid" 2>/dev/null || true
    wait "$mpstat_pid" 2>/dev/null || true

    # CPU
    echo -e "\n  ${CYAN}[5.4] CPU During UDP Flood${RESET}"
    local udpflood_cpu_idle udpflood_cpu_sirq
    udpflood_cpu_idle=$(tail -1 "$cpu_log" | awk '{print $NF}' || echo "90")
    udpflood_cpu_sirq=$(tail -1 "$cpu_log" | awk '{print $(NF-2)}' || echo "0")
    rm -f "$cpu_log"
    store_result "udpflood_cpu_usage_pct" "$(awk "BEGIN {printf \"%.1f\", 100 - $udpflood_cpu_idle}")"
    store_result "udpflood_cpu_softirq_pct" "$udpflood_cpu_sirq"

    # Drop stats
    echo -e "\n  ${CYAN}[5.5] Firewall Drop Statistics After UDP Flood${RESET}"
    local fw_stats_udp
    fw_stats_udp=$(get_fw_stats_json)
    local udp_total udp_dropped udp_dropped_rule
    udp_total=$(echo "$fw_stats_udp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_packets',0))" 2>/dev/null || echo "0")
    udp_dropped=$(echo "$fw_stats_udp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dropped_packets',0))" 2>/dev/null || echo "0")
    udp_dropped_rule=$(echo "$fw_stats_udp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dropped_rule',0))" 2>/dev/null || echo "0")
    local udp_pps_est
    udp_pps_est=$(awk "BEGIN {printf \"%.0f\", $udp_total / $FLOOD_DURATION}")
    store_result "udpflood_total_packets_processed" "$udp_total"
    store_result "udpflood_packets_dropped" "$udp_dropped"
    store_result "udpflood_dropped_by_rule" "$udp_dropped_rule"
    store_result "udpflood_estimated_drop_pps" "$(awk "BEGIN {printf \"%.0f\", $udp_dropped / $FLOOD_DURATION}")"
    store_result "udpflood_estimated_total_pps" "$udp_pps_est"
}

# ==============================================================================
# PHASE 6: RECOVERY TIME MEASUREMENT
# ==============================================================================

run_phase6() {
    echo ""
    echo -e "${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  PHASE 6: POST-ATTACK RECOVERY TIME${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    ensure_services
    flush_conntrack
    reset_fw_stats

    # Launch a 5-second SYN flood
    echo -e "\n  ${CYAN}[6.1] Launching 5-second SYN Flood, then measuring recovery${RESET}"
    $INCUS_CMD exec attacker -- timeout 5 hping3 -S -p 80 --flood "$WEBSERVER_IP" >/dev/null 2>&1 &
    local flood_pid=$!
    sleep 5
    wait "$flood_pid" 2>/dev/null || true

    # Now measure latency immediately after flood stops
    local recovery_times=()
    for delay in 0 1 2 3 5; do
        if [ "$delay" -gt 0 ]; then sleep 1; fi
        local t
        t=$($INCUS_CMD exec client -- curl -s -o /dev/null -w '%{time_total}' "http://${WEBSERVER_IP}/" --connect-timeout 2 2>/dev/null || echo "999")
        local t_ms
        t_ms=$(awk "BEGIN {printf \"%.2f\", $t * 1000}")
        store_result "recovery_latency_${delay}s_after_flood_ms" "$t_ms"
    done

    # Measure if latency returned to baseline
    local post_rtt
    post_rtt=$($INCUS_CMD exec client -- ping -c 10 -i 0.1 "$WEBSERVER_IP" 2>/dev/null | grep "rtt\|round-trip" | tail -1 | awk -F '/' '{print $5}' || echo "N/A")
    store_result "recovery_icmp_rtt_avg_ms" "$post_rtt"
}

# ==============================================================================
# REPORT GENERATION
# ==============================================================================

generate_report() {
    echo ""
    echo -e "${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  GENERATING PERFORMANCE REPORT${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    # Write JSON results
    echo "{" > "$RESULTS_FILE"
    echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$RESULTS_FILE"
    echo "  \"kernel\": \"$(uname -r)\"," >> "$RESULTS_FILE"
    echo "  \"cpus\": $(nproc)," >> "$RESULTS_FILE"
    echo "  \"xdp_mode\": \"native_driver\"," >> "$RESULTS_FILE"
    echo "  \"client_veth\": \"$CLIENT_VETH\"," >> "$RESULTS_FILE"
    echo "  \"attacker_veth\": \"${ATTACKER_VETH:-unknown}\"," >> "$RESULTS_FILE"
    echo "  \"results\": {" >> "$RESULTS_FILE"
    local first=1
    for key in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
        if [ "$first" -eq 0 ]; then echo "," >> "$RESULTS_FILE"; fi
        first=0
        local val="${RESULTS[$key]}"
        # Try to output as number, fall back to string
        if echo "$val" | grep -qP '^-?\d+\.?\d*$'; then
            printf '    "%s": %s' "$key" "$val" >> "$RESULTS_FILE"
        else
            printf '    "%s": "%s"' "$key" "$val" >> "$RESULTS_FILE"
        fi
    done
    echo "" >> "$RESULTS_FILE"
    echo "  }" >> "$RESULTS_FILE"
    echo "}" >> "$RESULTS_FILE"

    # Write human-readable report
    cat > "$REPORT_FILE" << 'HEADER'
================================================================================
     XDP/eBPF STATEFUL FIREWALL — COMPREHENSIVE PERFORMANCE BENCHMARK REPORT
================================================================================
HEADER
    echo "Date: $(date)" >> "$REPORT_FILE"
    echo "Kernel: $(uname -r)" >> "$REPORT_FILE"
    echo "CPUs: $(nproc)" >> "$REPORT_FILE"
    echo "Client: 10.10.1.20 via $CLIENT_VETH" >> "$REPORT_FILE"
    echo "Attacker: 10.10.1.10 via ${ATTACKER_VETH:-unknown}" >> "$REPORT_FILE"
    echo "Webserver: 10.10.2.10" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    echo "┌─────────────────────────────────────────────────────────────────────┐" >> "$REPORT_FILE"
    echo "│                    NORMAL TRAFFIC PERFORMANCE                      │" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┬─────────────────────────────────┤" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "TCP Throughput (Sender)" "${RESULTS[tcp_throughput_sender_mbps]:-N/A} Mbps" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "TCP Throughput (Receiver)" "${RESULTS[tcp_throughput_receiver_mbps]:-N/A} Mbps" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "TCP Retransmits" "${RESULTS[tcp_retransmits]:-N/A}" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "ICMP RTT (min/avg/max/mdev)" "${RESULTS[icmp_rtt_min_ms]:-?}/${RESULTS[icmp_rtt_avg_ms]:-?}/${RESULTS[icmp_rtt_max_ms]:-?}/${RESULTS[icmp_rtt_mdev_ms]:-?} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "ICMP Packet Loss" "${RESULTS[icmp_packet_loss_pct]:-0}%" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "HTTP Latency (avg)" "${RESULTS[http_latency_avg_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "HTTP Latency (P50/P95/P99)" "${RESULTS[http_latency_p50_ms]:-?}/${RESULTS[http_latency_p95_ms]:-?}/${RESULTS[http_latency_p99_ms]:-?} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "HTTP Success Rate" "${RESULTS[http_success_rate]:-N/A}" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Baseline CPU (idle/softirq)" "${RESULTS[baseline_cpu_idle_pct]:-?}% / ${RESULTS[baseline_cpu_softirq_pct]:-?}%" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┴─────────────────────────────────┤" >> "$REPORT_FILE"

    echo "│                    UDP PPS BY PACKET SIZE                          │" >> "$REPORT_FILE"
    echo "├──────────────┬──────────────┬──────────┬──────────┬────────────────┤" >> "$REPORT_FILE"
    printf "│ %-12s │ %-12s │ %-8s │ %-8s │ %-14s │\n" "Packet Size" "PPS" "Mbps" "Jitter" "CPU idle/sirq" >> "$REPORT_FILE"
    echo "├──────────────┼──────────────┼──────────┼──────────┼────────────────┤" >> "$REPORT_FILE"
    for pkt_size in $PACKET_SIZES; do
        printf "│ %-12s │ %-12s │ %-8s │ %-8s │ %-14s │\n" \
            "${pkt_size}B" \
            "${RESULTS[udp_${pkt_size}B_pps]:-N/A}" \
            "${RESULTS[udp_${pkt_size}B_throughput_mbps]:-N/A}" \
            "${RESULTS[udp_${pkt_size}B_jitter_ms]:-N/A}" \
            "${RESULTS[udp_${pkt_size}B_cpu_idle_pct]:-?}/${RESULTS[udp_${pkt_size}B_cpu_softirq_pct]:-?}" >> "$REPORT_FILE"
    done
    echo "├──────────────┴──────────────┴──────────┴──────────┴────────────────┤" >> "$REPORT_FILE"

    echo "│                    STATEFUL ENGINE                                 │" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┬─────────────────────────────────┤" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "New Connection Rate" "${RESULTS[new_conn_rate_conns_per_sec]:-N/A} conn/s" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Flows Tracked (New Conn Test)" "${RESULTS[new_conn_rate_new_flows_tracked]:-N/A}" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Conntrack Max Entries" "${RESULTS[conntrack_map_max_entries]:-65536}" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Memory per Connection" "${RESULTS[memory_per_connection_bytes]:-160} bytes" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Conntrack Max Memory" "${RESULTS[conntrack_map_max_memory_mb]:-N/A} MB" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "BPF Total Memory" "${RESULTS[bpf_total_memory_mb]:-N/A} MB" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┼─────────────────────────────────┤" >> "$REPORT_FILE"
    echo "│  Scalability (Parallel Streams)   │ Throughput / Conntrack Entries  │" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┼─────────────────────────────────┤" >> "$REPORT_FILE"
    for streams in $CONCURRENT_STREAMS; do
        printf "│  %-31s │ %-21s / %-6s │\n" \
            "${streams} parallel streams" \
            "${RESULTS[scalability_${streams}P_throughput_mbps]:-N/A} Mbps" \
            "${RESULTS[scalability_${streams}P_conntrack_entries]:-?}" >> "$REPORT_FILE"
    done
    echo "├───────────────────────────────────┴─────────────────────────────────┤" >> "$REPORT_FILE"

    echo "│                    SYN FLOOD RESILIENCE                            │" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┬─────────────────────────────────┤" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Total Packets Processed" "${RESULTS[synflood_total_packets_processed]:-N/A}" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Estimated Processing PPS" "${RESULTS[synflood_estimated_pps]:-N/A} pps" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Packets Dropped" "${RESULTS[synflood_packets_dropped]:-N/A}" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Drop Rate" "${RESULTS[synflood_drop_rate_pct]:-N/A}%" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Legit HTTP Success During Flood" "${RESULTS[synflood_http_success_rate]:-N/A} (${RESULTS[synflood_http_success_pct]:-0}%)" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Legit HTTP Latency During Flood" "${RESULTS[synflood_http_avg_latency_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Legit ICMP RTT During Flood" "${RESULTS[synflood_icmp_rtt_avg_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Legit ICMP Loss During Flood" "${RESULTS[synflood_icmp_packet_loss_pct]:-0}%" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "CPU Usage During Flood" "${RESULTS[synflood_cpu_usage_pct]:-N/A}%" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "CPU softirq During Flood" "${RESULTS[synflood_cpu_softirq_pct]:-N/A}%" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┴─────────────────────────────────┤" >> "$REPORT_FILE"

    echo "│                    UDP FLOOD RESILIENCE                            │" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┬─────────────────────────────────┤" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Total Packets Processed" "${RESULTS[udpflood_total_packets_processed]:-N/A}" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Estimated Drop PPS" "${RESULTS[udpflood_estimated_drop_pps]:-N/A} pps" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Legit HTTP Success During Flood" "${RESULTS[udpflood_http_success_rate]:-N/A} (${RESULTS[udpflood_http_success_pct]:-0}%)" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "Legit ICMP RTT During Flood" "${RESULTS[udpflood_icmp_rtt_avg_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "CPU Usage During Flood" "${RESULTS[udpflood_cpu_usage_pct]:-N/A}%" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "CPU softirq During Flood" "${RESULTS[udpflood_cpu_softirq_pct]:-N/A}%" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┴─────────────────────────────────┤" >> "$REPORT_FILE"

    echo "│                    POST-ATTACK RECOVERY                            │" >> "$REPORT_FILE"
    echo "├───────────────────────────────────┬─────────────────────────────────┤" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "HTTP Latency 0s After Flood" "${RESULTS[recovery_latency_0s_after_flood_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "HTTP Latency 1s After Flood" "${RESULTS[recovery_latency_1s_after_flood_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "HTTP Latency 2s After Flood" "${RESULTS[recovery_latency_2s_after_flood_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "HTTP Latency 3s After Flood" "${RESULTS[recovery_latency_3s_after_flood_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "HTTP Latency 5s After Flood" "${RESULTS[recovery_latency_5s_after_flood_ms]:-N/A} ms" >> "$REPORT_FILE"
    printf "│ %-33s │ %-31s │\n" "ICMP RTT Post-Recovery" "${RESULTS[recovery_icmp_rtt_avg_ms]:-N/A} ms" >> "$REPORT_FILE"
    echo "└───────────────────────────────────┴─────────────────────────────────┘" >> "$REPORT_FILE"

    echo "" >> "$REPORT_FILE"
    echo "Results JSON: $RESULTS_FILE" >> "$REPORT_FILE"
    echo "=================================================================================" >> "$REPORT_FILE"

    # Print report to terminal
    cat "$REPORT_FILE"

    echo ""
    echo -e "${GREEN}[+] Results saved:${RESET}"
    echo "    Report: $REPORT_FILE"
    echo "    JSON:   $RESULTS_FILE"
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

echo -e "${BOLD}=================================================================${RESET}"
echo -e "${BOLD}  XDP/eBPF STATEFUL FIREWALL PERFORMANCE BENCHMARK SUITE${RESET}"
echo -e "${BOLD}=================================================================${RESET}"
echo ""
print_environment() {
    echo "  Environment:"
    echo "    Kernel:         $(uname -r)"
    echo "    CPUs:           $(nproc)"
    echo "    Client veth:    $CLIENT_VETH"
    echo "    Attacker veth:  ${ATTACKER_VETH:-unknown}"
    local active_pid
    active_pid=$(get_active_xdp_prog_id)
    local xdp_info=""
    local map_info=""
    if [ -n "$active_pid" ]; then
        xdp_info=$(bpftool prog show id "$active_pid" 2>/dev/null | head -1 | sed 's/^[[:space:]]*//' || true)
        local map_ids
        map_ids=$(bpftool prog show id "$active_pid" 2>/dev/null | grep -oP 'map_ids \K[0-9,]+' | tr ',' ' ' || true)
        for mid in $map_ids; do
            if bpftool map show id "$mid" 2>/dev/null | grep -q "conntrack_map"; then
                map_info=$(bpftool map show id "$mid" 2>/dev/null | head -1 | sed 's/^[[:space:]]*//' || true)
                break
            fi
        done
    fi
    if [ -z "$xdp_info" ]; then
        xdp_info=$(bpftool prog show name xdp_firewall_prog 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//' || true)
    fi
    if [ -z "$map_info" ]; then
        map_info=$(bpftool map show name conntrack_map 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//' || true)
    fi
    echo "    XDP Program:    ${xdp_info:-Not loaded}"
    echo "    Conntrack Map:  ${map_info:-Not loaded}"
    echo ""
}

print_environment

if [ "$QUICK_MODE" -eq 1 ]; then
    echo -e "  ${YELLOW}Mode: QUICK (reduced sample counts)${RESET}"
    echo "  Estimated runtime: ~3 minutes"
else
    echo "  Mode: FULL"
    echo "  Estimated runtime: ~6 minutes"
fi
echo ""

# Ensure webserver services are up
ensure_services

run_phase1
run_phase2
run_phase3
run_phase4
run_phase5
run_phase6
generate_report

echo ""
echo -e "${GREEN}[+] Benchmark suite completed successfully!${RESET}"
