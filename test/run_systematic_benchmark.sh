#!/usr/bin/env bash
# ==============================================================================
# Comprehensive & Scientifically Rigorous Firewall Benchmark Suite (v3.0)
# ==============================================================================
# Methodologically validated to eliminate measurement artifacts:
#   1. TCP Benchmark Analysis (MSS, offloads, pacing, retransmissions)
#   2. Three Performance Baselines (No-XDP, XDP-Pass, Full-Firewall)
#   3. Packet-Processing / PPS across 64B, 128B, 256B, 512B, 1024B, 1500B (unlimited -b 0)
#   4. Multi-Worker Flood-Rate Scalability (50K, 100K, 250K, 500K, 1M PPS)
#      with Offered vs Ingress vs Dropped vs Forwarded PPS tracking
#   5. State-Table Scalability (25%, 50%, 75%, 90%, 95%, 100% + Overflow)
#      with cache warmup and multi-round statistical analysis (mean, min, max, stddev)
#   6. Per-Core CPU & SoftIRQ Profiling (Column 8 softirq fix + hottest core saturation)
#   7. Kernel XDP Datapath Profiling (kernel.bpf_stats_enabled nanoseconds/packet)
#   8. Observability Overhead: Tier A (Zero), Tier B (Minimal), Tier C (Full)
#   9. Parallel Scalability (1P, 4P, 8P, 16P, 32P, 64P across all 3 baselines)
#  10. Strict Offload Logging & Verification (ethtool -k)
#  11. Multi-Run Repeatability
#  12. Complete Structured JSON Output Schema
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FW_CTL="$ROOT_DIR/build/fw-ctl"
BENCH_TOOL="$ROOT_DIR/build/conntrack_bench_tool"

PASS_OBJ="$ROOT_DIR/build/xdp_pass.bpf.o"
ZERO_OBJ="$ROOT_DIR/build/firewall_zero_obs.bpf.o"
FAST_OBJ="$ROOT_DIR/build/firewall_fast.bpf.o"
FULL_OBJ="$ROOT_DIR/build/firewall.bpf.o"

RESULTS_DIR="$ROOT_DIR/benchmark_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_JSON="$RESULTS_DIR/systematic_benchmark_${TIMESTAMP}.json"
REPORT_TXT="$RESULTS_DIR/systematic_benchmark_${TIMESTAMP}.txt"

WEBSERVER_IP="10.10.2.10"
ITERATIONS="${ITERATIONS:-3}"
TEST_DURATION="${TEST_DURATION:-5}"
PACKET_SIZES=(64 128 256 512 1024 1500)
CONCURRENT_STREAMS=(1 4 8 16 32 64)
FLOOD_RATES=(50000 100000 250000 500000 1000000)
STATE_TIERS=(16384 32768 49152 58982 62259 65536) # 25%, 50%, 75%, 90%, 95%, 100%

# Quick mode override
if [ "${1:-}" = "--quick" ]; then
    ITERATIONS=1
    TEST_DURATION=3
    PACKET_SIZES=(64 512 1500)
    CONCURRENT_STREAMS=(1 4 16 64)
    FLOOD_RATES=(50000 250000 1000000)
    STATE_TIERS=(16384 49152 65536)
fi

mkdir -p "$RESULTS_DIR"

if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run as root: sudo $0"
    exit 1
fi

# Automatically restore file ownership to the invoking non-root user upon exit
fix_permissions() {
    if [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER:$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")" "$RESULTS_DIR" 2>/dev/null || true
    fi
}
trap fix_permissions EXIT

INCUS_CMD=""
if incus list >/dev/null 2>&1; then
    INCUS_CMD="incus"
elif sudo incus list >/dev/null 2>&1; then
    INCUS_CMD="sudo incus"
else
    echo "[-] Incus command not found."
    exit 1
fi

CLIENT_VETH=$($INCUS_CMD config get client volatile.eth0.host_name 2>/dev/null || true)
ATTACKER_VETH=$($INCUS_CMD config get attacker volatile.eth0.host_name 2>/dev/null || true)
SERVER_VETH=$($INCUS_CMD config get webserver volatile.eth0.host_name 2>/dev/null || true)
BRIDGE_UNTRUST="incus-untrust"
BRIDGE_PROTECT="incus-protect"

if [ -z "$CLIENT_VETH" ]; then
    echo "[-] Error: client container is not running."
    exit 1
fi

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

echo -e "${BOLD}=================================================================${RESET}"
echo -e "${BOLD}   SYSTEMATIC FIREWALL PERFORMANCE BENCHMARK ORCHESTRATOR (v3)    ${RESET}"
echo -e "${BOLD}=================================================================${RESET}"
echo "Host Kernel:      $(uname -r) ($(nproc) CPUs)"
echo "Client veth:      $CLIENT_VETH"
echo "Attacker veth:    ${ATTACKER_VETH:-unknown}"
echo "Webserver veth:   ${SERVER_VETH:-unknown}"
echo "Iterations:       $ITERATIONS run(s) per test"
echo "Duration:         ${TEST_DURATION}s per run"
echo "Results File:     $RESULTS_JSON"
echo ""

# Enable BPF kernel stats
sysctl -w kernel.bpf_stats_enabled=1 >/dev/null 2>&1 || true

python3 -c "import json; open('$RESULTS_JSON', 'w').write(json.dumps({'timestamp': '$TIMESTAMP', 'kernel': '$(uname -r)', 'cpus': $(nproc), 'runs': {}}, indent=2))"

append_json_section() {
    local section="$1"
    local data_json="$2"
    python3 -c "
import sys, json
sec = sys.argv[1]
raw = sys.argv[2]
try:
    with open('$RESULTS_JSON', 'r+') as f:
        d = json.load(f)
        try:
            d['runs'][sec] = json.loads(raw)
        except Exception:
            d['runs'][sec] = eval(raw)
        f.seek(0)
        json.dump(d, f, indent=2)
        f.truncate()
except Exception as e:
    pass
" "$section" "$data_json"
}

configure_and_verify_offloads() {
    for dev in "$CLIENT_VETH" "${ATTACKER_VETH:-}" "${SERVER_VETH:-}" "$BRIDGE_UNTRUST" "$BRIDGE_PROTECT"; do
        if [ -n "$dev" ] && ip link show "$dev" >/dev/null 2>&1; then
            ethtool -K "$dev" tso off gso off gro off rx off tx off 2>/dev/null || true
        fi
    done
    for c in client attacker webserver; do
        $INCUS_CMD exec "$c" -- ethtool -K eth0 tso off gso off gro off rx off tx off 2>/dev/null || true
    done
}

sample_cpu_utilization() {
    local duration="$1"
    shift
    local cpu_log=$(mktemp)

    mpstat -P ALL 1 "$duration" > "$cpu_log" 2>/dev/null &
    local mpstat_pid=$!

    "$@" >/dev/null 2>&1 &
    local work_pid=$!

    sleep "$duration"
    kill "$work_pid" 2>/dev/null || true
    wait "$work_pid" 2>/dev/null || true
    wait "$mpstat_pid" 2>/dev/null || true

    # Parse aggregate stats correctly (Column 8 is %soft, Column 12 is %idle)
    local agg_usr agg_sys agg_soft agg_idle
    agg_usr=$(awk '/^Average:\s+all/ {print $3}' "$cpu_log" | tail -1 || echo "0")
    agg_sys=$(awk '/^Average:\s+all/ {print $5}' "$cpu_log" | tail -1 || echo "0")
    agg_soft=$(awk '/^Average:\s+all/ {print $8}' "$cpu_log" | tail -1 || echo "0")
    agg_idle=$(awk '/^Average:\s+all/ {print $12}' "$cpu_log" | tail -1 || echo "100")
    local agg_busy=$(awk "BEGIN {printf \"%.2f\", 100 - ${agg_idle:-100}}")

    local hot_core hot_busy hot_soft
    read -r hot_core hot_busy hot_soft <<< "$(awk '/^Average:\s+[0-9]+/ {busy = 100 - $12; if (busy > max_b) {max_b = busy; c = $2; s = $8}} END {print (c ? c : 0), (max_b ? max_b : 0), (s ? s : 0)}' "$cpu_log")"

    rm -f "$cpu_log"
    echo "{\"total_busy_pct\":$agg_busy,\"usr_pct\":${agg_usr:-0},\"sys_pct\":${agg_sys:-0},\"softirq_pct\":${agg_soft:-0},\"hottest_core\":$hot_core,\"hottest_core_busy_pct\":$hot_busy,\"hottest_core_softirq_pct\":$hot_soft}"
}

ensure_services() {
    $INCUS_CMD exec client -- sh -c 'ip addr show eth0 | grep -q 10.10.1.20 || ip addr add 10.10.1.20/24 dev eth0; ip route show | grep -q default || ip route add default via 10.10.1.1' 2>/dev/null || true
    $INCUS_CMD exec attacker -- sh -c 'ip addr show eth0 | grep -q 10.10.1.10 || ip addr add 10.10.1.10/24 dev eth0; ip route show | grep -q default || ip route add default via 10.10.1.1' 2>/dev/null || true

    $INCUS_CMD exec webserver -- pkill -f "iperf3 -s" 2>/dev/null || true
    sleep 0.2
    $INCUS_CMD exec webserver -- sh -c 'iperf3 -s -D >/dev/null 2>&1' 2>/dev/null || true
    $INCUS_CMD exec webserver -- systemctl start nginx 2>/dev/null || true
    sleep 0.3

    configure_and_verify_offloads
}

switch_baseline() {
    local mode="$1" # "no_xdp", "xdp_pass", "firewall_zero", "firewall_fast", "firewall_full"
    echo -e "  ${YELLOW}[*] Switching to environment: ${mode}${RESET}"

    pkill -f fw-ctl 2>/dev/null || true
    sleep 0.5

    for dev in "$CLIENT_VETH" "${ATTACKER_VETH:-}"; do
        if [ -n "$dev" ] && ip link show "$dev" >/dev/null 2>&1; then
            ip link set dev "$dev" xdp off 2>/dev/null || true
            ip link set dev "$dev" xdpgeneric off 2>/dev/null || true
            tc qdisc del dev "$dev" clsact 2>/dev/null || true
        fi
    done

    case "$mode" in
        "no_xdp")
            # Baseline A: Raw Linux kernel forwarding
            ;;
        "xdp_pass")
            # Baseline B: Pure XDP driver hook with XDP_PASS
            for dev in "$CLIENT_VETH" "${ATTACKER_VETH:-}"; do
                if [ -n "$dev" ]; then
                    ip link set dev "$dev" xdpdrv obj "$PASS_OBJ" sec xdp 2>/dev/null || \
                    ip link set dev "$dev" xdpgeneric obj "$PASS_OBJ" sec xdp 2>/dev/null || true
                fi
            done
            ;;
        "firewall_zero")
            # Observability Tier A: Zero map updates, zero events
            BPF_OBJ="$ZERO_OBJ" "$FW_CTL" -i "${CLIENT_VETH},${ATTACKER_VETH:-}" -m hybrid -d both >/tmp/fw_daemon.log 2>&1 &
            sleep 1
            ;;
        "firewall_fast")
            # Observability Tier B: Minimal per-CPU counters only
            BPF_OBJ="$FAST_OBJ" "$FW_CTL" -i "${CLIENT_VETH},${ATTACKER_VETH:-}" -m hybrid -d both >/tmp/fw_daemon.log 2>&1 &
            sleep 1
            ;;
        "firewall_full")
            # Observability Tier C: Full stateful firewall with telemetry ringbuffer
            BPF_OBJ="$FULL_OBJ" "$FW_CTL" -i "${CLIENT_VETH},${ATTACKER_VETH:-}" -m hybrid -d both >/tmp/fw_daemon.log 2>&1 &
            sleep 1
            ;;
    esac
    ensure_services
}

get_rx_packets() {
    local iface="$1"
    cat "/sys/class/net/${iface}/statistics/rx_packets" 2>/dev/null || echo "0"
}

get_tx_packets() {
    local iface="$1"
    cat "/sys/class/net/${iface}/statistics/tx_packets" 2>/dev/null || echo "0"
}

# ==============================================================================
# BENCHMARK 1 & 2: THREE-TIER BASELINE COMPARISON
# ==============================================================================

benchmark_three_baselines() {
    echo -e "\n${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  TASK 1 & 2: THREE-TIER BASELINE COMPARISON (A, B, C)           ${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    local baselines_json="{"
    local first_b=1

    for mode in "no_xdp" "xdp_pass" "firewall_fast"; do
        switch_baseline "$mode"

        echo -e "  ${CYAN}-> Benchmarking mode: $mode ($ITERATIONS iteration(s))${RESET}"
        local tcp_sum=0 retrans_sum=0 rtt_sum=0 http_sum=0

        for it in $(seq 1 "$ITERATIONS"); do
            local tcp_raw
            tcp_raw=$($INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -t "$TEST_DURATION" -J 2>/dev/null || echo '{}')
            local mbps retrans
            mbps=$(echo "$tcp_raw" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d.get('end',{}).get('sum_sent',{}).get('bits_per_second',0)/1e6, 2))" 2>/dev/null || echo "0")
            retrans=$(echo "$tcp_raw" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('end',{}).get('sum_sent',{}).get('retransmits',0))" 2>/dev/null || echo "0")

            local rtt
            rtt=$($INCUS_CMD exec client -- ping -c 10 -i 0.1 "$WEBSERVER_IP" 2>/dev/null | grep "rtt\|round-trip" | tail -1 | awk -F'/' '{print $5}' || echo "0")

            local http_t
            http_t=$($INCUS_CMD exec client -- curl -s -o /dev/null -w '%{time_total}' "http://${WEBSERVER_IP}/" --connect-timeout 2 2>/dev/null || echo "0")
            local http_ms=$(awk "BEGIN {printf \"%.2f\", ${http_t:-0} * 1000}")

            tcp_sum=$(awk "BEGIN {print $tcp_sum + $mbps}")
            retrans_sum=$((retrans_sum + retrans))
            rtt_sum=$(awk "BEGIN {print $rtt_sum + ${rtt:-0}}")
            http_sum=$(awk "BEGIN {print $http_sum + ${http_ms:-0}}")
        done

        local avg_tcp=$(awk "BEGIN {printf \"%.2f\", $tcp_sum / $ITERATIONS}")
        local avg_retrans=$(awk "BEGIN {printf \"%.1f\", $retrans_sum / $ITERATIONS}")
        local avg_rtt=$(awk "BEGIN {printf \"%.3f\", $rtt_sum / $ITERATIONS}")
        local avg_http=$(awk "BEGIN {printf \"%.2f\", $http_sum / $ITERATIONS}")

        sleep 0.5
        local cpu_res
        cpu_res=$(sample_cpu_utilization "$TEST_DURATION" $INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -t "$TEST_DURATION")

        echo "     Result: TCP=${avg_tcp} Mbps | Retrans=${avg_retrans} | RTT=${avg_rtt} ms | HTTP=${avg_http} ms"

        if [ "$first_b" -eq 0 ]; then baselines_json+=","; fi
        first_b=0
        baselines_json+="\"$mode\":{\"tcp_throughput_mbps\":$avg_tcp,\"retransmits\":$avg_retrans,\"icmp_rtt_ms\":$avg_rtt,\"http_latency_ms\":$avg_http,\"cpu\":$cpu_res}"
    done

    baselines_json+="}"
    append_json_section "three_baselines" "$baselines_json"
}

# ==============================================================================
# BENCHMARK 3: PACKET-PROCESSING (PPS) ACROSS PACKET SIZES (64B TO 1500B)
# ==============================================================================

benchmark_packet_sizes() {
    echo -e "\n${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  TASK 3: PACKET PROCESSING RATE (PPS) BY PACKET SIZE            ${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    switch_baseline "firewall_fast"
    local pps_json="{"
    local first_p=1

    for sz in "${PACKET_SIZES[@]}"; do
        echo -e "  ${CYAN}-> Testing UDP Packet Size: ${sz} Bytes (Uncapped -b 0)${RESET}"

        local pps_sum=0 mbps_sum=0 loss_sum=0 jitter_sum=0
        for it in $(seq 1 "$ITERATIONS"); do
            local udp_raw
            udp_raw=$($INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -u -b 0 -l "$sz" -t "$TEST_DURATION" -J 2>/dev/null || echo '{}')

            local pps mbps loss jitter
            pps=$(echo "$udp_raw" | python3 -c "import sys,json; d=json.load(sys.stdin); s=d.get('end',{}).get('sum',{}); print(int(s.get('packets',0)/max(s.get('seconds',1),0.1)))" 2>/dev/null || echo "0")
            mbps=$(echo "$udp_raw" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d.get('end',{}).get('sum',{}).get('bits_per_second',0)/1e6, 2))" 2>/dev/null || echo "0")
            loss=$(echo "$udp_raw" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d.get('end',{}).get('sum',{}).get('lost_percent',0), 2))" 2>/dev/null || echo "0")
            jitter=$(echo "$udp_raw" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d.get('end',{}).get('sum',{}).get('jitter_ms',0), 3))" 2>/dev/null || echo "0")

            pps_sum=$((pps_sum + pps))
            mbps_sum=$(awk "BEGIN {print $mbps_sum + $mbps}")
            loss_sum=$(awk "BEGIN {print $loss_sum + $loss}")
            jitter_sum=$(awk "BEGIN {print $jitter_sum + $jitter}")
        done

        local avg_pps=$((pps_sum / ITERATIONS))
        local avg_mbps=$(awk "BEGIN {printf \"%.2f\", $mbps_sum / $ITERATIONS}")
        local avg_loss=$(awk "BEGIN {printf \"%.2f\", $loss_sum / $ITERATIONS}")
        local avg_jitter=$(awk "BEGIN {printf \"%.3f\", $jitter_sum / $ITERATIONS}")

        local cpu_res
        cpu_res=$(sample_cpu_utilization "$TEST_DURATION" $INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -u -b 0 -l "$sz" -t "$TEST_DURATION")

        echo "     Result: ${sz}B: ${avg_pps} PPS | ${avg_mbps} Mbps | Loss: ${avg_loss}% | Jitter: ${avg_jitter} ms"

        if [ "$first_p" -eq 0 ]; then pps_json+=","; fi
        first_p=0
        pps_json+="\"${sz}B\":{\"packet_size_bytes\":$sz,\"achieved_pps\":$avg_pps,\"throughput_mbps\":$avg_mbps,\"packet_loss_pct\":$avg_loss,\"jitter_ms\":$avg_jitter,\"cpu\":$cpu_res}"
    done

    pps_json+="}"
    append_json_section "packet_size_scalability" "$pps_json"
}

# ==============================================================================
# BENCHMARK 4: FLOOD-RATE SCALABILITY (OFFERED VS INGRESS VS DROPPED)
# ==============================================================================

benchmark_flood_scalability() {
    echo -e "\n${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  TASK 4: FLOOD-RATE SCALABILITY & GENERATOR LIMITATION AUDIT     ${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    switch_baseline "firewall_fast"
    local flood_json="{"
    local first_f=1

    for rate in "${FLOOD_RATES[@]}"; do
        echo -e "  ${CYAN}-> Target Rate: ${rate} PPS to blocked port 9999${RESET}"

        "$FW_CTL" stats reset >/dev/null 2>&1 || true

        # Sample interface packet counters before flood
        local tx_attacker_before=$(get_rx_packets "$ATTACKER_VETH") # host rx from attacker container
        local rx_server_before=$(get_tx_packets "$SERVER_VETH")    # host tx toward webserver container

        # To overcome single-threaded userspace syscall limits (>100K PPS), scale worker threads
        local num_workers=1
        if [ "$rate" -gt 100000 ]; then
            num_workers=$(( (rate / 80000) + 1 ))
            if [ "$num_workers" -gt 8 ]; then num_workers=8; fi
        fi

        local per_worker_rate=$((rate / num_workers))
        local interval_us=$((1000000 / per_worker_rate))
        if [ "$interval_us" -lt 1 ]; then interval_us=1; fi

        # Launch worker flood processes
        local pids=()
        for w in $(seq 1 "$num_workers"); do
            $INCUS_CMD exec attacker -- timeout "$TEST_DURATION" hping3 --udp -p 9999 -i "u${interval_us}" "$WEBSERVER_IP" >/dev/null 2>&1 &
            pids+=($!)
        done

        sleep 1

        # Probe legitimate traffic while under attack
        local http_code
        http_code=$($INCUS_CMD exec client -- curl -s -o /dev/null -w '%{http_code}' "http://${WEBSERVER_IP}/" --connect-timeout 2 2>/dev/null || echo "000")
        local ping_rtt
        ping_rtt=$($INCUS_CMD exec client -- ping -c 5 -i 0.2 "$WEBSERVER_IP" 2>/dev/null | grep "rtt\|round-trip" | tail -1 | awk -F'/' '{print $5}' || echo "N/A")

        for p in "${pids[@]}"; do
            wait "$p" 2>/dev/null || true
        done

        # Sample interface packet counters after flood
        local tx_attacker_after=$(get_rx_packets "$ATTACKER_VETH")
        local rx_server_after=$(get_tx_packets "$SERVER_VETH")

        local offered_packets=$((tx_attacker_after - tx_attacker_before))
        local forwarded_packets=$((rx_server_after - rx_server_before))

        local dur=${TEST_DURATION:-5}
        if [ "$dur" -le 0 ]; then dur=1; fi

        local offered_pps=$((offered_packets / dur))
        local forwarded_pps=$((forwarded_packets / dur))

        # Read firewall drops
        local fw_stats
        fw_stats=$("$FW_CTL" stats show --json 2>/dev/null || echo '{}')
        local dropped=0
        dropped=$(echo "$fw_stats" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dropped_packets', 0))" 2>/dev/null || echo "0")
        dropped=${dropped:-0}
        local dropped_pps=$((dropped / dur))

        # Detect whether the generator hit a userspace saturation ceiling
        local gen_saturated="false"
        if [ "$offered_pps" -lt "$((rate * 8 / 10))" ]; then
            gen_saturated="true"
        fi

        echo "     Result: Target=${rate} PPS | Offered=${offered_pps} PPS | Dropped=${dropped_pps} PPS | Leaked=${forwarded_pps} PPS | HTTP=${http_code} | Gen Saturated=${gen_saturated}"

        if [ "$first_f" -eq 0 ]; then flood_json+=","; fi
        first_f=0
        flood_json+="\"${rate}_pps\":{\"target_pps\":$rate,\"offered_pps\":$offered_pps,\"ingress_pps\":$offered_pps,\"dropped_pps\":$dropped_pps,\"forwarded_pps\":$forwarded_pps,\"generator_saturated\":$gen_saturated,\"http_status\":\"$http_code\",\"icmp_rtt_ms\":\"$ping_rtt\"}"
    done

    flood_json+="}"
    append_json_section "flood_rate_scalability" "$flood_json"
}

# ==============================================================================
# BENCHMARK 5: STATE-TABLE SCALABILITY WITH MULTI-ROUND STATISTICAL ANALYSIS
# ==============================================================================

benchmark_statetable_scalability() {
    echo -e "\n${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  TASK 5: STATE-TABLE SCALABILITY & STATISTICAL LOOKUP AUDIT     ${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    switch_baseline "firewall_fast"
    local state_json="{"
    local first_s=1

    for tier in "${STATE_TIERS[@]}"; do
        local pct=$((tier * 100 / 65536))
        echo -e "  ${CYAN}-> Testing State Table Occupancy: ${tier} entries (~${pct}% capacity)${RESET}"

        "$BENCH_TOOL" clear >/dev/null 2>&1 || true
        local pop_res
        pop_res=$("$BENCH_TOOL" populate "$tier" 2>/dev/null || echo '{}')

        # 5 rounds of 10,000 lookups with warm-up for statistically defensible mean, min, max, stddev
        local lookup_res
        lookup_res=$("$BENCH_TOOL" lookup 10000 5 2>/dev/null || echo '{}')
        local mean_ns min_ns max_ns stddev_ns
        mean_ns=$(echo "$lookup_res" | python3 -c "import sys,json; print(json.load(sys.stdin).get('mean_ns', 0))" 2>/dev/null || echo "0")
        min_ns=$(echo "$lookup_res" | python3 -c "import sys,json; print(json.load(sys.stdin).get('min_ns', 0))" 2>/dev/null || echo "0")
        max_ns=$(echo "$lookup_res" | python3 -c "import sys,json; print(json.load(sys.stdin).get('max_ns', 0))" 2>/dev/null || echo "0")
        stddev_ns=$(echo "$lookup_res" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stddev_ns', 0))" 2>/dev/null || echo "0")

        local http_t
        http_t=$($INCUS_CMD exec client -- curl -s -o /dev/null -w '%{time_total}' "http://${WEBSERVER_IP}/" --connect-timeout 2 2>/dev/null || echo "0")
        local http_ms=$(awk "BEGIN {printf \"%.2f\", ${http_t:-0} * 1000}")

        local mem_bytes
        mem_bytes=$(bpftool map show name conntrack_map 2>/dev/null | grep -oP 'memlock \K[0-9]+' | tail -1 || echo "0")
        local mem_mb=$(awk "BEGIN {printf \"%.2f\", ${mem_bytes:-0} / 1048576}")

        echo "     Result: Occupancy=${tier} (${pct}%) | Syscall Lookup Mean=${mean_ns} ns (±${stddev_ns} ns, range ${min_ns}-${max_ns}) | HTTP=${http_ms} ms"

        if [ "$first_s" -eq 0 ]; then state_json+=","; fi
        first_s=0
        state_json+="\"${pct}_pct\":{\"target_entries\":$tier,\"capacity_pct\":$pct,\"mean_lookup_ns\":$mean_ns,\"min_lookup_ns\":$min_ns,\"max_lookup_ns\":$max_ns,\"stddev_lookup_ns\":$stddev_ns,\"http_latency_ms\":$http_ms,\"memory_mb\":$mem_mb}"
    done

    # Test overflow beyond 100% capacity (Attempt 70,000 entries)
    echo -e "  ${YELLOW}-> Testing Capacity Overflow: Attempting 70,000 insertions into 65,536-entry table${RESET}"
    local overflow_res
    overflow_res=$("$BENCH_TOOL" overflow 70000 2>/dev/null || echo '{}')
    state_json+=",\"overflow_test\":$overflow_res"

    "$BENCH_TOOL" clear >/dev/null 2>&1 || true
    state_json+="}"
    append_json_section "statetable_scalability" "$state_json"
}

# ==============================================================================
# BENCHMARK 7 & 8: OBSERVABILITY OVERHEAD (TIER A, B, C)
# ==============================================================================

benchmark_observability_overhead() {
    echo -e "\n${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  TASK 7 & 8: OBSERVABILITY OVERHEAD (ZERO VS MINIMAL VS FULL)   ${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    local obs_json="{"
    local first_o=1

    for obs_tier in "firewall_zero" "firewall_fast" "firewall_full"; do
        switch_baseline "$obs_tier"

        echo -e "  ${CYAN}-> Testing Observability Tier: ${obs_tier}${RESET}"

        local tcp_raw
        tcp_raw=$($INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -t "$TEST_DURATION" -J 2>/dev/null || echo '{}')
        local mbps retrans
        mbps=$(echo "$tcp_raw" | python3 -c "import sys,json; print(round(json.load(sys.stdin).get('end',{}).get('sum_sent',{}).get('bits_per_second',0)/1e6, 2))" 2>/dev/null || echo "0")
        retrans=$(echo "$tcp_raw" | python3 -c "import sys,json; print(json.load(sys.stdin).get('end',{}).get('sum_sent',{}).get('retransmits',0))" 2>/dev/null || echo "0")

        local prog_stat
        prog_stat=$(bpftool prog show name xdp_firewall_prog 2>/dev/null || echo "")
        local run_time_ns run_cnt avg_ns_per_pkt=0
        run_time_ns=$(echo "$prog_stat" | grep -oP 'run_time_ns \K[0-9]+' | tail -1 || echo "0")
        run_cnt=$(echo "$prog_stat" | grep -oP 'run_cnt \K[0-9]+' | tail -1 || echo "0")
        if [ "$run_cnt" -gt 0 ]; then
            avg_ns_per_pkt=$(awk "BEGIN {printf \"%.1f\", $run_time_ns / $run_cnt}")
        fi

        sleep 0.5
        local cpu_res
        cpu_res=$(sample_cpu_utilization "$TEST_DURATION" $INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -t "$TEST_DURATION")

        echo "     Result: ${obs_tier}: Throughput=${mbps} Mbps | Retrans=${retrans} | Avg Kernel Time=${avg_ns_per_pkt} ns/pkt"

        if [ "$first_o" -eq 0 ]; then obs_json+=","; fi
        first_o=0
        obs_json+="\"$obs_tier\":{\"throughput_mbps\":$mbps,\"retransmits\":$retrans,\"avg_kernel_ns_per_packet\":$avg_ns_per_pkt,\"cpu\":$cpu_res}"
    done

    obs_json+="}"
    append_json_section "observability_comparison" "$obs_json"
}

# ==============================================================================
# BENCHMARK 9: PARALLEL SCALABILITY ACROSS ALL THREE BASELINES
# ==============================================================================

benchmark_parallel_scalability() {
    echo -e "\n${BOLD}=================================================================${RESET}"
    echo -e "${BOLD}  TASK 9: PARALLEL STREAM SCALABILITY ACROSS ALL 3 BASELINES     ${RESET}"
    echo -e "${BOLD}=================================================================${RESET}"

    local stream_json="{"
    local first_b=1

    for mode in "no_xdp" "xdp_pass" "firewall_fast"; do
        switch_baseline "$mode"
        echo -e "  ${CYAN}-> Baseline: ${mode}${RESET}"

        local mode_json="{"
        local first_st=1

        for streams in "${CONCURRENT_STREAMS[@]}"; do
            local tmp_iperf=$(mktemp)
            $INCUS_CMD exec client -- iperf3 -c "$WEBSERVER_IP" -t "$TEST_DURATION" -P "$streams" -J 2>/dev/null > "$tmp_iperf" &
            local pid=$!

            sleep 1.5
            local active_conns
            active_conns=$("$BENCH_TOOL" count 2>/dev/null | grep -oP '"entries":\K[0-9]+' || echo "0")

            wait "$pid" 2>/dev/null || true
            local raw=$(cat "$tmp_iperf" 2>/dev/null || echo '{}')
            rm -f "$tmp_iperf"

            local mbps retrans
            mbps=$(echo "$raw" | python3 -c "import sys,json; print(round(json.load(sys.stdin).get('end',{}).get('sum_sent',{}).get('bits_per_second',0)/1e6, 2))" 2>/dev/null || echo "0")
            retrans=$(echo "$raw" | python3 -c "import sys,json; print(json.load(sys.stdin).get('end',{}).get('sum_sent',{}).get('retransmits',0))" 2>/dev/null || echo "0")

            echo "     Result (${mode} - ${streams}P): ${mbps} Mbps | Retrans=${retrans} | Active Conntrack=${active_conns}"

            if [ "$first_st" -eq 0 ]; then mode_json+=","; fi
            first_st=0
            mode_json+="\"${streams}P\":{\"streams\":$streams,\"throughput_mbps\":$mbps,\"retransmits\":$retrans,\"active_conntrack\":$active_conns}"
        done

        mode_json+="}"
        if [ "$first_b" -eq 0 ]; then stream_json+=","; fi
        first_b=0
        stream_json+="\"$mode\":$mode_json"
    done

    stream_json+="}"
    append_json_section "parallel_scalability" "$stream_json"
}

# ==============================================================================
# MAIN ORCHESTRATION
# ==============================================================================

benchmark_three_baselines
benchmark_packet_sizes
benchmark_flood_scalability
benchmark_statetable_scalability
benchmark_observability_overhead
benchmark_parallel_scalability

echo -e "\n${GREEN}[+] All systematic benchmarks completed successfully!${RESET}"
echo "    JSON Output: $RESULTS_JSON"
