#!/usr/bin/env bash
# ==========================================================
#  End-to-End Firewall Performance Benchmark Orchestrator
# ==========================================================
# Runs a standardized performance test using the Client-Attacker-Webserver
# topology to measure firewall throughput, latency, and resilience:
#
#   Phase 1: Baseline Client Performance (Clean state)
#   Phase 2: Stress & Attack Injection (Attacker floods server)
#   Phase 3: Client Performance Under Attack
#   Phase 4: Comparative Performance Report
# ==========================================================

set -euo pipefail

TARGET_IP="${1:-10.10.2.10}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NUM_SAMPLES="${2:-20}"

echo "=========================================================="
echo "      FIREWALL PERFORMANCE BENCHMARK ORCHESTRATOR         "
echo "=========================================================="
echo "[+] Target Webserver: $TARGET_IP"
echo "[+] Sample Count:     $NUM_SAMPLES requests per phase"
echo ""

# Ensure Webserver services are running
bash "$SCRIPT_DIR/traffic_server.sh" >/dev/null 2>&1 || true

measure_http() {
    local target="$1"
    local count="$2"
    local success=0
    local total_time=0

    for i in $(seq 1 "$count"); do
        res=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" "http://${target}:80/" --connect-timeout 2 2>/dev/null || echo "000 0")
        code=$(echo "$res" | awk '{print $1}')
        t=$(echo "$res" | awk '{print $2}')

        if [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ]; then
            success=$((success + 1))
            total_time=$(awk -v a="$total_time" -v b="$t" 'BEGIN { printf "%.6f", a + b }')
        fi
    done

    local avg="0.0000"
    if [ "$success" -gt 0 ]; then
        avg=$(awk -v total="$total_time" -v cnt="$success" 'BEGIN { printf "%.4f", total / cnt }')
    fi
    echo "$success $avg"
}

# ----------------------------------------------------------
# PHASE 1: Baseline Measurements (No Attack)
# ----------------------------------------------------------
echo "----------------------------------------------------------"
echo "[*] PHASE 1: Measuring Baseline Performance (Clean Traffic)"
echo "----------------------------------------------------------"

echo "[1/2] Measuring Client HTTP Latency & Throughput ($NUM_SAMPLES requests)..."
read -r baseline_success baseline_avg_latency <<< "$(measure_http "$TARGET_IP" "$NUM_SAMPLES")"
echo "    -> Baseline HTTP Success: $baseline_success / $NUM_SAMPLES"
echo "    -> Baseline Avg Latency:  ${baseline_avg_latency}s"

echo "[2/2] Measuring Baseline ICMP Ping RTT..."
baseline_rtt=$(ping -c 5 -W 1 "$TARGET_IP" 2>/dev/null | tail -1 | awk -F '/' '{print $5}' || echo "N/A")
if [ -z "$baseline_rtt" ]; then baseline_rtt="N/A"; fi
echo "    -> Baseline Ping RTT:     ${baseline_rtt} ms"

# ----------------------------------------------------------
# PHASE 2 & 3: Performance Under Attack
# ----------------------------------------------------------
echo ""
echo "----------------------------------------------------------"
echo "[*] PHASE 2: Injecting Hostile Traffic (SYN Flood Attack)"
echo "----------------------------------------------------------"
echo "[+] Launching background SYN flood from Attacker..."
bash "$SCRIPT_DIR/traffic_attacker.sh" "$TARGET_IP" syn 10 >/dev/null 2>&1 &
ATTACK_PID=$!

sleep 1

echo ""
echo "----------------------------------------------------------"
echo "[*] PHASE 3: Measuring Client Performance UNDER ATTACK"
echo "----------------------------------------------------------"
echo "[1/2] Measuring Client HTTP Latency Under Attack ($NUM_SAMPLES requests)..."
read -r attack_success attack_avg_latency <<< "$(measure_http "$TARGET_IP" "$NUM_SAMPLES")"
echo "    -> Under-Attack HTTP Success: $attack_success / $NUM_SAMPLES"
echo "    -> Under-Attack Avg Latency:  ${attack_avg_latency}s"

echo "[2/2] Measuring Under-Attack ICMP Ping RTT..."
attack_rtt=$(ping -c 5 -W 1 "$TARGET_IP" 2>/dev/null | tail -1 | awk -F '/' '{print $5}' || echo "N/A")
if [ -z "$attack_rtt" ]; then attack_rtt="N/A"; fi
echo "    -> Under-Attack Ping RTT:     ${attack_rtt} ms"

wait "$ATTACK_PID" 2>/dev/null || true

# ----------------------------------------------------------
# PHASE 4: Summary Report
# ----------------------------------------------------------
echo ""
echo "=========================================================="
echo "              BENCHMARK RESULTS SUMMARY                   "
echo "=========================================================="
printf "%-25s | %-18s | %-18s\n" "Metric" "Baseline (Clean)" "Under Attack"
echo "----------------------------------------------------------"
printf "%-25s | %-18s | %-18s\n" "HTTP Success Rate" "$baseline_success / $NUM_SAMPLES" "$attack_success / $NUM_SAMPLES"
printf "%-25s | %-18s | %-18s\n" "HTTP Latency (Avg)" "${baseline_avg_latency}s" "${attack_avg_latency}s"
printf "%-25s | %-18s | %-18s\n" "Ping RTT (Avg)" "${baseline_rtt} ms" "${attack_rtt} ms"
echo "=========================================================="
echo ""
echo "[+] Benchmark completed successfully."
