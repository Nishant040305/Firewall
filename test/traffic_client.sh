#!/usr/bin/env bash
# ==========================================================
#  Legitimate Client Traffic Generator
# ==========================================================
# Simulates normal user behavior against the protected Webserver:
#  - Continuous or burst HTTP requests
#  - Ping / Latency measurement
#  - Throughput testing via iperf3
# ==========================================================

set -euo pipefail

WEBSERVER_IP="${1:-10.10.2.10}"
MODE="${2:-all}" # http, iperf, ping, loop, all
COUNT="${3:-10}"

USE_INCUS="${USE_INCUS:-auto}"
INCUS_EXEC=""
if [ "$USE_INCUS" = "auto" ] || [ "$USE_INCUS" = "1" ]; then
    if command -v incus >/dev/null 2>&1 && incus list 2>/dev/null | grep -q "client.*RUNNING"; then
        INCUS_EXEC="incus exec client --"
    elif sudo incus list 2>/dev/null | grep -q "client.*RUNNING"; then
        INCUS_EXEC="sudo incus exec client --"
    fi
fi

run_cmd() {
    if [ -n "$INCUS_EXEC" ]; then
        $INCUS_EXEC "$@"
    else
        "$@"
    fi
}

echo "=========================================================="
echo "          Client Legitimate Traffic Generator             "
echo "=========================================================="
echo "[+] Target Webserver: $WEBSERVER_IP"
echo "[+] Test Mode:        $MODE"
if [ -n "$INCUS_EXEC" ]; then
    echo "[+] Running from:     Incus container 'client'"
else
    echo "[+] Running from:     Local host / VM"
fi
echo "=========================================================="

test_ping() {
    echo ""
    echo "[*] [1/3] Testing ICMP Ping / Latency to $WEBSERVER_IP (5 packets)..."
    run_cmd ping -c 5 -W 2 "$WEBSERVER_IP" || {
        echo "[!] ICMP Ping failed or dropped."
    }
}

test_http() {
    echo ""
    echo "[*] [2/3] Sending $COUNT HTTP GET requests to http://$WEBSERVER_IP:80 ..."
    success=0
    failed=0
    start_time=$(date +%s%N)

    for i in $(seq 1 "$COUNT"); do
        # Use curl with timing metrics
        res=$(run_cmd curl -s -o /dev/null -w "%{http_code} %{time_total}" "http://$WEBSERVER_IP:80/" --connect-timeout 2 || echo "000 0")
        code=$(echo "$res" | awk '{print $1}')
        time_sec=$(echo "$res" | awk '{print $2}')
        if [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ]; then
            echo "    Request #$i: HTTP $code (Latency: ${time_sec}s) - SUCCESS"
            success=$((success + 1))
        else
            echo "    Request #$i: HTTP $code (Failed / Timeout) - DROP"
            failed=$((failed + 1))
        fi
        sleep 0.1
    done

    end_time=$(date +%s%N)
    total_duration_ms=$(( (end_time - start_time) / 1000000 ))
    echo "[+] HTTP Results: $success Successful | $failed Dropped | Total Duration: ${total_duration_ms}ms"
}

test_iperf() {
    echo ""
    echo "[*] [3/3] Running iperf3 TCP Throughput Benchmark (5 seconds)..."
    run_cmd iperf3 -c "$WEBSERVER_IP" -t 5 -P 2 || {
        echo "[!] iperf3 test failed or port 5201 unreachable."
    }
}

test_loop() {
    echo ""
    echo "[*] Running Continuous HTTP Traffic Loop (Press Ctrl+C to stop)..."
    req=0
    while true; do
        req=$((req + 1))
        res=$(run_cmd curl -s -o /dev/null -w "%{http_code} %{time_total}" "http://$WEBSERVER_IP:80/" --connect-timeout 1 || echo "000 0")
        code=$(echo "$res" | awk '{print $1}')
        time_sec=$(echo "$res" | awk '{print $2}')
        echo "[CLIENT $(date +%T)] Req #$req -> HTTP $code (${time_sec}s)"
        sleep 0.5
    done
}

case "$MODE" in
    ping)
        test_ping
        ;;
    http)
        test_http
        ;;
    iperf)
        test_iperf
        ;;
    loop)
        test_loop
        ;;
    all)
        test_ping
        test_http
        test_iperf
        ;;
    *)
        echo "Unknown mode: $MODE. Available: ping, http, iperf, loop, all"
        exit 1
        ;;
esac

echo ""
echo "[+] Client test run finished."
