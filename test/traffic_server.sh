#!/usr/bin/env bash
# ==========================================================
#  Webserver Service & Health Monitor
# ==========================================================
# Starts HTTP and benchmark services (Nginx, iperf3) on the
# protected webserver and monitors active connections.
# ==========================================================

set -euo pipefail

WEBSERVER_IP="${WEBSERVER_IP:-10.10.2.10}"
USE_INCUS="${USE_INCUS:-auto}"

# Detect Incus environment
INCUS_EXEC=""
if [ "$USE_INCUS" = "auto" ] || [ "$USE_INCUS" = "1" ]; then
    if command -v incus >/dev/null 2>&1 && incus list 2>/dev/null | grep -q "webserver.*RUNNING"; then
        INCUS_EXEC="incus exec webserver --"
    elif sudo incus list 2>/dev/null | grep -q "webserver.*RUNNING"; then
        INCUS_EXEC="sudo incus exec webserver --"
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
echo "          Starting Webserver Services                     "
echo "=========================================================="
echo "[+] Target Webserver: $WEBSERVER_IP"
if [ -n "$INCUS_EXEC" ]; then
    echo "[+] Execution context: Incus container 'webserver'"
else
    echo "[+] Execution context: Local host / VM"
fi

# 1. Start Nginx HTTP server
echo "[*] Ensuring Nginx is running..."
run_cmd systemctl start nginx 2>/dev/null || run_cmd service nginx start 2>/dev/null || run_cmd nginx 2>/dev/null || {
    echo "[!] Nginx not found or failed to start, starting lightweight Python HTTP server on port 80..."
    run_cmd sh -c 'nohup python3 -m http.server 80 >/tmp/http_server.log 2>&1 &' || true
}

# 2. Start iperf3 server on port 5201
echo "[*] Starting iperf3 server daemon (Port 5201)..."
run_cmd pkill -f "iperf3 -s" 2>/dev/null || true
run_cmd sh -c 'nohup iperf3 -s -D >/tmp/iperf3_server.log 2>&1 &' || true

echo "[+] Webserver services initialized."
echo ""
echo "Listening Ports:"
run_cmd ss -tulpn 2>/dev/null || run_cmd netstat -tulpn 2>/dev/null || true
echo ""
echo "Ready to receive Client and Attacker traffic!"
