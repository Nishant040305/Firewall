#!/usr/bin/env bash
# Sets up Incus networks and containers for firewall testing.
# Usage: ./setup_env.sh [IMAGE_NAME]
# Default: images:debian/12 (e.g. images:ubuntu/24.04, images:fedora/40, images:alpine/3.20)
set -euo pipefail

IMAGE="${1:-images:debian/12}"
echo "[+] Using container image: $IMAGE"

INCUS_CMD="incus"
if ! incus list >/dev/null 2>&1; then
    INCUS_CMD="sudo incus"
fi

echo "[+] Creating Incus virtual networks (temporarily with NAT for package installation)..."
$INCUS_CMD network create incus-mgmt ipv4.address=10.10.99.1/24 ipv4.nat=true ipv6.address=none || true
$INCUS_CMD network create incus-untrust ipv4.address=10.10.1.1/24 ipv4.nat=true ipv6.address=none || true
$INCUS_CMD network create incus-protect ipv4.address=10.10.2.1/24 ipv4.nat=true ipv6.address=none || true

echo "[+] Launching containers..."
# Untrusted network (Client & Attacker)
$INCUS_CMD init "$IMAGE" attacker --network incus-untrust || true
$INCUS_CMD config device set attacker eth0 ipv4.address 10.10.1.10 || true
$INCUS_CMD start attacker || true

$INCUS_CMD init "$IMAGE" client --network incus-untrust || true
$INCUS_CMD config device set client eth0 ipv4.address 10.10.1.20 || true
$INCUS_CMD start client || true

# Protected network (Server)
$INCUS_CMD init "$IMAGE" webserver --network incus-protect || true
$INCUS_CMD config device set webserver eth0 ipv4.address 10.10.2.10 || true
$INCUS_CMD start webserver || true

# Management network (Admin workstation)
$INCUS_CMD init "$IMAGE" admin --network incus-mgmt || true
$INCUS_CMD config device set admin eth0 ipv4.address 10.10.99.10 || true
$INCUS_CMD start admin || true

# Ensure host forwarding and firewall allow container traffic
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sudo iptables -P FORWARD ACCEPT 2>/dev/null || true

echo "[+] Waiting for containers to initialize networking..."
sleep 5

echo "[+] Installing test tools inside containers (IPv4)..."
for c in webserver attacker client admin; do
    $INCUS_CMD exec "$c" -- sh -c '
        echo "Acquire::ForceIPv4 \"true\";" > /etc/apt/apt.conf.d/99force-ipv4
        sed -i "s|deb.debian.org|azure.deb.debian.cloud|g" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
    ' || true
done

$INCUS_CMD exec webserver -- sh -c 'apt-get update -y && apt-get install -y nginx curl tcpdump iperf3' || true
$INCUS_CMD exec attacker -- sh -c 'apt-get update -y && apt-get install -y hping3 nmap curl iperf3 netcat-openbsd' || true
$INCUS_CMD exec client -- sh -c 'apt-get update -y && apt-get install -y curl iperf3 hping3' || true
$INCUS_CMD exec admin -- sh -c 'apt-get update -y && apt-get install -y curl tcpdump nmap' || true

echo "[+] Isolating untrusted and protected networks (disabling NAT)..."
$INCUS_CMD network set incus-untrust ipv4.nat=false || true
$INCUS_CMD network set incus-protect ipv4.nat=false || true

echo "[+] Setup complete! Container status:"
$INCUS_CMD list
