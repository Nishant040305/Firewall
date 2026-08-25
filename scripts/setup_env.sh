#!/usr/bin/env bash
# Sets up Incus networks and containers for firewall testing.
# Usage: ./setup_env.sh [IMAGE_NAME]
# Default: images:ubuntu/24.04 (e.g. images:debian/12, images:fedora/40, images:alpine/3.20)
set -euo pipefail

IMAGE="${1:-images:ubuntu/24.04}"
echo "[+] Using container image: $IMAGE"

echo "[+] Creating Incus virtual networks..."
incus network create incusbr-mgmt ipv4.address=10.10.99.1/24 ipv4.nat=true || true
incus network create incusbr-untrusted ipv4.address=10.10.1.1/24 ipv4.nat=false || true
incus network create incusbr-protected ipv4.address=10.10.2.1/24 ipv4.nat=false || true

echo "[+] Launching containers..."
# Untrusted network (Client & Attacker)
incus init "$IMAGE" attacker --network incusbr-untrusted || true
incus config device set attacker eth0 ipv4.address 10.10.1.10 || true
incus start attacker || true

incus init "$IMAGE" client --network incusbr-untrusted || true
incus config device set client eth0 ipv4.address 10.10.1.20 || true
incus start client || true

# Protected network (Server)
incus init "$IMAGE" webserver --network incusbr-protected || true
incus config device set webserver eth0 ipv4.address 10.10.2.10 || true
incus start webserver || true

# Management network (Admin workstation)
incus init "$IMAGE" admin --network incusbr-mgmt || true
incus config device set admin eth0 ipv4.address 10.10.99.10 || true
incus start admin || true

echo "[+] Waiting for containers to initialize networking..."
sleep 5

echo "[+] Installing test tools inside containers..."
incus exec webserver -- sh -c 'apt-get update -y && apt-get install -y nginx curl tcpdump iperf3' || true
incus exec attacker -- sh -c 'apt-get update -y && apt-get install -y hping3 nmap curl iperf3 netcat-openbsd' || true
incus exec client -- sh -c 'apt-get update -y && apt-get install -y curl iperf3 hping3' || true
incus exec admin -- sh -c 'apt-get update -y && apt-get install -y curl tcpdump nmap' || true

echo "[+] Setup complete! Container status:"
incus list
