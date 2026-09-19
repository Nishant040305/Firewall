#!/usr/bin/env bash
# Sets up Incus networks and containers for firewall testing.
# Usage: ./setup_env.sh [IMAGE_NAME]
# Default: images:ubuntu/24.04 (e.g. images:debian/12, images:fedora/40, images:alpine/3.20)
set -euo pipefail

IMAGE="${1:-images:ubuntu/24.04}"
echo "[+] Using container image: $IMAGE"

INCUS_CMD="incus"
if ! incus list >/dev/null 2>&1; then
    INCUS_CMD="sudo incus"
fi

echo "[+] Ensuring functional idmap (subuid/subgid) for Incus containers..."
RESTART_INCUS=0
if ! grep -q "^root:" /etc/subuid 2>/dev/null; then
    echo "root:1000000:1000000000" | sudo tee -a /etc/subuid >/dev/null
    RESTART_INCUS=1
fi
if ! grep -q "^root:" /etc/subgid 2>/dev/null; then
    echo "root:1000000:1000000000" | sudo tee -a /etc/subgid >/dev/null
    RESTART_INCUS=1
fi
if [ "$RESTART_INCUS" -eq 1 ]; then
    echo "[+] Restarting Incus daemon to apply subuid/subgid idmap..."
    sudo systemctl restart incus 2>/dev/null || true
    sleep 2
fi

echo "[+] Configuring Incus virtual networks (enabling NAT for package installation)..."
$INCUS_CMD network create incus-mgmt ipv4.address=10.10.99.1/24 ipv4.nat=true ipv6.address=none 2>/dev/null || $INCUS_CMD network set incus-mgmt ipv4.nat=true 2>/dev/null || true
$INCUS_CMD network create incus-untrust ipv4.address=10.10.1.1/24 ipv4.nat=true ipv6.address=none 2>/dev/null || $INCUS_CMD network set incus-untrust ipv4.nat=true 2>/dev/null || true
$INCUS_CMD network create incus-protect ipv4.address=10.10.2.1/24 ipv4.nat=true ipv6.address=none 2>/dev/null || $INCUS_CMD network set incus-protect ipv4.nat=true 2>/dev/null || true

echo "[+] Launching containers..."
# Untrusted network (Client & Attacker)
$INCUS_CMD init "$IMAGE" attacker --network incus-untrust 2>/dev/null || true
$INCUS_CMD config device set attacker eth0 ipv4.address 10.10.1.10 2>/dev/null || true
$INCUS_CMD start attacker 2>/dev/null || true

$INCUS_CMD init "$IMAGE" client --network incus-untrust 2>/dev/null || true
$INCUS_CMD config device set client eth0 ipv4.address 10.10.1.20 2>/dev/null || true
$INCUS_CMD start client 2>/dev/null || true

# Protected network (Server)
$INCUS_CMD init "$IMAGE" webserver --network incus-protect 2>/dev/null || true
$INCUS_CMD config device set webserver eth0 ipv4.address 10.10.2.10 2>/dev/null || true
$INCUS_CMD start webserver 2>/dev/null || true

# Management network (Admin workstation)
$INCUS_CMD init "$IMAGE" admin --network incus-mgmt 2>/dev/null || true
$INCUS_CMD config device set admin eth0 ipv4.address 10.10.99.10 2>/dev/null || true
$INCUS_CMD start admin 2>/dev/null || true

# Ensure host forwarding and firewall allow container traffic
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sudo iptables -P FORWARD ACCEPT 2>/dev/null || true
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
    echo "[+] Configuring firewalld trusted zone for Incus bridge interfaces..."
    sudo firewall-cmd --zone=trusted --add-interface=incus-untrust --add-interface=incus-protect --add-interface=incus-mgmt 2>/dev/null || true
    sudo firewall-cmd --zone=trusted --add-interface=incus-untrust --add-interface=incus-protect --add-interface=incus-mgmt --permanent 2>/dev/null || true
fi

echo "[+] Waiting for containers to initialize networking..."
sleep 5

echo "[+] Configuring container DNS and package repositories..."
for c in webserver attacker client admin; do
    $INCUS_CMD exec "$c" -- sh -c '
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        echo "Acquire::ForceIPv4 \"true\";" > /etc/apt/apt.conf.d/99force-ipv4
        # Ensure Ubuntu universe repository is enabled for tools like hping3
        if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
            sed -i "/^Components:/ s/$/ universe restricted multiverse/" /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
        fi
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
