#!/usr/bin/env bash
# Automated dependency installer & environment verification for eBPF/XDP Firewall.
set -euo pipefail

sudo apt-get update -y
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    gcc-multilib \
    iproute2 \
    tcpdump \
    iperf3 \
    hping3 \
    nmap \
    curl \
    netcat-openbsd \
    python3 \
    git \
    incus \
    incus-client \
    linux-headers-"$(uname -r)"

# Enable IP forwarding on the host
sudo sysctl -w net.ipv4.ip_forward=1

# Initialize Incus if not already initialized
if command -v incus &> /dev/null; then
    sudo incus admin init --auto || true
fi

if command -v clang &> /dev/null; then
    echo "[+] Clang installed: $(clang --version | head -n 1)"
else
    echo "[-] Clang not found!"
fi

# Verify BTF Kernel Support
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "Kernel BTF support: Available (/sys/kernel/btf/vmlinux found)"
else
    echo "Warning: /sys/kernel/btf/vmlinux not found. Verify your kernel configuration."
fi

echo "[+] package installed successfully."