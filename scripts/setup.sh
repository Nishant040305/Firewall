#!/usr/bin/env bash
# ==============================================================================
# Automated Dependency Installer & Environment Verification
# Supports Ubuntu/Debian (apt) and Fedora/RHEL/CentOS (dnf)
# ==============================================================================
set -euo pipefail

echo "================================================================="
echo "       eBPF/XDP Firewall Setup & Environment Verification        "
echo "================================================================="

if command -v dnf >/dev/null 2>&1; then
    echo "[+] Detected Fedora/RHEL system (dnf)"
    sudo dnf install -y \
        gcc \
        clang \
        llvm \
        make \
        libbpf-devel \
        elfutils-libelf-devel \
        zlib-devel \
        glibc-devel \
        iproute \
        tcpdump \
        iperf3 \
        hping3 \
        nmap \
        curl \
        netcat \
        python3 \
        git \
        kernel-headers || true
elif command -v apt-get >/dev/null 2>&1; then
    echo "[+] Detected Ubuntu/Debian system (apt)"
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
        linux-headers-"$(uname -r)" || true

    # Install Incus if available
    if ! sudo apt-get install -y incus incus-client 2>/dev/null; then
        echo "[*] Attempting to install Incus from bookworm-backports / distro repo..."
        sudo apt-get install -y -t bookworm-backports incus incus-client qemu-system-x86 2>/dev/null || true
    fi
fi

# Enable IP forwarding on the host (Step 1 & 4)
echo "[+] Enabling IPv4 packet forwarding on host kernel..."
sudo sysctl -w net.ipv4.ip_forward=1

# Initialize Incus if installed
if command -v incus &> /dev/null; then
    echo "[+] Initializing Incus daemon..."
    sudo incus admin init --auto 2>/dev/null || true
fi

# Verify Clang
if command -v clang &> /dev/null; then
    echo "[+] Clang compiler: $(clang --version | head -n 1)"
else
    echo "[!] Warning: Clang is required to build eBPF bytecode. Run: sudo dnf/apt install clang"
fi

# Verify BTF Kernel Support
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "[+] Kernel BTF support: Available (/sys/kernel/btf/vmlinux found)"
else
    echo "[!] Notice: /sys/kernel/btf/vmlinux not found. Standard BPF compilation will be used."
fi

# Create BPF filesystem directory for map pinning
sudo mkdir -p /sys/fs/bpf/firewall 2>/dev/null || true

echo "================================================================="
echo "[+] Setup & verification completed successfully."
echo "================================================================="
