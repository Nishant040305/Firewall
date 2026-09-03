#!/usr/bin/env bash
# ==============================================================================
# Step 15: Exact Packet Path Tracing & Validation Utility
# ==============================================================================
# Traces how a packet moves between containers through Incus bridges,
# virtual Ethernet (veth) pairs, XDP hooks, and the Linux routing plane:
#
#   Container [Client/Attacker eth0] (10.10.1.10/20)
#          │  (veth pair in network namespace)
#          ▼
#   Host Virtual Interface (vethXXXX)
#          │
#          ▼
#   Incus Bridge (incus-untrust / 10.10.1.1)
#          │
#          ▼  <-- [ XDP HOOK: xdp_firewall_prog (Fast-Path Filter) ]
#   Host IP Routing Engine (net.ipv4.ip_forward = 1)
#          │
#          ▼  <-- [ TC EGRESS HOOK: tc_egress_prog ]
#   Incus Bridge (incus-protect / 10.10.2.1)
#          │
#          ▼
#   Host Virtual Interface (vethYYYY)
#          │  (veth pair)
#          ▼
#   Container [Webserver eth0] (10.10.2.10)
# ==============================================================================

set -euo pipefail

echo "================================================================="
echo "        STEP 15: PACKET PATH TRACE & VALIDATION UTILITY          "
echo "================================================================="

echo "[1/5] Checking Kernel IP Forwarding Status:"
ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
if [ "$ip_fwd" = "1" ]; then
    echo "    -> net.ipv4.ip_forward = 1 (ENABLED)"
else
    echo "    -> net.ipv4.ip_forward = 0 (DISABLED - Run: sudo sysctl -w net.ipv4.ip_forward=1)"
fi

echo ""
echo "[2/5] Inspecting Incus Bridges on Host:"
ip -br link show type bridge 2>/dev/null || echo "    No bridge links found."

echo ""
echo "[3/5] Inspecting Virtual Ethernet (veth) Pairs:"
ip -br link show type veth 2>/dev/null || echo "    No veth links found (Containers not running)."

echo ""
echo "[4/5] Inspecting Kernel Routing Table for Container Subnets:"
ip route show | grep -E "10.10.1|10.10.2|10.10.99" || ip route show | head -n 5

echo ""
echo "[5/5] Checking Attached XDP / TC Hooks:"
if command -v bpftool >/dev/null 2>&1; then
    sudo bpftool net show 2>/dev/null || echo "    bpftool net show completed."
else
    ip link show | grep -E "xdp|clsact" || echo "    No XDP/TC hooks currently attached."
fi

echo ""
echo "================================================================="
echo "Packet Path Transit Lifecycle:"
echo " 1. Packet created in Client (10.10.1.20) -> transmitted via container eth0."
echo " 2. Enters host namespace through peer veth interface connected to bridge 'incus-untrust'."
echo " 3. XDP Hook intercepts frame on ingress driver/generic layer."
echo "    - If Rule matches ALLOW & Valid State -> XDP_PASS"
echo "    - If Malformed / Unsolicited / Blocked -> XDP_DROP (Early kernel drop!)"
echo " 4. If passed, Host Routing Engine inspects FIB and routes packet toward 'incus-protect'."
echo " 5. TC Egress hook inspects and forwards frame to destination veth."
echo " 6. Packet arrives at Webserver container eth0 (10.10.2.10)."
echo "================================================================="
