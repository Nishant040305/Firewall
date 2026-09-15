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
echo ""
echo "[5/6] Checking Attached XDP / TC Hooks and Attachment Mode:"
if command -v bpftool >/dev/null 2>&1; then
    echo "--- bpftool net show ---"
    sudo bpftool net show 2>/dev/null || echo "    bpftool net show completed."
    echo ""
    echo "--- Loaded BPF Programs (XDP & TC) ---"
    sudo bpftool prog show | grep -E "xdp_firewall_prog|tc_ingress_prog|tc_egress_prog" || echo "    No firewall programs loaded in kernel."
else
    echo "--- ip link hook details ---"
    ip -d link show | grep -E "xdp|clsact" || echo "    No XDP/TC hooks currently attached."
fi

echo ""
echo "[6/6] Inspecting Detailed Interface Link Modes (Generic vs Native Driver):"
for iface in incus-untrust incus-protect eth0; do
    if ip link show "$iface" >/dev/null 2>&1; then
        xdp_info=$(ip -d link show dev "$iface" 2>/dev/null | grep -E "xdp" || true)
        tc_info=$(ip -d link show dev "$iface" 2>/dev/null | grep -E "clsact" || true)
        echo "  [*] Interface: $iface"
        if [ -n "$xdp_info" ]; then
            echo "      XDP Hook: $xdp_info"
            if echo "$xdp_info" | grep -q "xdpgeneric"; then
                echo "      -> Mode: GENERIC / SKB (xdpgeneric) [Kernel allocates sk_buff before hook]"
            elif echo "$xdp_info" | grep -q "xdpdrv"; then
                echo "      -> Mode: NATIVE / DRIVER (xdpdrv) [Zero sk_buff allocation, line-rate]"
            fi
        else
            echo "      XDP Hook: None"
        fi
        if [ -n "$tc_info" ]; then
            echo "      TC Hook:  clsact qdisc present"
        fi
    fi
done

echo ""
echo "================================================================="
echo "Complete Bidirectional Packet Path Transit Lifecycle:"
echo "-----------------------------------------------------------------"
echo "A. FORWARD PATH (Client 10.10.1.20 -> Webserver 10.10.2.10:80):"
echo " 1. Client container (10.10.1.20) transmits SYN via container eth0."
echo " 2. Frame traverses virtual ethernet (veth) pair into host namespace."
echo " 3. Frame reaches bridge 'incus-untrust' (slave veth port)."
echo " 4. Hook interception: xdp_firewall_prog executes."
echo "    - ATTACHMENT MODE: xdpgeneric (SKB mode on Linux bridge) or xdpdrv (if on physical/veth NIC)."
echo "    - Verdict: If valid SYN matching rules -> conntrack entry created -> XDP_PASS."
echo "               If invalid/unsolicited/blocked -> XDP_DROP."
echo " 5. Linux IP Routing Engine (FIB) forwards packet: incus-untrust -> incus-protect."
echo " 6. TC Egress hook (tc_egress_prog) on incus-protect inspects outgoing frame."
echo " 7. Frame traverses veth pair into Webserver container namespace."
echo " 8. Delivered to Webserver eth0 -> Nginx listening on port 80."
echo ""
echo "B. RETURN PATH (Webserver 10.10.2.10 -> Client 10.10.1.20):"
echo " 1. Webserver container generates SYN-ACK response via container eth0."
echo " 2. Frame crosses veth pair to host 'incus-protect' bridge."
echo " 3. Host IP routing engine looks up destination 10.10.1.20 via 'incus-untrust'."
echo " 4. TC Egress hook on 'incus-untrust' intercepts outgoing return frame."
echo "    - Stateful conntrack looks up reverse key, transitions state: SYN_SENT -> SYN_RECV."
echo "    - Verdict: TC_ACT_OK (Allowed)."
echo " 5. Frame delivered across peer veth interface to Client container eth0."
echo " 6. Client receives SYN-ACK and completes TCP three-way handshake with ACK."
echo "================================================================="
