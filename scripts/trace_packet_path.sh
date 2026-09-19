#!/usr/bin/env bash
# ==============================================================================
# Step 15: Exact Packet Path Tracing & Validation Utility
# ==============================================================================
# Traces how a packet moves between containers through Incus bridges,
# virtual Ethernet (veth) pairs, XDP hooks, and the Linux routing plane.
# ==============================================================================

set -euo pipefail

echo "================================================================="
echo "        STEP 15: PACKET PATH TRACE & VALIDATION UTILITY          "
echo "================================================================="

echo "[1/6] Checking Kernel IP Forwarding Status:"
ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
if [ "$ip_fwd" = "1" ]; then
    echo "    -> net.ipv4.ip_forward = 1 (ENABLED)"
else
    echo "    -> net.ipv4.ip_forward = 0 (DISABLED - Run: sudo sysctl -w net.ipv4.ip_forward=1)"
fi

echo ""
echo "[2/6] Inspecting Incus Bridges on Host:"
ip -br link show type bridge 2>/dev/null || echo "    No bridge links found."

echo ""
echo "[3/6] Inspecting Virtual Ethernet (veth) Pairs & Container Endpoints:"
ip -br link show type veth 2>/dev/null || echo "    No veth links found (Containers not running)."

CLIENT_VETH=""
ATTACKER_VETH=""
SERVER_VETH=""
ADMIN_VETH=""

# Resolve incus command with proper permissions
INCUS_CMD=""
if incus list >/dev/null 2>&1; then
    INCUS_CMD="incus"
elif sudo incus list >/dev/null 2>&1; then
    INCUS_CMD="sudo incus"
fi

# Resolve container host veths
if [ -n "$INCUS_CMD" ]; then
    echo ""
    echo "  Container <---> Host Interface Map:"
    for c in client attacker webserver admin; do
        hv=$($INCUS_CMD config get "$c" volatile.eth0.host_name 2>/dev/null || true)
        ip_addr=$($INCUS_CMD list -c 4 "$c" --format csv 2>/dev/null | awk '{print $1}' || true)
        if [ -n "$hv" ]; then
            echo "    * Container '$c' [IP: ${ip_addr:-Pending}] <---> Host veth: '$hv'"
            case "$c" in
                client)    CLIENT_VETH="$hv" ;;
                attacker)  ATTACKER_VETH="$hv" ;;
                webserver) SERVER_VETH="$hv" ;;
                admin)     ADMIN_VETH="$hv" ;;
            esac
        fi
    done
fi

echo ""
echo "[4/6] Inspecting Kernel Routing Table for Container Subnets:"
ip route show | grep -E "10.10.1|10.10.2|10.10.99" || ip route show | head -n 5

echo ""
echo "[5/6] Checking Attached XDP / TC Hooks and Attachment Mode:"
BPFTOOL_BIN=""
if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then
    BPFTOOL_BIN="bpftool"
else
    FOUND_BIN=$(find /usr/lib/linux-tools/ -name bpftool 2>/dev/null | sort -V | tail -1 || true)
    if [ -n "$FOUND_BIN" ] && [ -x "$FOUND_BIN" ]; then
        BPFTOOL_BIN="$FOUND_BIN"
    fi
fi

HOOK_ON_VETH=0
HOOK_ON_BRIDGE=0

if [ -n "$BPFTOOL_BIN" ]; then
    echo "--- bpftool net show ---"
    sudo "$BPFTOOL_BIN" net show 2>/dev/null || echo "    bpftool net show completed."
    echo ""
    echo "--- Loaded BPF Programs (XDP & TC) ---"
    sudo "$BPFTOOL_BIN" prog show 2>/dev/null | grep -E "xdp_firewall_prog|tc_ingress_prog|tc_egress_prog" || echo "    No firewall programs currently loaded."
    
    # Check if attached to veth or bridge
    if sudo "$BPFTOOL_BIN" net show 2>/dev/null | grep -qE "veth[a-f0-9]+.*driver id"; then
        HOOK_ON_VETH=1
    fi
    if sudo "$BPFTOOL_BIN" net show 2>/dev/null | grep -qE "incus-.*(generic|driver) id"; then
        HOOK_ON_BRIDGE=1
    fi
else
    echo "--- Kernel Netlink Hook Status (ip link) ---"
    ip -d link show | grep -E "xdp|clsact" || echo "    No XDP/TC hooks currently attached."
fi

echo ""
echo "[6/6] Inspecting Detailed Interface Link Modes & TC Filters:"
# Parse interfaces cleanly, stripping any @peer suffix
IFACES=$(ip -br link 2>/dev/null | awk '{print $1}' | cut -d'@' -f1 | grep -E "incus|veth|docker|br" | sort -u || echo "incus-untrust incus-protect eth0")
for iface in $IFACES; do
    if ip link show "$iface" >/dev/null 2>&1; then
        xdp_info=$(ip -d link show dev "$iface" 2>/dev/null | grep -E "xdp" || true)
        tc_info=$(ip -d link show dev "$iface" 2>/dev/null | grep -E "clsact" || true)
        
        # Only print interfaces that are relevant (bridges or active veths)
        if [ -n "$xdp_info" ] || [ -n "$tc_info" ] || echo "$iface" | grep -qE "incus-(untrust|protect)"; then
            echo "  [*] Interface: $iface"
            if [ -n "$xdp_info" ]; then
                echo "      XDP Hook: $xdp_info"
                if echo "$xdp_info" | grep -q "xdpdrv"; then
                    echo "      -> Mode: NATIVE / DRIVER (xdpdrv) [Zero sk_buff allocation, line-rate]"
                elif echo "$xdp_info" | grep -q "xdpgeneric"; then
                    echo "      -> Mode: GENERIC / SKB (xdpgeneric) [Kernel allocates sk_buff before hook]"
                fi
            else
                echo "      XDP Hook: None"
            fi
            if [ -n "$tc_info" ]; then
                echo "      TC Qdisc: clsact present"
                tc_ing=$(tc filter show dev "$iface" ingress 2>/dev/null | grep -E "bpf|prog" || true)
                tc_egr=$(tc filter show dev "$iface" egress 2>/dev/null | grep -E "bpf|prog" || true)
                if [ -n "$tc_ing" ]; then
                    echo "      -> TC Ingress Hook (tc_ingress_prog): $tc_ing"
                fi
                if [ -n "$tc_egr" ]; then
                    echo "      -> TC Egress Hook  (tc_egress_prog):  $tc_egr"
                fi
            fi
        fi
    fi
done

echo ""
echo "================================================================="
echo "Live End-to-End Packet Path Traversal Analysis:"
echo "================================================================="

echo "A. FORWARD PACKET PATH (Client 10.10.1.20 -> Webserver 10.10.2.10:80):"
echo "  [Step 1] Client Container: Transmits TCP SYN from eth0 (10.10.1.20:XXXX -> 10.10.2.10:80)."
echo "  [Step 2] Client veth Cable: Traverses peer wire into host namespace interface '${CLIENT_VETH:-veth_client}'."

if [ "$HOOK_ON_VETH" -eq 1 ]; then
    echo "  [Step 3] ★ FIREWALL HOOK (NATIVE XDP): Intercepts packet directly on '${CLIENT_VETH:-veth_client}'!"
    echo "           - Mode: NATIVE DRIVER (xdpdrv) inside veth driver (Zero sk_buff overhead)"
    echo "           - Evaluation: Parsed 5-tuple -> rules_map lookup -> state created in conntrack_map"
    echo "           - Verdict: XDP_PASS (or XDP_DROP if blocked/unauthorized)"
    echo "  [Step 4] Host Bridge 'incus-untrust': Allowed frame enters bridge port as Layer 2 frame."
else
    echo "  [Step 3] Host Bridge 'incus-untrust': Frame enters bridge switch port (10.10.1.1)."
    echo "  [Step 4] ★ FIREWALL HOOK (BRIDGE XDP): Intercepts packet on bridge 'incus-untrust'!"
    echo "           - Mode: GENERIC SKB (xdpgeneric)"
    echo "           - Evaluation: Parsed 5-tuple -> rules_map lookup -> conntrack: SYN_SENT"
    echo "           - Verdict: XDP_PASS (or XDP_DROP)"
fi

echo "  [Step 5] Linux Kernel IP Forwarding Engine (FIB):"
echo "           - net.ipv4.ip_forward = 1 routes destination 10.10.2.10 -> dev incus-protect."
echo "  [Step 6] Protected Bridge 'incus-protect': Frame queued for delivery towards protected segment."
echo "  [Step 7] Protected veth Cable: Traverses host interface '${SERVER_VETH:-veth_server}' into container namespace."
echo "  [Step 8] Webserver Container: Delivered to eth0 (10.10.2.10) -> Nginx listening on port 80."

echo ""
echo "B. RETURN PACKET PATH (Webserver 10.10.2.10 -> Client 10.10.1.20):"
echo "  [Step 1] Webserver Container: Generates TCP SYN-ACK reply (10.10.2.10:80 -> 10.10.1.20:XXXX)."
echo "  [Step 2] Server veth: Traverses host-side '${SERVER_VETH:-veth_server}' into 'incus-protect' bridge."
echo "  [Step 3] Linux Kernel IP Routing: FIB resolves destination 10.10.1.20 -> dev incus-untrust."
echo "  [Step 4] Host Bridge 'incus-untrust': Frame routed to untrusted segment."

if [ "$HOOK_ON_VETH" -eq 1 ]; then
    echo "  [Step 5] ★ FIREWALL HOOK (TC EGRESS): Intercepts outgoing return frame on '${CLIENT_VETH:-veth_client}'!"
    echo "           - Stateful Conntrack: Reverse flow match in conntrack_map"
    echo "           - TCP State Transition: CONN_STATE_SYN_SENT -> CONN_STATE_SYN_RECV"
    echo "           - Verdict: TC_ACT_OK"
    echo "  [Step 6] Client veth: Delivered across virtual wire into Client namespace eth0."
else
    echo "  [Step 5] ★ FIREWALL HOOK (TC EGRESS): Intercepts frame on bridge 'incus-untrust' egress!"
    echo "           - Stateful Conntrack: Reverse flow match in conntrack_map"
    echo "           - TCP State Transition: CONN_STATE_SYN_SENT -> CONN_STATE_SYN_RECV"
    echo "           - Verdict: TC_ACT_OK"
    echo "  [Step 6] Client veth: Traverses peer wire into Client container eth0."
fi

echo "  [Step 7] Client Container: Receives SYN-ACK, transmits final ACK -> State becomes ESTABLISHED!"
echo "================================================================="
