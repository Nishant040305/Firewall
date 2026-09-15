# Packet Path Validation & Kernel Flow Architecture (Step 15)

This document traces the exact path of a network packet through the Incus virtual testbed, Linux host kernel, eBPF/XDP hooks, and stateful decision engine.

---

## 1. End-to-End Packet Path Topology

```
+-----------------------------------------------------------------------------------+
| LINUX HOST (Single Physical / Virtual Machine)                                    |
|                                                                                   |
|  [ Client Container ]             [ Attacker Container ]                          |
|   IP: 10.10.1.20                   IP: 10.10.1.10                                 |
|   Interface: eth0                  Interface: eth0                                |
|         |                                |                                        |
|   (veth pair)                      (veth pair)                                    |
|         v                                v                                        |
|   +---------------------------------------------+                                 |
|   | Incus Untrusted Bridge: incus-untrust       |                                 |
|   | Subnet: 10.10.1.0/24 (Gateway: 10.10.1.1)   |                                 |
|   +---------------------------------------------+                                 |
|                         |                                                         |
|                         v                                                         |
|         +-------------------------------+                                         |
|         |  XDP INGRESS HOOK (Step 5)    |                                         |
|         |  - L2/L3/L4 Parsing (Step 7)  |                                         |
|         |  - Stateful Conntrack (Step 9)|                                         |
|         |  - Dynamic Rule Match (Step 8)|                                         |
|         +-------------------------------+                                         |
|                   /           \                                                   |
|       [ XDP_DROP ]             [ XDP_PASS ]                                       |
|      (Early Kernel Drop)              \                                           |
|                                        v                                          |
|                          +----------------------------+                           |
|                          | Host IPv4 Forwarding (FIB) |                           |
|                          | (net.ipv4.ip_forward = 1)  |                           |
|                          +----------------------------+                           |
|                                        |                                          |
|                                        v                                          |
|                          +----------------------------+                           |
|                          | TC EGRESS HOOK             |                           |
|                          +----------------------------+                           |
|                                        |                                          |
|                                        v                                          |
|   +---------------------------------------------+                                 |
|   | Incus Protected Bridge: incus-protect       |                                 |
|   | Subnet: 10.10.2.0/24 (Gateway: 10.10.2.1)   |                                 |
|   +---------------------------------------------+                                 |
|                         |                                                         |
|                    (veth pair)                                                    |
|                         v                                                         |
|              [ Webserver Container ]                                              |
|               IP: 10.10.2.10                                                      |
|               Nginx HTTP (Port 80)                                                |
|               iperf3 (Port 5201)                                                  |
+-----------------------------------------------------------------------------------+
```

---

---

## 2. Interface Attachment Points & Execution Modes

| Hook Point | Program Name | Target Interface | Execution Mode | Architectural Rationale & Behavior |
|:---|:---|:---|:---|:---|
| **Ingress Hook** | `xdp_firewall_prog` | `incus-untrust` | **Generic (SKB) Mode (`xdpgeneric`)** | Linux software bridge devices (`net/bridge/`) do not implement driver-level `ndo_bpf` callbacks. When attaching to `incus-untrust`, `bpf_xdp_attach()` automatically falls back from `XDP_FLAGS_DRV_MODE` to `XDP_FLAGS_SKB_MODE`. Packets are converted to `sk_buff` by the kernel before XDP executes, but malicious packets are still dropped prior to routing table lookups and netfilter conntrack table insertion. (*Note:* To run in Native Driver mode `xdpdrv`, XDP must be attached directly to the physical NIC or host-side `veth` endpoint). |
| **TC Ingress Hook** | `tc_ingress_prog` | Configured Ingress NIC | **TC `clsact` Ingress** | Fallback hook used when running in pure TC mode (`--mode tc`). Executes inside the network stack at the TC ingress layer. |
| **TC Egress Hook** | `tc_egress_prog` | `incus-protect` / `incus-untrust` | **TC `clsact` Egress** | Inspects frames leaving the host routing layer toward destination containers, tracking connection state transitions and enforcing egress filtering policies. |

---

## 3. Bidirectional Packet Transit Lifecycle

### A. Forward Path (Client: `10.10.1.20` → Webserver: `10.10.2.10:80`)

1. **Generation in Client Container**:
   - Client process (`curl http://10.10.2.10/`) transmits a TCP `SYN` packet via container `eth0`.
   - Default gateway inside container namespace resolves to `10.10.1.1` (host bridge IP).

2. **veth Boundary Crossing**:
   - Virtual ethernet (`veth`) pair transfers the frame from the container network namespace to the host namespace.
   - The host interface is a slave port of the `incus-untrust` bridge.

3. **XDP Ingress Execution (`xdp_firewall_prog` on `incus-untrust`)**:
   - Hook evaluates Ethernet, IPv4, and TCP headers (`proto_tcp.bpf.h`).
   - For a `SYN` packet: evaluates dynamic rules in `rules_map`.
   - If allowed: allocates initial forward and reverse state entries in `conntrack_map` (`CONN_STATE_SYN_SENT`) and issues `XDP_PASS`.
   - If unsolicited (non-SYN without existing state) or blocked: issues `XDP_DROP`.

4. **Host Routing & Forwarding**:
   - Kernel IP forwarding engine (`net.ipv4.ip_forward = 1`) inspects the FIB (Forwarding Information Base).
   - Destination `10.10.2.10` matches route `10.10.2.0/24 dev incus-protect`.

5. **TC Egress Processing (`tc_egress_prog` on `incus-protect`)**:
   - Frame is queued for egress on the `incus-protect` bridge.
   - TC egress hook inspects the frame; returns `TC_ACT_OK`.

6. **Delivery to Protected Container**:
   - Frame crosses the destination `veth` pair and enters the Webserver namespace.
   - Delivered to `eth0` and picked up by Nginx listening on port 80.

---

### B. Return Path (Webserver: `10.10.2.10:80` → Client: `10.10.1.20`)

1. **Response Generation in Server Container**:
   - Nginx transmits a TCP `SYN-ACK` packet destined for `10.10.1.20`.
   - Container routes packet through its local `eth0` to gateway `10.10.2.1`.

2. **Ingress at Protected Bridge**:
   - Frame crosses `veth` pair into host bridge `incus-protect`.
   - Linux host routing engine looks up destination `10.10.1.20`, matching `10.10.1.0/24 dev incus-untrust`.

3. **TC Egress Processing on `incus-untrust` (`tc_egress_prog`)**:
   - As the return frame exits towards `incus-untrust`, the TC egress filter intercepts it.
   - **Reverse Conntrack Match:** The 5-tuple matches the reverse flow entry (`rev_key`) established during the initial SYN.
   - State advances from `CONN_STATE_SYN_SENT` to `CONN_STATE_SYN_RECV`.
   - Verdict: `TC_ACT_OK`.

4. **Delivery to Client Container**:
   - Frame traverses client `veth` into the client container namespace.
   - Client TCP stack receives `SYN-ACK` and completes the 3-way handshake by transmitting the final `ACK`.
   - When the final `ACK` arrives, conntrack transitions the connection to `CONN_STATE_ESTABLISHED`.

---

## 4. Running System Verification Commands

To verify attachment points, modes, and packet traversal on a live system:

### 1. Check Interface Attachment and Mode via `ip link`:
```bash
ip -d link show dev incus-untrust
```
**Expected Output:**
```text
X: incus-untrust: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    link/ether ...
    bridge forward_delay 0 hello_time 200 ...
    generic xdp id 42 act []
```
*Key Evidence:* `generic xdp id <ID>` confirms the program is operating in **Generic/SKB mode (`xdpgeneric`)**.

### 2. Inspect Loaded Programs via `bpftool`:
```bash
sudo bpftool net show
```
**Expected Output:**
```text
xdp:
incus-untrust(6) generic id 42 act []

tc:
incus-untrust(6) clsact/egress tc_egress_prog id 43
incus-protect(7) clsact/egress tc_egress_prog id 43
```

### 3. Verify Active Program Bytecode:
```bash
sudo bpftool prog show name xdp_firewall_prog
```
**Expected Output:**
```text
42: xdp  name xdp_firewall_prog  tag 9b8e21a4f091c53d  gpl
    loaded_at 2026-09-15T10:00:00+0000  uid 0
    xlated 1424B  jited 836B  memlock 4096B  map_ids 12,13,14,15
```

### 4. Execute Full Path Validation Utility:
```bash
sudo ./scripts/trace_packet_path.sh
```
The script validates kernel forwarding, bridge states, veth pairs, routing table entries, and attached XDP/TC hooks automatically.
