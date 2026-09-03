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

## 2. Six-Stage Packet Transit Lifecycle

1. **Generation in Container**:
   - The client application (e.g. `curl http://10.10.2.10/`) initiates a TCP socket connection.
   - The container kernel routes the packet through its local interface `eth0` with default gateway `10.10.1.1`.

2. **veth Boundary Crossing**:
   - The virtual ethernet (`veth`) driver immediately transfers the packet frame into the host root network namespace.
   - The host interface is enslaved to the `incus-untrust` bridge.

3. **XDP Ingress Execution**:
   - The XDP program `xdp_firewall_prog` executes directly on the receiving interface.
   - If the packet is malformed, blocked by policy, or an unsolicited out-of-state ACK/SYN-ACK, XDP issues `XDP_DROP`. The frame is recycled immediately in the driver ring without allocating an `sk_buff`.
   - If allowed, XDP issues `XDP_PASS`.

4. **Host Routing & Forwarding**:
   - The packet is converted to an `sk_buff` by the kernel network stack.
   - The kernel routing table looks up the destination `10.10.2.10` and finds the route via interface `incus-protect`.

5. **TC Egress Processing**:
   - The Traffic Control (`tc_egress_prog`) hook inspects the egress frame before queueing on the target bridge.

6. **Delivery to Destination Container**:
   - The frame traverses the target `veth` pair and enters the Webserver container's network namespace, reaching Nginx on port 80.
