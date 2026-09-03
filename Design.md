# Comprehensive Stateful eBPF/XDP Firewall Architecture & Implementation Guide

## 1. Overview & Core Philosophy

This project implements a high-performance, kernel-native stateful firewall using **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)** on Linux. The system provides sub-microsecond packet classification, line-rate throughput, stateful TCP/UDP/ICMP flow tracking, and dynamic rule management from userspace without kernel recompilation.

The architecture strictly follows a **split dataplane/control-plane model**:
- **Kernel Dataplane (eBPF/XDP)**: Fast-path packet parsing, state validation, rule matching, and line-rate enforcement (`XDP_PASS` / `XDP_DROP`).
- **Userspace Control Plane (`firewallctl` / `fw-ctl`)**: Rule configuration, connection state inspection, telemetry aggregation, and lifecycle management.

---

## 2. The 16-Step Design & Architecture Blueprint

```
+----------------------------------------------------------------------------------------------------+
|                                      LINUX HOST (Step 1 & Step 4)                                   |
|                                                                                                    |
|  +---------------------------------------------------+    +-------------------------------------+  |
|  |           UNTRUSTED NETWORK (Step 3)              |    |       PROTECTED NETWORK (Step 3)    |  |
|  |           Subnet: 10.10.1.0/24                    |    |       Subnet: 10.10.2.0/24          |  |
|  |  +-----------------------+ +--------------------+ |    |  +-------------------------------+  |  |
|  |  |   Client Container    | | Attacker Container | |    |  |      Webserver Container      |  |  |
|  |  |    (10.10.1.20)       | |   (10.10.1.10)     | |    |  |          (10.10.2.10)         |  |  |
|  |  |   Legitimate Traffic  | |  Floods & Scans    | |    |  |    Nginx (80), iperf3 (5201)  |  |  |
|  |  +-----------+-----------+ +---------+----------+ |    |  +---------------+---------------+  |  |
|  +--------------|-----------------------|------------+    +------------------|------------------+  |
|                 +-----------+-----------+                                    |                     |
|                             | (veth pair)                                    | (veth pair)         |
|                             v                                                v                     |
|               +----------------------------+                  +----------------------------+       |
|               |  Bridge: incus-untrust     |                  |   Bridge: incus-protect    |       |
|               |  IP: 10.10.1.1/24          |                  |   IP: 10.10.2.1/24         |       |
|               +--------------+-------------+                  +--------------+-------------+       |
|                              |                                               ^                     |
|                              v                                               |                     |
|                 +----------------------------+                               |                     |
|                 |  XDP Ingress Hook (Step 5) |                               |                     |
|                 +--------------+-------------+                               |                     |
|                                |                                             |                     |
|                                v                                             |                     |
|         +---------------------------------------------+                      |                     |
|         |  eBPF 4-Stage Firewall Pipeline (Step 6)    |                      |                     |
|         |   1. 5-Tuple Packet Parser (Step 7)         |                      |                     |
|         |   2. Stateful Connection Engine (Step 9)    |                      |                     |
|         |   3. Dynamic Rule Matcher (Step 8)          |                      |                     |
|         |   4. Telemetry & Stats Counters (Step 11)   |                      |                     |
|         +----------------------+----------------------+                      |                     |
|                                |                                             |                     |
|                 +--------------+--------------+                              |                     |
|                 |                             |                              |                     |
|           [ XDP_DROP ]                  [ XDP_PASS ]                         |                     |
|        (Attacks / Out-of-State)               |                              |                     |
|                                               v                              |                     |
|                               +-------------------------------+              |                     |
|                               | Host IPv4 Routing Plane (FIB) |--------------+                     |
|                               |  (net.ipv4.ip_forward = 1)    |                                    |
|                               +-------------------------------+                                    |
+----------------------------------------------------------------------------------------------------+
```

---

### Step 1: Set up one Linux machine as the host
- All components, virtual network bridges, containers, and kernel hooks run on a single host.
- Host requirements: Linux Kernel >= 5.15 with BTF support (`/sys/kernel/btf/vmlinux`), Clang/LLVM toolchain, and `ip_forward=1`.

### Step 2: Create virtual machines/containers using Incus
- Incus provisions lightweight system containers that provide isolated network namespaces and individual IP addresses without the virtualization overhead of full virtual machines.
- Containers: `client` (10.10.1.20), `attacker` (10.10.1.10), `webserver` (10.10.2.10), `admin` (10.10.99.10).

### Step 3: Organise containers into three networks
- **Untrusted Segment (`incus-untrust` - 10.10.1.0/24)**: Houses clients and the attacker simulator.
- **Protected Segment (`incus-protect` - 10.10.2.0/24)**: Houses target services (Nginx, backend applications).
- **Management Segment (`incus-mgmt` - 10.10.99.0/24)**: Isolated network for administration and monitoring to prevent operator lockout during aggressive firewall policy tests.

### Step 4: Connect networks through the Linux host, not through a container
- Container networks are joined on the host via bridge interfaces and `veth` pairs.
- The host routing engine (`net.ipv4.ip_forward = 1`) routes traffic across subnets.
- The firewall attaches directly to this forwarding path on the host, operating at the bare-metal kernel driver layer.

### Step 5: Attach the firewall using XDP
- The XDP hook (`xdp_firewall_prog`) intercepts incoming packets at the network device driver layer (or generic SKB fallback) prior to `sk_buff` allocation or netfilter traversal, saving up to 90% of kernel CPU overhead during high packet loads.

### Step 6: Write the firewall logic in eBPF
The kernel fast-path executes a four-stage pipeline:
1. **Parser**: Validates Ethernet, IPv4, TCP/UDP/ICMP headers.
2. **State Engine**: Validates connection state (TCP handshake, sequence tracking, UDP flow activity).
3. **Rule Engine**: Evaluates user-defined policies for initial connection establishment.
4. **Decision & Telemetry Engine**: Returns `XDP_PASS` or `XDP_DROP` and emits telemetry events to the BPF ring buffer.

### Step 7: Parse each packet into its five identifying fields
- For every packet, extracts: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`.
- Validates TCP control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).

### Step 8: Keep firewall rules outside the eBPF program
- Rules are stored in a dedicated `BPF_MAP_TYPE_ARRAY` (`rules_map`).
- Each entry defines subnet masks, port ranges, protocol filters, actions (`ALLOW`, `DROP`), and hit counters.
- Rules can be updated dynamically via `firewallctl` without rebuilding or reloading the eBPF kernel program.

### Step 9: Add connection state to make it a stateful firewall
- Flow states are tracked in `conntrack_map` (`BPF_MAP_TYPE_HASH`).
- **TCP State Machine**:
  - `SYN` (new flow allowed by rule) -> `CONN_STATE_SYN_SENT`.
  - `SYN-ACK` (from server) -> `CONN_STATE_SYN_RECV`.
  - `ACK` (handshake complete) -> `CONN_STATE_ESTABLISHED` (Fast-path allow).
  - `FIN` / `RST` -> `CONN_STATE_FIN_WAIT` / `CONN_STATE_CLOSED`.
  - **Unsolicited out-of-state packets** (e.g. non-SYN packets with no prior state) are dropped immediately (`XDP_DROP`).
- **UDP & ICMP**: Pseudo-connection state tracking with automatic inactivity timeouts.

### Step 10: Build the userspace control tool (`firewallctl`)
- `firewallctl` interacts with BPF maps via `libbpf`:
  - `firewallctl rule add / del / list / flush / load`
  - `firewallctl conntrack list / flush`
  - `firewallctl stats show / reset`
  - `firewallctl monitor`

### Step 11: Collect granular statistics
- `stats_map` (`BPF_MAP_TYPE_PERCPU_ARRAY`) maintains line-rate per-CPU counters:
  - Total packets received, allowed, and dropped.
  - Breakdown by protocol: TCP, UDP, ICMP, Other.
  - Drop classifications: policy drop, unsolicited/out-of-state drop, malformed drop.
  - Stateful connection lifecycle: new, established, closed, timed out.

### Step 12: Build a baseline for comparison (nftables vs. XDP)
- `test/benchmark_baseline_nftables.sh` benchmarks identical stateful policies in `nftables` vs `eBPF/XDP`.
- Measures throughput (iperf3), latency (ping RTT), and CPU utilization under SYN floods.

### Step 13: Generate test traffic
- Tools inside the container lab:
  - `curl` / `nginx`: HTTP web traffic.
  - `iperf3`: Max-bandwidth throughput.
  - `ping`: ICMP latency and reachability.
  - `hping3`: TCP SYN floods, UDP blasts, ICMP floods, malformed Xmas packets, and unsolicited ACK injection.

### Step 14: Run through the test cases
- `test/run_all_tests.sh` verifies:
  1. Allowed traffic passes (HTTP :80 & ICMP).
  2. Blocked ports are dropped (Port 8080 / Port 22).
  3. Full TCP handshake is tracked in the state table.
  4. Unsolicited packets with no matching state are dropped.

### Step 15: Validate the exact packet path first
- `scripts/trace_packet_path.sh` and `docs/PACKET_PATH_VALIDATION.md` document the six-stage transit lifecycle across Incus bridges, veth pairs, XDP hooks, routing FIBs, and target containers.

### Step 16: Treat this as an expandable platform
- `docs/ARCHITECTURE_AND_EXTENSIONS.md` details future platform extensions:
  - Token-bucket per-IP rate limiting.
  - Stateless SYN Cookies for DDoS protection.
  - Adaptive dynamic blacklisting of repeat offenders.
  - Flow telemetry export for Machine Learning anomaly detection.
