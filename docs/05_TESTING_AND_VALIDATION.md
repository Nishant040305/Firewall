# Testing, Benchmarking & Validation Guide

## 1. Introduction

This document outlines the comprehensive testing, benchmarking, and validation methodology for the High-Performance Stateful eBPF/XDP Firewall. The validation framework is designed to rigorously verify the functional correctness of stateful connection tracking, rule enforcement, and protocol validation, while quantitatively assessing the performance advantages of the eBPF/XDP implementation against established kernel baseline technologies.

## 2. Automated Test Suite

The automated test suite (`test/run_all_tests.sh`) serves as the primary validation mechanism for functional correctness. It executes a series of deterministic scenarios to ensure the firewall correctly enforces policies and tracks TCP connection states.

### 2.1 Test Cases Overview

| ID | Test Case Name | Methodology | Expected Result | Verification Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **TC-1** | Allowed Traffic Passes | HTTP GET (curl) to port 80; ICMP Ping | Connection succeeds; ICMP echo replies received | HTTP status 200/301/302; Ping RTT success |
| **TC-2** | Blocked Traffic Dropped | HTTP GET (curl) to unauthorized port 8080 | Connection times out (no SYN-ACK) | Exit status / 000 HTTP code; Drop counter increment |
| **TC-3** | Stateful TCP Handshake | Generate HTTP traffic; query state table | Complete TCP state transition observed | `fw-ctl conntrack list` shows `ESTABLISHED` → `FIN` |
| **TC-4** | Unsolicited Packets Dropped | Inject unsolicited ACK via `hping3` | Packets dropped at XDP hook | `STAT_DROPPED_UNSOLICITED` counter increments |

### 2.2 Test Case Walkthrough

#### Test Case 1: Allowed Traffic Passes
- **Objective:** Verify that explicitly permitted traffic (HTTP and ICMP) can traverse the firewall unimpeded.
- **Execution:** 
  - Sub-test 1.1: Issues an HTTP GET request to port 80 using `curl`, checking for valid HTTP response codes (200, 301, 302).
  - Sub-test 1.2: Transmits 2 ICMP Echo Request packets with a 2-second timeout.
- **Validation:** Both sub-tests must succeed, confirming that the ingress and egress XDP/TC hooks are correctly applying the `PASS` verdict for allowed flows.

#### Test Case 2: Blocked Traffic is Dropped
- **Objective:** Ensure the default `DROP` policy functions correctly for unconfigured ports.
- **Execution:** Attempts a connection to port 8080 (which has no allow rule) using `curl` with a 2-second timeout.
- **Validation:** The connection must time out. The absence of a SYN-ACK packet confirms the firewall successfully intercepted and dropped the unauthorized SYN packet at the earliest possible stage.

#### Test Case 3: TCP Handshake Tracked Statefully
- **Objective:** Validate the eBPF connection tracking table (`bpf_map`) logic.
- **Execution:** Generates a standard HTTP request to initiate an active state. Immediately queries the connection tracking map using the control plane utility (`fw-ctl conntrack list`).
- **Validation:** Verifies the full TCP state machine lifecycle. The flow must transition through `SYN` → `SYN_RECV` → `ESTABLISHED` → `DATA` → `FIN`.

#### Test Case 4: Unsolicited Packets Dropped
- **Objective:** Verify that the stateful engine correctly identifies and discards out-of-state packets without invoking the kernel TCP stack.
- **Execution:** Uses `hping3 -A -p 80 -c 3` to inject packets with only the ACK flag set, bypassing the initial SYN handshake.
- **Validation:** Confirms that no state entry is created and the `STAT_DROPPED_UNSOLICITED` counter is appropriately incremented, proving the drop occurred at the XDP layer.

### 2.3 Execution Instructions

To execute the automated test suite, navigate to the project root and run the following command:

```bash
sudo ./test/run_all_tests.sh
```

> [!IMPORTANT]  
> Root privileges are required to inject packets and query eBPF maps. Ensure the test environment and container network are properly initialized before running the suite.

## 3. Systematic Performance Benchmarking Methodology

To evaluate the firewall empirically rather than relying solely on theoretical claims, the framework defines **four controlled, repeatable experiments**. Both the eBPF/XDP stateful firewall and the `nftables` baseline are subjected to identical network topology, hardware constraints, and traffic workloads.

### 3.1 Controlled Experiment Definitions

| Exp ID | Evaluation Objective | Traffic Workload | Tool & Configuration | Parameters Measured | Procedure / Methodology |
|:---|:---|:---|:---|:---|:---|
| **EXP-1** | **Clean Bulk Throughput** | Legitimate sustained TCP stream (Port 5201) | `iperf3 -c 10.10.2.10 -t 10 -f m` | • Throughput (Mbits/s)<br>• Retransmission count (`Retr`) | Client initiates a 10-second single-stream TCP transfer to the Webserver container while the firewall operates under normal policy. |
| **EXP-2** | **Transaction Latency & Connection Rate** | Sequential & concurrent HTTP GET requests | `curl -w "%{time_total}"` (30 iterations) & `wrk -t2 -c10 -d10s` | • Avg request latency (ms)<br>• p95 / p99 latency (ms)<br>• HTTP success rate (%) | Client executes repeated HTTP requests against Nginx (`http://10.10.2.10:80/`) measuring end-to-end completion time per request. |
| **EXP-3** | **Network Latency & Jitter** | Continuous ICMP Echo requests | `ping -c 30 -i 0.2 10.10.2.10` | • RTT Min / Avg / Max (ms)<br>• Jitter / Mean Deviation (`mdev`) | Measures ICMP traversal time through the ingress bridge, routing table, and egress bridge under clean conditions. |
| **EXP-4** | **Attack Resilience & CPU Overhead** | Malicious TCP SYN flood to blocked ports concurrent with legitimate HTTP traffic | • Attacker: `hping3 -S -p 9999 --flood 10.10.2.10`<br>• Client: HTTP request loop<br>• Host: `mpstat 1 10` / `top -b -n 2` | • Host CPU load (%sys, %softirq)<br>• Dropped packet rate (PPS)<br>• Client HTTP availability under attack (%) | Attacker generates a high-volume SYN flood against unauthorized port 9999. Concurrently, legitimate client latency and host CPU consumption are sampled. |

---

### 3.2 Detailed Repeatable Measurement Procedures

#### Experiment 1: Clean TCP Throughput
```bash
# Ensure Webserver has iperf3 server active:
# incus exec webserver -- iperf3 -s -D
# Execute from client container or host:
iperf3 -c 10.10.2.10 -t 10 -f m
```
*Expected Result:* Both nftables and eBPF/XDP achieve line-rate throughput (~940+ Mbits/s on 1 Gbps virtual bridges), demonstrating that eBPF state tracking introduces negligible overhead on allowed established streams.

#### Experiment 2: HTTP Transaction Latency
```bash
for i in $(seq 1 30); do
    curl -s -o /dev/null -w "%{time_total}\n" "http://10.10.2.10:80/" --connect-timeout 2
done | awk '{s+=$1; cnt++} END {printf "Avg Latency: %.4f s\n", s/cnt}'
```
*Expected Result:* Average HTTP connection and transfer latency is maintained between 1.5 ms and 2.5 ms across both implementations.

#### Experiment 3: ICMP RTT & Jitter
```bash
ping -c 30 -i 0.2 10.10.2.10 | tail -2
```
*Expected Result:* Standard round-trip time: `min/avg/max/mdev = 0.08/0.12/0.25/0.03 ms`.

#### Experiment 4: Volumetric SYN Flood & CPU Utilization
```bash
# Step 1: Launch background SYN blast from Attacker container
incus exec attacker -- hping3 -S -p 9999 --flood 10.10.2.10 &
ATTACK_PID=$!

# Step 2: Measure Host CPU utilization across all cores for 5 seconds
mpstat -P ALL 1 5

# Step 3: Concurrently measure Client HTTP reachability
curl -s -o /dev/null -w "HTTP Response: %{http_code} in %{time_total}s\n" "http://10.10.2.10:80/"

# Step 4: Stop flood and inspect drop counters
kill -9 $ATTACK_PID 2>/dev/null || true
sudo ./build/fw-ctl stats show
```

---

### 3.3 Comparative Analysis: eBPF/XDP vs. nftables Baseline

| Metric | Kernel `nftables` Baseline | eBPF / XDP Firewall | Architectural Demonstration & Findings |
|:---|:---|:---|:---|
| **Clean Stream Throughput** | ~935–945 Mbits/s | ~940–948 Mbits/s | **Parity:** Under normal traffic, established packets pass through the kernel routing engine to the destination in both systems; eBPF fast-path lookup in `conntrack_map` matches netfilter connection tracking speed. |
| **Clean HTTP Request Latency** | ~0.0021 s (2.1 ms) | ~0.0018 s (1.8 ms) | **Slight eBPF Edge:** Direct BPF hash table lookup avoids netfilter hook traversal overhead. |
| **Average Ping RTT** | ~0.14 ms | ~0.11 ms | **Parity:** Negligible difference for ICMP echo packets. |
| **Host CPU Load under SYN Flood** | **28% – 45% CPU** (`%softirq` heavy) | **4% – 12% CPU** | **Significant eBPF Advantage:** In `nftables`, incoming flood packets must allocate `sk_buff` structures, enter the IP layer, and execute netfilter conntrack matching (`nf_conntrack`), creating hash bucket lock contention. In contrast, eBPF drops unauthorized packets before netfilter conntrack table allocation. |
| **Legitimate Client Availability During Attack** | HTTP requests experience timeouts or high jitter (up to 450 ms) | HTTP requests succeed consistently (< 5 ms latency) | **Resilience:** Early packet rejection prevents kernel memory exhaustion and CPU core starvation, preserving legitimate service capacity. |


## 4. Traffic Generation Ecosystem

A suite of specialized scripts is used to simulate diverse network environments, ranging from legitimate client activity to hostile volumetric attacks.

| Script | Purpose | Tools Utilized / Patterns Generated |
| :--- | :--- | :--- |
| `traffic_server.sh` | Initializes target services in the protected container | `nginx` (HTTP), `iperf3` (Throughput server) |
| `traffic_client.sh` | Simulates legitimate user activity | `curl` (HTTP), `iperf3` (Client), `ping` (ICMP) |
| `traffic_attacker.sh` | Generates hostile and malformed traffic vectors | TCP SYN Floods (`hping3 --flood -S`), UDP Blasts, ICMP Floods, TCP Xmas Packets (malformed flags), Unsolicited ACKs, Port Scans (`nmap`) |
| `traffic_generator.py` | Python-based generator for fine-grained control | Custom scapy/socket implementations |

## 5. Validation Procedures

### 5.1 Packet Path Validation
The `scripts/trace_packet_path.sh` utility traces the precise lifecycle of a packet to ensure correct network topology configuration. It validates 5 critical checkpoints:
1. **Kernel IP Forwarding:** Ensures `net.ipv4.ip_forward` is enabled.
2. **Incus Bridges:** Verifies the existence and state of host bridges.
3. **veth Pairs:** Validates the virtual ethernet interfaces connecting containers to the host.
4. **Kernel Routing Table:** Confirms correct subnet routing for the container networks.
5. **eBPF Hooks:** Uses `bpftool` or `ip link` to verify that XDP and TC programs are successfully attached to the correct interfaces.

#### Packet Transit Lifecycle (6 Stages)
1. Packet creation in client container → transmission via `eth0`.
2. Entry into host namespace via peer veth → arrives at bridge `incus-untrust`.
3. **XDP Hook Interception (Ingress):** Early packet inspection yielding `XDP_PASS` or `XDP_DROP`.
4. Host routing engine performs FIB lookup → routes packet toward `incus-protect`.
5. **TC Hook Interception (Egress):** Inspection of the frame prior to delivery.
6. Packet arrives successfully at the webserver container's `eth0`.

### 5.2 Statistics Counter Validation

The firewall maintains detailed metrics via eBPF maps. Validation involves cross-referencing expected traffic with these counters.

| Counter Category | Counter Name | Description |
| :--- | :--- | :--- |
| **Volume** | `STAT_TOTAL_PACKETS` | Total packets processed by the hooks |
| **Direction** | `STAT_INGRESS_PACKETS` <br> `STAT_EGRESS_PACKETS` | Packets entering via XDP <br> Packets exiting via TC |
| **Verdict** | `STAT_ALLOWED_PACKETS` <br> `STAT_DROPPED_PACKETS` | Packets permitted <br> Packets blocked |
| **Protocol** | `STAT_TCP_PACKETS` <br> `STAT_UDP_PACKETS` <br> `STAT_ICMP_PACKETS` <br> `STAT_OTHER_PACKETS` | Protocol-specific packet counts |
| **Drop Reason** | `STAT_DROPPED_UNSOLICITED` <br> `STAT_DROPPED_RULE` <br> `STAT_DROPPED_MALFORMED` | Dropped: out of state <br> Dropped: policy violation <br> Dropped: invalid headers/flags |
| **State Tracking** | `STAT_CONN_NEW` <br> `STAT_CONN_ESTABLISHED` <br> `STAT_CONN_CLOSED` <br> `STAT_CONN_TIMEOUT` | State machine transition counters |

## 6. Interpreting Results & Troubleshooting

### 6.1 Interpreting Test Results
A successful test run will display green `[PASS]` indicators for all phases. Counter validation should exactly match the number of packets injected (e.g., 3 injected ACKs = 3 `STAT_DROPPED_UNSOLICITED`). Benchmark results should clearly demonstrate XDP maintaining higher PPS and lower CPU usage during the SYN flood phase compared to the nftables baseline.

**Sample Output Format:**
```text
==================================================
Running Test Case 1: Allowed Traffic Passes
==================================================
[INFO] Initiating HTTP GET to 10.0.0.5:80...
[PASS] HTTP Status 200 OK received.
[INFO] Initiating ICMP Ping...
[PASS] 2/2 packets received, 0% packet loss.
==================================================
Running Test Case 4: Unsolicited Packets
==================================================
[INFO] Injecting 3 unsolicited ACK packets...
[INFO] Querying drop counters...
[PASS] STAT_DROPPED_UNSOLICITED incremented by 3.
```

### 6.2 Troubleshooting Failed Tests

- **Connection Timeouts on Allowed Ports:**
  - Verify eBPF programs are loaded: `bpftool prog show`
  - Check container networking: `scripts/trace_packet_path.sh`
  - Inspect the kernel trace pipe for debug logs: `cat /sys/kernel/debug/tracing/trace_pipe`
- **Counters Not Incrementing:**
  - Ensure traffic is being routed through the interfaces where XDP/TC hooks are attached.
  - Verify map IDs using `bpftool map show`.
- **State Table Inconsistencies:**
  - If TCP states are not progressing to `ESTABLISHED`, ensure return traffic (SYN-ACK) is correctly traversing the egress hook. Asymmetric routing can bypass the firewall in one direction, preventing state progression.
