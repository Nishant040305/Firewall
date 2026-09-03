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

## 3. Benchmarking Methodology

The benchmarking framework is designed to provide quantitative evidence of the performance characteristics of the XDP-based firewall, specifically focusing on throughput, latency, and resilience under high-load attack scenarios.

### 3.1 Performance Benchmarking (`test/benchmark_performance.sh`)
This dedicated suite measures the raw capabilities of the eBPF/XDP implementation under various traffic patterns and loads. Key metrics captured include:
- Maximum throughput (measured via `iperf3`)
- Latency jitter under load
- Packet processing rate (PPS) at the XDP hook

### 3.2 Baseline Comparison: nftables vs XDP (`test/benchmark_baseline_nftables.sh`)
To demonstrate the architectural advantages of XDP, this benchmark conducts a direct comparison against the Linux kernel's standard `nftables`.
- **Setup:** Configures equivalent stateful rulesets in both the XDP firewall and kernel `nftables`.
- **Execution:** Measures throughput, ICMP RTT latency, and crucially, CPU utilization during simulated TCP SYN floods.
- **Objective:** To quantitatively prove the CPU and latency benefits of dropping malicious packets at the NIC driver level (XDP) prior to `skb` allocation, compared to the later `netfilter` hooks utilized by `nftables`.

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
