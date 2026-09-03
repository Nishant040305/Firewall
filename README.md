# High-Performance Stateful eBPF/XDP Firewall

A high-throughput, kernel-native stateful firewall built on **eBPF** and **XDP** on Linux, paired with a flexible userspace control plane (`firewallctl`).

---

## 📋 Architectural Overview (The 16 Steps)

1. **Single Linux Host**: Runs host routing, Incus container lab, and the eBPF kernel dataplane.
2. **Incus Containers**: Lightweight containers (`client`, `attacker`, `webserver`, `admin`) acting as independent network hosts.
3. **Three Network Segments**: Untrusted (`10.10.1.0/24`), Protected (`10.10.2.0/24`), and Management (`10.10.99.0/24`).
4. **Host Routing**: Joined via host bridges (`incus-untrust`, `incus-protect`) and routed by the host kernel.
5. **XDP Ingress Hook**: Early packet filtering before SKB allocation in the Linux network driver.
6. **eBPF Logic Pipeline**: 4-stage processing: Parser → State Engine → Rule Matcher → Telemetry.
7. **5-Tuple Packet Parsing**: Extracts source/dest IP, source/dest port, protocol, and TCP flags.
8. **Dynamic eBPF Rule Table**: Policy rules stored in `rules_map` array for zero-recompile runtime updates.
9. **Stateful Connection Tracking**: Full TCP handshake and flow lifecycle management in `conntrack_map`.
10. **Userspace Control Tool (`firewallctl`)**: Dynamic policy management, conntrack inspection, and telemetry.
11. **Granular Statistics**: Per-CPU line-rate counters for packets, drops, and flow states in `stats_map`.
12. **Baseline Comparison**: Standardized comparison against kernel `nftables`.
13. **Traffic Generation**: `iperf3` throughput, `ping` latency, and `hping3` attack simulations.
14. **Test Suite**: Automated verification of allowed traffic, blocked ports, state tracking, and unsolicited packet drops.
15. **Packet Path Validation**: Traced transit across veth pairs, bridges, XDP, and routing FIB.
16. **Expandable Platform**: Modular foundation for rate limiting, SYN cookies, and machine learning telemetry.

---

## 🚀 Quick Start

### 1. Install Dependencies & Verify Environment (Step 1)
```bash
bash scripts/setup.sh
```

### 2. Initialize Container Lab & 3 Networks (Steps 2 & 3)
```bash
bash scripts/setup_env.sh
```

### 3. Build eBPF Dataplane & Userspace Utility
```bash
make
```

### 4. Start the Stateful Firewall
```bash
# Attach to the untrusted bridge interface
sudo ./build/fw-ctl -i incus-untrust -m hybrid -d both
```

---

## 🛠️ CLI Management with `firewallctl` (Step 10)

`firewallctl` communicates directly with kernel eBPF maps:

```bash
# View active rules
sudo ./build/firewallctl rule list

# Add a rule to allow HTTP web traffic
sudo ./build/firewallctl rule add --proto tcp --dport 80 --action allow --desc "HTTP Web"

# Add a rule to allow iperf3 benchmarks
sudo ./build/firewallctl rule add --proto tcp --dport 5201 --action allow --desc "iperf3"

# Add a rule to allow ICMP ping
sudo ./build/firewallctl rule add --proto icmp --action allow --desc "Ping Echo"

# Load rules from YAML configuration
sudo ./build/firewallctl rule load config/rules.yaml

# Delete a rule by ID
sudo ./build/firewallctl rule del 1

# Flush all active rules
sudo ./build/firewallctl rule flush

# View active stateful connections
sudo ./build/firewallctl conntrack list

# View firewall packet and drop statistics (Step 11)
sudo ./build/firewallctl stats show

# Export statistics as JSON
sudo ./build/firewallctl stats show --json
```

---

## 🧪 Testing & Validation (Steps 12, 14, 15)

### Run the Step 14 Automated Test Suite
```bash
bash test/run_all_tests.sh 10.10.2.10
```
Verifies:
- ✅ Allowed HTTP & ICMP traffic passes.
- ✅ Unauthorized ports (e.g. 8080) are dropped.
- ✅ Full TCP 3-way handshake is recorded statefully in `conntrack_map`.
- ✅ Unsolicited ACK/SYN-ACK packets with no state are dropped.

### Run the Step 12 Comparative Benchmark (nftables vs XDP)
```bash
bash test/benchmark_baseline_nftables.sh 10.10.2.10
```

### Trace Packet Path (Step 15)
```bash
bash scripts/trace_packet_path.sh
```

---

## 📂 Project Directory Structure

```text
├── Makefile                   # Build automation for eBPF and userspace
├── Design.md                  # Comprehensive 16-step architectural design
├── README.md                  # User guide & operations manual
├── config/
│   ├── firewall.yaml          # Global runtime parameters & interfaces
│   └── rules.yaml             # Declarative firewall policy rules
├── docs/
│   ├── PACKET_PATH_VALIDATION.md   # Step 15 packet path flow documentation
│   └── ARCHITECTURE_AND_EXTENSIONS.md # Step 16 future platform extensions
├── include/
│   ├── core/
│   │   ├── constants.h        # Capacity limits, timeouts, and actions
│   │   ├── types.h            # Telemetry events and shared types
│   │   ├── stats.h            # Step 11 statistics counter definitions
│   │   ├── rules.h            # Step 8 rule structure definitions
│   │   └── conntrack.h        # Step 9 flow key and state structures
│   └── protocols/
│       └── icmp_types.h       # Protocol header definitions
├── src/
│   ├── kernel/
│   │   ├── main.bpf.c         # eBPF XDP/TC entrypoint and pipeline
│   │   ├── core/
│   │   │   ├── context.bpf.h  # Unified packet context
│   │   │   ├── maps.bpf.h     # BPF maps (rules, conntrack, stats, events)
│   │   │   ├── helpers.bpf.h  # Helper functions and ringbuf emission
│   │   │   ├── rules.bpf.h    # Step 8 dynamic rule matching engine
│   │   │   └── conntrack.bpf.h# Step 9 stateful TCP/UDP/ICMP engine
│   │   └── protocols/         # L2/L3/L4 protocol parsers
│   └── userspace/
│       ├── main.c             # Firewall main entrypoint
│       └── core/
│           ├── bpf_loader.c   # BPF object loader & map pinning
│           ├── cli.c          # firewallctl CLI argument parser
│           ├── config.c       # YAML configuration parser
│           ├── rules_mgr.c    # Step 8 rule manager
│           ├── conntrack_mgr.c# Step 9 connection tracking manager
│           └── stats_mgr.c    # Step 11 telemetry manager
├── scripts/
│   ├── setup.sh               # Step 1 dependency installer (apt & dnf)
│   ├── setup_env.sh           # Steps 2 & 3 Incus testbed provisioner
│   ├── teardown_env.sh        # Testbed cleanup script
│   └── trace_packet_path.sh   # Step 15 packet tracing utility
└── test/
    ├── run_all_tests.sh       # Step 14 automated test cases
    ├── benchmark_baseline_nftables.sh # Step 12 nftables vs XDP benchmark
    ├── traffic_attacker.sh    # Hostile traffic generator (SYN floods, scans)
    ├── traffic_client.sh      # Legitimate client traffic simulator
    └── traffic_server.sh      # Target server daemon starter
```

---

## 📚 Detailed Documentation

For in-depth, professor-grade technical documentation covering every aspect of the project, refer to the [`docs/`](docs/) directory:

| Document | Description |
|----------|-------------|
| [**00 — Documentation Index**](docs/00_INDEX.md) | Master navigation index with project structure and architecture overview |
| [**01 — Container Lab Setup**](docs/01_CONTAINER_LAB_SETUP.md) | Incus container testbed, three-segment network topology, veth pairs, bridges |
| [**02 — eBPF/XDP Dataplane**](docs/02_EBPF_DATAPLANE.md) | Kernel fast-path pipeline: 4-stage processing, BPF maps, TCP state machine |
| [**03 — Build Process**](docs/03_BUILD_PROCESS.md) | Two-phase compilation (Clang BPF + GCC native), dependencies, Makefile targets |
| [**04 — Userspace Control Plane**](docs/04_USERSPACE_CONTROL_PLANE.md) | `firewallctl` CLI reference, BPF loader lifecycle, configuration, map pinning |
| [**05 — Testing & Validation**](docs/05_TESTING_AND_VALIDATION.md) | Automated test suite, nftables benchmark, traffic generation, attack simulation |
| [**06 — Packet Path Validation**](docs/PACKET_PATH_VALIDATION.md) | Six-stage packet transit lifecycle from container to container through XDP/TC hooks |
| [**07 — Platform Extensions**](docs/ARCHITECTURE_AND_EXTENSIONS.md) | Future modules: rate limiting, SYN cookies, adaptive blacklisting, ML telemetry |

---

## 🧹 Teardown

To clean up all test containers and virtual network bridges:
```bash
bash scripts/teardown_env.sh
```
