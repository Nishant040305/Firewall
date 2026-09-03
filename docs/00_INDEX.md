# 📚 Documentation Index — High-Performance Stateful eBPF/XDP Firewall

> **Project**: High-Performance Stateful eBPF/XDP Firewall  
> **Author**: Nishant  
> **Platform**: Linux (Kernel ≥ 5.15 with BTF support)  
> **Technologies**: eBPF, XDP, TC, libbpf, Incus Containers, C

---

## Document Map

| # | Document | Description | Key Topics |
|---|----------|-------------|------------|
| 01 | [Container Lab Environment & Network Topology](01_CONTAINER_LAB_SETUP.md) | Virtual testbed architecture using Incus containers and three-segment network | Containers, bridges, veth pairs, network segments, NAT isolation |
| 02 | [eBPF/XDP Kernel Dataplane Architecture](02_EBPF_DATAPLANE.md) | Kernel fast-path pipeline: parsing, stateful tracking, rule matching, telemetry | 4-stage pipeline, BPF maps, TCP state machine, XDP vs TC |
| 03 | [Build Process & Compilation Guide](03_BUILD_PROCESS.md) | Complete build instructions, two-phase compilation, dependencies, Makefile | Clang BPF target, GCC native, libbpf linking, prerequisites |
| 04 | [Userspace Control Plane & CLI Reference](04_USERSPACE_CONTROL_PLANE.md) | `firewallctl` / `fw-ctl` daemon and management CLI | Rule management, conntrack, stats, BPF loader, map pinning |
| 05 | [Testing, Benchmarking & Validation Guide](05_TESTING_AND_VALIDATION.md) | Automated test suite, nftables benchmark, traffic generation, packet tracing | 4 test cases, benchmark methodology, attack simulation |
| 06 | [Packet Path Validation & Kernel Flow](PACKET_PATH_VALIDATION.md) | Exact packet transit path through the virtual testbed and kernel hooks | 6-stage lifecycle, veth crossing, XDP/TC interception points |
| 07 | [Expandable Platform & Future Extensions](ARCHITECTURE_AND_EXTENSIONS.md) | Modular architecture for future security modules | Rate limiting, SYN cookies, adaptive blacklisting, ML telemetry |

---

## Quick Navigation

### For Understanding the System
1. Start with **[01 — Container Lab](01_CONTAINER_LAB_SETUP.md)** to understand the network topology
2. Read **[02 — eBPF Dataplane](02_EBPF_DATAPLANE.md)** to understand the kernel packet processing pipeline
3. Study **[06 — Packet Path](PACKET_PATH_VALIDATION.md)** to trace a packet end-to-end

### For Building and Running
1. Follow **[03 — Build Process](03_BUILD_PROCESS.md)** for prerequisites and compilation
2. Reference **[04 — Userspace Control Plane](04_USERSPACE_CONTROL_PLANE.md)** for CLI commands

### For Testing and Validation
1. Use **[05 — Testing & Validation](05_TESTING_AND_VALIDATION.md)** for test execution
2. Review **[07 — Extensions](ARCHITECTURE_AND_EXTENSIONS.md)** for future platform capabilities

---

## Project Directory Structure

```
FirewallProgram/
├── README.md                      # Project overview and quick start guide
├── Design.md                      # 16-step architectural design blueprint
├── Makefile                       # Build automation (BPF + userspace)
├── config/
│   ├── firewall.yaml              # Runtime configuration
│   └── rules.yaml                 # Declarative firewall policy rules
├── docs/
│   ├── 00_INDEX.md                # ← This document (master index)
│   ├── 01_CONTAINER_LAB_SETUP.md  # Container lab environment guide
│   ├── 02_EBPF_DATAPLANE.md       # eBPF/XDP kernel dataplane guide
│   ├── 03_BUILD_PROCESS.md        # Build & compilation guide
│   ├── 04_USERSPACE_CONTROL_PLANE.md  # Userspace CLI reference
│   ├── 05_TESTING_AND_VALIDATION.md   # Testing & benchmarking guide
│   ├── PACKET_PATH_VALIDATION.md  # Packet transit lifecycle
│   └── ARCHITECTURE_AND_EXTENSIONS.md # Platform extensions roadmap
├── include/
│   ├── core/                      # Shared data structure headers
│   │   ├── constants.h            # Capacity limits, timeouts, actions
│   │   ├── types.h                # Telemetry events and shared types
│   │   ├── stats.h                # Statistics counter definitions
│   │   ├── rules.h                # Rule structure definitions
│   │   └── conntrack.h            # Flow key and state structures
│   └── protocols/
│       └── icmp_types.h           # ICMP type constants
├── src/
│   ├── kernel/                    # eBPF/XDP kernel dataplane
│   │   ├── main.bpf.c             # BPF entry point (XDP + TC programs)
│   │   ├── core/                  # Core BPF logic headers
│   │   │   ├── context.bpf.h      # Unified packet context
│   │   │   ├── maps.bpf.h         # BPF map definitions
│   │   │   ├── helpers.bpf.h      # Helper functions & ring buffer
│   │   │   ├── rules.bpf.h        # Dynamic rule matching engine
│   │   │   └── conntrack.bpf.h    # Stateful TCP/UDP/ICMP engine
│   │   └── protocols/             # L2/L3/L4 protocol parsers
│   │       ├── proto_eth.bpf.h    # Ethernet L2 parser
│   │       ├── proto_ipv4.bpf.h   # IPv4 L3 parser
│   │       ├── proto_tcp.bpf.h    # TCP L4 parser (ports + flags)
│   │       ├── proto_udp.bpf.h    # UDP L4 parser (ports)
│   │       └── proto_icmp.bpf.h   # ICMP parser
│   └── userspace/                 # Userspace control plane
│       ├── main.c                 # Firewall daemon entry point
│       ├── core/                  # Core userspace modules
│       │   ├── firewall_ctx.c/h   # Master context & lifecycle manager
│       │   ├── bpf_loader.c/h     # BPF object loader & hook attachment
│       │   ├── cli.c/h            # CLI argument parser
│       │   ├── config.c/h         # YAML configuration parser
│       │   ├── rules_mgr.c/h      # Rule CRUD operations
│       │   ├── conntrack_mgr.c/h  # Connection tracking display & flush
│       │   └── stats_mgr.c/h      # Statistics aggregation & display
│       ├── utils/                 # Utility functions
│       │   ├── ip_utils.c/h       # IP address formatting
│       │   └── format_utils.c/h   # Output formatting
│       ├── protocols/             # Protocol display adapters
│       │   ├── protocol_registry.c/h  # Protocol adapter registry
│       │   ├── proto_tcp.c        # TCP display adapter
│       │   ├── proto_udp.c        # UDP display adapter
│       │   └── proto_icmp.c       # ICMP display adapter
│       └── telemetry/
│           └── event_bus.c/h      # Ring buffer event polling
├── scripts/
│   ├── setup.sh                   # Dependency installer (apt & dnf)
│   ├── setup_env.sh               # Incus testbed provisioner
│   ├── teardown_env.sh            # Testbed cleanup
│   └── trace_packet_path.sh       # Packet path tracing utility
└── test/
    ├── README.md                  # Test suite documentation
    ├── run_all_tests.sh           # Automated test cases
    ├── benchmark_baseline_nftables.sh  # nftables vs XDP benchmark
    ├── benchmark_performance.sh   # Performance measurement
    ├── traffic_attacker.sh        # Hostile traffic generator
    ├── traffic_client.sh          # Legitimate traffic simulator
    ├── traffic_server.sh          # Target server starter
    └── traffic_generator.py       # Python traffic generator
```

---

## System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        LINUX HOST                                │
│                                                                  │
│   ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│   │   Client     │  │   Attacker   │  │     Webserver         │   │
│   │ 10.10.1.20   │  │ 10.10.1.10   │  │   10.10.2.10         │   │
│   └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘   │
│          │ (veth)          │ (veth)               │ (veth)       │
│   ┌──────┴─────────────────┴───────┐  ┌──────────┴───────────┐   │
│   │    Bridge: incus-untrust       │  │  Bridge: incus-protect│   │
│   │    10.10.1.0/24                │  │  10.10.2.0/24         │   │
│   └──────────────┬─────────────────┘  └──────────┬───────────┘   │
│                  │                               ▲               │
│                  ▼                               │               │
│   ┌──────────────────────────────┐               │               │
│   │  XDP Hook (Ingress Filter)   │               │               │
│   │  ┌────────────────────────┐  │               │               │
│   │  │ 1. Parse 5-Tuple       │  │               │               │
│   │  │ 2. Conntrack Lookup    │  │               │               │
│   │  │ 3. Rule Evaluation     │  │               │               │
│   │  │ 4. Stats + Telemetry   │  │               │               │
│   │  └────────────────────────┘  │               │               │
│   │     XDP_DROP ↙   ↘ XDP_PASS │               │               │
│   └──────────────────────────────┘               │               │
│                  │                               │               │
│                  ▼                               │               │
│   ┌──────────────────────────────┐               │               │
│   │   Host IPv4 Routing (FIB)    │───────────────┘               │
│   │   net.ipv4.ip_forward = 1    │                               │
│   └──────────────────────────────┘                               │
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │              Userspace Control Plane (fw-ctl)            │   │
│   │  ┌──────┐ ┌───────┐ ┌──────────┐ ┌───────┐ ┌────────┐  │   │
│   │  │ CLI  │ │Config │ │BPF Loader│ │ Rules │ │ Stats  │  │   │
│   │  └──────┘ └───────┘ └──────────┘ └───────┘ └────────┘  │   │
│   └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```
