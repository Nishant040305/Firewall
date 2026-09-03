# Expandable Firewall Platform & Architecture (Step 16)

This firewall is built on a modular eBPF/XDP architecture designed to easily accommodate advanced security modules without modifying the underlying network topology.

---

## 1. Modular Platform Architecture

```
                    ┌──────────────────────────────────────┐
                    │      eBPF/XDP Fast Dataplane         │
                    └──────────────────┬───────────────────┘
                                       │
         ┌───────────────────┬─────────┴─────────┬───────────────────┐
         │                   │                   │                   │
         ▼                   ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ 1. Rate Limiter │ │ 2. DDoS / SYN   │ │ 3. Adaptive     │ │ 4. ML Anomaly   │
│  (Token Bucket) │ │     Cookies     │ │   Blacklisting  │ │  Feature Engine │
└─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘
```

---

## 2. Platform Expansion Modules

### A. Token-Bucket Rate Limiter
- **Purpose**: Prevent bandwidth exhaustion and brute force attacks by limiting packets/bytes per second per source IP.
- **eBPF Map**: `BPF_MAP_TYPE_LRU_HASH` storing tokens and `last_updated_ns` per `src_ip`.
- **Mechanism**: Refills tokens at a configured rate; packets arriving when tokens are 0 are dropped with `XDP_DROP`.

### B. Stateless SYN Cookies (DDoS Defense)
- **Purpose**: Protect against massive TCP SYN floods that attempt to exhaust the connection tracking table memory.
- **Mechanism**: When `conntrack_map` utilization exceeds a high watermark (e.g. 80%), the firewall switches to stateless SYN cookies:
  - Generates a cryptographically hashed initial sequence number containing IP/port information and timestamp.
  - State is only committed to `conntrack_map` once a valid client ACK containing the matching sequence number arrives.

### C. Adaptive Dynamic Blacklisting
- **Purpose**: Automatically block attackers scanning ports or sending malformed packets.
- **Mechanism**:
  - The kernel increments a `violation_count` for source IPs that trigger policy drops.
  - Once violations exceed a threshold (e.g. 10 drops in 5 seconds), the source IP is automatically added to an in-kernel blacklist map with a temporary TTL (e.g. 10 minutes).

### D. Machine Learning Anomaly Detection Telemetry
- **Purpose**: Feed rich flow-level statistics to userspace AI/ML models for zero-day threat detection.
- **Mechanism**:
  - eBPF emits flow summaries (packet length distributions, inter-arrival jitter, TCP window sizes) into the BPF ring buffer.
  - A userspace inference service evaluates flow behavior in real time and dynamically injects block rules via `firewallctl`.
