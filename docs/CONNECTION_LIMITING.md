# Per-source TCP connection cap

```yaml
connection_limit:
  enabled: true
  interfaces:       # empty selects the sole attached interface
  source_max: 32    # 1..32; tune for legitimate clients behind NAT
```

The cap counts inbound TCP connections per initiator IP/address family across
selected ingress interfaces. Both half-open and closing sessions count. A
retransmitted SYN reuses its full-tuple slot; reverse traffic renews the same
slot rather than consuming another connection. UDP and ICMP are unaffected.
Admission follows SYN policy checks and precedes conntrack allocation. No policy
scan is added to established traffic.

Timeout constants remain in `include/core/constants.h`, unchanged: SYN idle
timeout is 5 seconds for DualMap and 30 for other engines; established idle
timeout is 300 seconds and close timeout is 10 seconds. Slots are reused lazily
on new admission after expiry. Accepted activity renews them, including cache
hits. Failed conntrack allocation can conservatively occupy a SYN slot until
expiry. This is firewall-observed state, not an application socket count, and
inherits the existing TCP state machine's validation limitations.

Source admission and renewal use a shared per-source spin lock. New admission
and accelerator misses scan at most 32 slots, not firewall rules. A verified
LRU tuple hint accelerates established traffic; hint eviction does not remove
authoritative accounting. There is additional lookup/locking overhead on TCP
traffic when enabled; hardware throughput/latency has not been benchmarked.

**Deployment limitation:** the authoritative source hash has 4,096 entries,
roughly 10 MiB of slot values. Expired slots are reused within a source, but
source records are not deleted automatically. Once the table fills with distinct
IPs, new untracked sources fail closed until restart. It is not ready for
unattended long-running production use without safe source-record reclamation.
Using LRU eviction for authoritative records would let attackers bypass the cap.
Many spoofed sources can exhaust this table; configure appropriate anti-spoof
policy where feasible. No aggregate SYN cap is enabled by this feature.

Runtime defaults are disabled for existing configurations; the shipped
`config/firewall.yaml` explicitly enables the 32-connection example. Multiple
attached interfaces require explicit ingress selection. Changes require restart,
and SIGHUP rejects changes rather than silently changing accounting.

Compile out all maps, calls, counters and settings with `make CONN_LIMIT=0 all`
(isolated `-c0` profile), or select the option in `make select`. Rebuild matching
BPF/userspace binaries and restart to apply the new build. Counters are exposed
as `connection_limit_drops` and `connection_limit_map_failures`; limiter drops do
not emit individual packet events.

Validation: `make test-connection-limit` exercises the real admission logic with
mock maps, concurrency, expiry, reverse traffic, full-table handling and config
validation. `make test-ipv6-kernel` exercises XDP and both TC hooks without
attaching a live interface.
