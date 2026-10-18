# SYN rate limiting

The firewall now optionally limits initial TCP SYN packets (SYN set, ACK clear),
including retransmissions, before rule evaluation and connection-state creation.
It is **not** a bandwidth limiter or a limit on established TCP data, UDP or ICMP.
The established TCP idle timeout remains 300 seconds.

## Configuration

### Compile the feature out

```sh
make -j4 RATE_LIMIT=0
# Or: make -j4 lean RATE_LIMIT=0
```

`RATE_LIMIT=1` is the build default. With `RATE_LIMIT=0`, the limiter header,
checks, BPF maps, initialization, configuration fields and limiter counters are
excluded at compile time. The runtime `rate_limit` section is ignored and cannot
enable it. Startup diagnostics explicitly report "compiled out".
Disabled builds use a separate profile directory with `-r0` appended, e.g.
`build/profiles/fastcache-t0-l0-full-r0/`. Use its matching `fw-ctl` binary.
`make select` also offers this choice. `test-rate-limit` requires `RATE_LIMIT=1`;
the normal dataplane tests verify absence of limiter maps in disabled builds.

`config/firewall.yaml` enables an example profile:

```yaml
rate_limit:
  enabled: true
  interfaces: eth0
  source_rate: 100
  source_burst: 200
  aggregate_enabled: false
  aggregate_rate: 10000
  aggregate_burst: 20000
```

Rates are SYN packets/second; bursts are packets. These are starting examples,
not measured production recommendations. Account for NAT clients and handshake
retransmissions. Set `enabled: false` to disable. Without a rate-limit section,
the control plane defaults to disabled for compatibility.

`aggregate_enabled: false` keeps only per-source limiting: no aggregate bucket
is initialized, looked up or locked. `aggregate_rate` and `aggregate_burst` can be
omitted in this mode. The map definition remains in rate-limit-enabled builds.
Set `aggregate_enabled: true` to enforce the shared cap too. Existing configs
that omit this flag retain aggregate limiting for backward compatibility; the
shipped config explicitly disables it. Rebuild matching BPF/userspace and restart
after this configuration-layout change. Many-source/spoofed-source floods can
overwhelm per-source protection without an aggregate guard.

An empty `interfaces` selects the sole attached interface. If the firewall is
attached to multiple interfaces, explicitly provide a comma-separated subset of
external ingress interfaces. Each selected interface has its own aggregate and
per-source budgets. Select only one enforcement ingress per packet path to avoid
charging packets multiple times. TC egress never consumes rate-limit tokens.
Rate-limit changes require a daemon restart; SIGHUP rejects changes to this section.

## Dataplane

Validated SYN -> optional aggregate bucket -> source bucket -> existing state/rules.
Over-limit packets do not scan rules or allocate state. Allowed packets still
must satisfy firewall policy. The source key includes ingress interface, address
family and the full source address, not the source port or destination port.

Shared hash-map values use short BPF spin-lock critical sections to coordinate
budgets across CPUs. Timestamp and helper calls stay outside the lock. Fractional
refill credit is preserved with integer arithmetic and bounded multiplication.
Concurrent first insertion uses `BPF_NOEXIST`, never resetting another CPU's
bucket. When enabled, aggregate tokens are consumed even when the source limiter or policy
subsequently rejects the packet: they budget attempted SYN processing.

Unlike the earlier proposed direct-indexed configuration array, configuration is
a small hash keyed by ifindex, so selecting an interface needs one lookup, not
an interface list scan or a firewall-rule scan. Established TCP does not perform
rate-limit map lookups.

## Important capacity limitation

The source map holds **65,536 source/interface pairs across all scopes**. This
first version deliberately does not evict or delete entries during operation:
unsafe deletion can race with packets and reset budgets, while LRU churn grants
fresh bursts to spoofed sources. Once full, untracked sources are dropped;
existing tracked sources continue under their budgets. Restart creates fresh
maps, but also resets connection state and budgets.

This is bounded, fail-closed behavior, **not a complete defense against source
churn or a production-ready long-running reclamation policy**. Safe idle-entry
reclamation remains a follow-up; monitor map failures and capacity before rollout.
An aggregate cap slows admission but cannot prevent eventual table exhaustion.
Shared aggregate locks also create contention under floods: benchmark on target
hardware. XDP cannot recover upstream bandwidth already consumed by an attack.

## Observability and tests

`fw-ctl stats show --json` includes `syn_source_drops`, `syn_aggregate_drops` and
`syn_map_failures`. Overall drop counters include these packets. Rate-limit drops
do not generate per-packet ring-buffer events; this avoids flood logging overhead.
Counters are unavailable in builds using `OBSERVABILITY=none`.

```sh
make -j4
make test-rate-limit
make test-ipv6
sudo make test-ipv6-kernel
```

Unit tests cover arithmetic, fractional refill, overflow bounds, concurrent
source budgets, address/scoping behavior and map exhaustion. Kernel tests load
and test-run XDP and TC programs without attaching interfaces, checking SYN
enforcement, source-port bypass attempts, no rejected-flow allocation, and
established-data/egress bypass. Real NIC throughput, latency, NAT workloads and
distributed spoofed-source attacks still need deployment-specific validation.
