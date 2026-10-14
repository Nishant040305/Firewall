# Network visibility without alert fatigue

This first stage adds **evidence logging**, not attack detection, automatic blocking,
or a public dashboard. A firewall drop is not proof of an attack. All network
records are informational; filtering the viewer never changes firewall policy.

## Start and inspect

Build with `make`, then restart the daemon during a planned maintenance window
using your existing, verified interface/rule configuration. The shared event
layout and statistics map changed: deploy the new userspace binary and BPF object
together. Do not run a second daemon against an existing deployment just to read logs.

The standard `build/firewall.bpf.o` emits metadata. The benchmark objects
`firewall_fast.bpf.o` and `firewall_zero_obs.bpf.o` disable packet events and must
not be used for incident visibility. This change does **not** turn the firewall
into a passive sensor: existing rules still enforce their normal decisions.

Default configuration in `config/firewall.yaml`:

```yaml
telemetry:
  path: telemetry/network.jsonl
  aggregate_window_sec: 30
  max_file_mb: 20
  console_events: false
```

The parent directory must exist, be owned/controlled by the host operator, and not
be writable by an application container. Paths are relative to the daemon working
directory; use an absolute path under a host log directory in production. Files
are restricted to mode `0600`; symlinks, non-regular files, multiple hard links,
and files owned by another user are rejected. Do not place credentials in paths.
Opening the evidence log is required at startup; failure after BPF attachment
causes startup to abort and detach. Runtime write failures do not change policy.

There is one rotated backup (`network.jsonl.1`), approximately 40 MB total by
default. Rotation is byte-based, **not guaranteed days of retention**. An off-host
collector should continuously ship the files before they are overwritten.
Do not use an additional competing file rotator. Writes are flushed to the OS,
not fsynced per record; crashes/power loss can lose buffered/recent evidence.

```bash
# Live outbound evidence, updated at the aggregation interval
sudo python3 scripts/network_logs.py --follow --direction out

# Both endpoints can match an IP or subnet
sudo python3 scripts/network_logs.py --ip 192.0.2.0/24 --action drop

# Service-specific view
sudo python3 scripts/network_logs.py --port 443 --direction out

# Less noise: top endpoint/service/verdict groups, including retained history
sudo python3 scripts/network_logs.py telemetry/network.jsonl.1 telemetry/network.jsonl --summary

# Inspect logging gaps separately from traffic
sudo python3 scripts/network_logs.py --health
sudo ./build/firewallctl stats show --json
```

Pass explicit paths if the daemon uses a non-default log destination. The viewer
only requires file read permission, not BPF access. Normal views hide health
records. `--reason` distinguishes `policy`, `default_policy`, `invalid_state`,
`malformed`, and `state`; `--action` distinguishes `allow`/`drop`.

## Evidence and noise reduction

Records include IPv4 source/destination, ports, protocol number, interface index,
hook direction, action, rule ID, reason, TCP flags, connection state, and first/last
timestamps. `new_flow` marks allowed TCP SYNs and newly tracked UDP/ICMP flows;
it is not a count of unique successful connections. UTC timestamps are derived
from a startup realtime/monotonic offset; host clock changes can introduce drift.
Monotonic nanosecond fields preserve ordering within the host boot.

Within each flush window, identical metadata events become one record with an
`event_count` and `observed_bytes`. Different tuples, rules, flags, states, or
verdicts are never silently merged. Aggregation uses bounded memory; hash
collisions flush the older entry rather than discard it. High-cardinality scans
can still produce many records. The offline summary groups away source ports;
the underlying evidence preserves them. No normal traffic is permanently
excluded by a default ignore list.

The console no longer prints periodic full statistics tables or individual
packet events. Use `stats show` on demand. `console_events: true` is an optional
debug mirror of aggregated JSON and health records. SIGHUP applies aggregation,
file-size, and console settings from the normal daemon loop; changing log paths
or attachment interfaces requires restart.

## Coverage and limits

- Events cover drops, selected TCP lifecycle packets, and newly tracked UDP/ICMP
  flows. **Established bulk traffic is not captured packet-by-packet.**
- `observed_bytes` counts only emitted events. It is not flow bandwidth, transfer
  size, or exfiltration accounting. Existing conntrack counters also use lazy
  updates and must not be treated as exact byte totals.
- Only interfaces attached by the daemon are visible. `in`/`out` mean interface
  hook direction, not necessarily internet-to-container direction. Verify Docker
  veth/bridge placement and NAT behavior with controlled inbound/outbound tests.
  Interface indices need to be correlated with host interface inventories.
- IPv6/non-IPv4 traffic remains uninspected by this dataplane. There is no VLAN
  parser, payload capture, DNS domain parsing, TLS decryption, HTTP request logging,
  container/process attribution, or human identity lookup in this stage.
- Truncated/malformed IPv4 packets may have unknown endpoints (`0.0.0.0`, port 0,
  protocol 0) because their headers could not be safely parsed.
- There are no per-packet reputation lookups or additional filtering rules.

`telemetry_health` records contain cumulative events received, invalid event
sizes, aggregation evictions, write errors, and kernel ring-buffer reservation
failures (`kernel_events_lost`). Kernel loss counters reset with maps/stat resets;
user counters reset with daemon restart. A successful kernel-stat read does not
prove sensor coverage. Losses cannot reconstruct missing source IPs. Under floods,
ring-buffer pressure and log churn can still limit evidence; kernel-side telemetry
rate limiting/flow summaries and monitoring for missing health heartbeats are
future work. A disk failure can also prevent the health record itself being stored.

## Next signals to add, separately

Add trusted-proxy HTTP metadata and Falco process alerts, plus container CPU/RAM
metrics. Redact authorization headers, cookies, query secrets and command-line
secrets. Do not persist whole request bodies or environment dumps by default.

Only after those sources are correlated should there be notifications: for example,
an unexpected shell child of Next.js followed by an unusual outbound connection.
Use one incident key per container/detector, cooldowns, counts and recovery notices.
Keep raw evidence searchable even when notifications are suppressed. Ordinary
port scans/drops should normally appear in summaries rather than page an operator.

## Validation

`make test-logging` runs unprivileged aggregation, rotation, permissions, symlink,
configuration and viewer-filter tests. `make` compiles the dataplane and daemon.
Actual BPF verifier loading, Docker/NAT placement, traffic coverage and high-load
behavior require a separate controlled deployment test; building is not proof of
runtime coverage.
