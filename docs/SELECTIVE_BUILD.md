# Selective compilation

`feat/selective-build` combines the seven IPv6 branches into one source tree.
The original branches remain unchanged. Selection is **compile-time**, never
a per-packet runtime switch. IPv4/IPv6 parsing, rules, address utilities and
connection layouts are shared.

## Build exactly what you need

```bash
make -j4 ENGINE=fastcache
make -j4 ENGINE=stateful OBSERVABILITY=minimal
make -j4 ENGINE=dualmap TIMING=1
make -j4 ENGINE=fastcache LOGGING=1
make -j4 ENGINE=dualmap TIMING=1 LOGGING=1
make -j4 ENGINE=fastcache OBSERVABILITY=none
```

| Option | Values | Default |
| --- | --- | --- |
| `ENGINE` | `stateful`, `fastcache`, `dualmap` | `fastcache` |
| `TIMING` | `0`, `1` | `0` |
| `LOGGING` | `0`, `1` | `0` |
| `OBSERVABILITY` | `full`, `minimal`, `none` | `full` |

`stateful` corresponds to the historical `Statefull` branch; `dualmap` to
`SHARDED_DUAL_MAP`. Setting `TIMING=1` replaces the separate `*_time` branches.
`LOGGING=1` enables the structured network visibility feature for any engine.

- `full`: counters and sampled transition/drop events. With `LOGGING=0`,
  a small console consumer is linked; with `LOGGING=1`, structured aggregation
  and private JSONL logging are linked instead.
- `minimal`: counters only; no event ring buffer or consumer code.
- `none`: no stats/event/timing maps or consumers; rule hit counters remain.
- Timing requires `full` or `minimal`. Logging requires `full`. Invalid
  combinations fail immediately, rather than silently disabling a feature.

Default `make` builds **one** firewall BPF object and its matching control
plane, not normal/minimal/zero objects together. Tests, benchmarks and the
pass-through baseline are not dependencies of `all`:

```bash
make ENGINE=dualmap tools       # Conntrack population benchmark only
make ENGINE=fastcache baseline # Pass-through BPF object only
make print-config             # Show selected files and output directory
```

Outputs are isolated under:

```text
build/profiles/<engine>-t<timing>-l<logging>-<observability>/
```

For example:

```bash
sudo ./build/profiles/dualmap-t1-l0-full/fw-ctl -i incus-untrust -m hybrid
sudo ./build/profiles/dualmap-t1-l0-full/firewallctl perf show --json
```

The binary defaults to its own profile's BPF object (relative to the repository
root). `BPF_OBJ=/absolute/path` can override relocation, but the object must match
the engine/timing/observability profile. Full-mode logging is a userspace choice
and does not change the BPF object. Only one daemon may use the shared pin
directory at a time. CLI map access rejects incompatible map layouts/profiles.
Stop the daemon and clean stale pins before changing profiles; the loader will
not overwrite another daemon's pins. See [IPv6 deployment](IPV6.md).

## Structure and zero-cost selection

- `include/core/build_config.h`: feature identifiers and compile-time validation.
- `src/kernel/engines/single.bpf.h`: common single-LRU TCP/UDP/ICMP logic;
  FastCache-only blocks are preprocessor-selected.
- `src/kernel/engines/dualmap.bpf.h`: only dual-map TCP placement/promotion.
  UDP and ICMP reuse the single-map implementation.
- `src/kernel/core/conntrack.bpf.h`: selects the engine and optional map-operation
  timing wrappers. No function-pointer or runtime engine dispatch.
- `src/kernel/core/maps.bpf.h`: emits only selected maps.
- `src/kernel/core/timing.bpf.h`: optional per-CPU metrics, absent when disabled.
- `src/userspace/core/perf_mgr.c`: linked only for timing builds.
- `src/userspace/telemetry/console_bus.c`: console events without structured logging.
- `network_log.c` and `event_bus.c`: linked only when `LOGGING=1`.

Compiler-generated dependencies track included files, so editing dual-map TCP
does not rebuild a FastCache object. Each configuration has a compiler/flag
stamp: changed flags rebuild that configuration; unchanged builds preserve
object timestamps. `make clean` removes **only the selected profile**. Other
profiles and legacy `build/fw-ctl` files are left intact; use profile paths, not
the old binary path. Arbitrary flag overrides reuse the same profile directory;
do not run concurrent builds of the same profile with different compiler flags.

Non-timing FastCache XDP and TC instruction sections were compared with the
previous `feat/network-visibility` build and were byte-for-byte identical. This
checks absence of dispatch/instrumentation overhead, **not live throughput**.
Timing and logging on/off produce identical BPF instructions for the same
engine/observability when timing is disabled; logging is userspace-only.

## Timing semantics

`perf show`/`perf reset` are compiled only with `TIMING=1`. Stable IDs cover
extraction, FastCache hash/cache lookup, conntrack map lookups/mutations,
rule lookup, stats, ring buffer and total pipeline. Map-mutation timing measures
helper update/delete calls, not every direct store into an existing map value.
Consequently update totals are not a complete decomposition of pipeline time.
These new metrics are not numerically interchangeable with historical timing
branches. A discarded synthetic hash is no longer reported for stateful/dual-map
engines that do not actually calculate a userspace hash.

Dual-map retains its 5-second SYN/1-second refresh settings; single-LRU/FastCache
retain 30-second SYN/5-second refresh settings. Established-map best-effort GC
runs in the control loop once per second, with bounded scans/deletion batches;
no separate pthread or volatile cross-thread flag is needed. It rechecks entries
before deletion, but lookup/deletion is not atomic with concurrent packet refresh.
Dual-map TCP insertion/promotion failures drop instead of accepting untracked
flows. Other pre-existing state/cache semantics are intentionally retained.

## Validation

```bash
make ENGINE=fastcache test-ipv6
sudo make ENGINE=dualmap TIMING=1 test-ipv6-kernel
make LOGGING=1 test-logging
python3 test/selective_build_test.py
sudo python3 test/selective_build_test.py --kernel
```

The matrix covers **21 valid profiles**, checks selected maps and linked symbols,
no unnecessary baseline/benchmark objects, no-op incremental builds, dependency
isolation, option validation and 55 real XDP/TC packet checks per profile.
Total: **1,155 packet assertions**, plus address/CIDR/CLI/YAML tests. Kernel tests
do not attach to live interfaces. Run unprivileged builds first; use `sudo` only
for kernel tests if you want build outputs to remain owned by your normal user.
Logging's C and Python tests are also retained.

Legacy timing benchmark programs/reports are retained in the repository as
historical reference, but are not built by `all` or the new `tools` target; use
the selected profile's `perf` CLI and kernel packet tests for current metrics.
