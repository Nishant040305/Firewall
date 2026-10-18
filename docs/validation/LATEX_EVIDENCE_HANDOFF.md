# Evidence handoff for the forthcoming LaTeX report

## Scope and status

This is a preparation/audit note, not a completed runtime validation or a new
benchmark report. The October 4 PDF was read through local `pdftotext` extraction.
Its original content and the LaTeX template have not been changed. No deployment,
traffic generation, nftables installation or new benchmark was performed for
this review.

**Confirmed primary dataset:** the user corrected the intended location to
`benchmark_results/public_vm_test/`, with raw runs under its `results/` folder.
Use this Azure dataset for updated performance content, not the October 4 values.
The user confirms **8 vCPUs / 16 GB RAM for the traffic generator** and
**2 vCPUs / 4 GB RAM for the firewall receiver/system under test**. The dataset
inventory tables are in `benchmark_results/public_vm_test/DATASET_DETAILS.md`.
The user identifies its `no-firewall` arm as the nftables baseline. Label that arm
precisely: **existing host rules (including nftables), eBPF disabled**. No new
nftables experiment is requested by this correction.

## Source hierarchy

| Source | Role | Limits |
|---|---|---|
| `docs/FIREWALL_DEVELOPMENT_AND_LATENCY_REPORT.pdf` | Historical October 4 report; development narrative and old numerical claims | Not authoritative evidence of current deployment or controlled comparisons |
| `benchmark_results/json/2026-10-04/` | Historical seven configuration summaries and three timing records | Some JSON/provenance/sample-retention problems; see `../VALIDATION_REQUIREMENTS.md` |
| `docs/validation/evidence/runtime_second/` | Saved October 17 local Incus runtime inventory | Historical snapshot, not a fresh current inspection; no firewall hooks; `tc` unavailable |
| `docs/validation/evidence/runtime/` | Earlier local inventory | Container lifecycle/name inconsistency; prefer second snapshot |
| `benchmark_results/public_vm_test/results/` | October 17 Azure private-path capacity, resilience and timing data | Different topology/hardware/workloads from local Incus; must be reported separately |
| `docs/VALIDATION_REQUIREMENTS.md` | Detailed prior methodology audit and validation requirements | A plan with blockers, not proof those measurements were completed |
| `docs/SELECTIVE_BUILD.md`, `docs/TC_PACKET_ACCESS.md`, current source | Current profile selection and timing/implementation semantics | Source expectations are not live attachment evidence |
| `docs/BTech_Latex_Report/thesis.tex`, `mnnit.cls`, `references.bib` | Existing thesis template | `thesis.tex` still contains placeholder project/author/chapter material |

The older container/dataplane/testing/visibility documents contain conflicting
or obsolete descriptions. In particular, current IPv6/profile documentation
supersedes older IPv4-only and legacy `build/fw-ctl` examples.

## Actual saved runtime evidence

### Azure datapath: primary dataset

`benchmark_results/public_vm_test/results/private_capacity_fastcache_20261017_162914/inventory.json`
contains actual saved `bpftool -j net` output:

```json
{"xdp":[{"devname":"eth0","ifindex":2,"mode":"driver","id":220}],
 "tc":[{"devname":"eth0","ifindex":2,"kind":"clsact/egress",
         "name":"tc_egress_prog:[222]","id":222}],"flow_dissector":[]}
```

This confirms native/driver XDP on Azure guest `eth0` and TC clsact egress on
that same interface for that run. No TC ingress attachment is listed. It is not
evidence of host-veth or bridge attachment in the local Incus lab.
The corresponding `no-firewall` inventory records empty XDP and TC arrays.
Its attempted BPF rule-list command fails; that failure is retained, not treated
as a host nftables policy dump. These inventories do not save an equivalent
nftables policy or establish matching UDP9999 drop verdicts across the arms.

`README.md` and `RESULTS.md` describe earlier public-path trials, including an
existing redirecting HTTP service and unavailable public ICMP. They must not be
used as the methodology/results for later private-path trials. Private traffic
originates at `172.16.0.5` and terminates at `172.16.0.4`; the firewall runs on the
receiver, not a demonstrated client-container-to-webserver forwarding path.
The private capacity script probes HTTP `/` on port80; the separate resilience
suite uses the dedicated port18080 endpoint.

### Local Incus snapshot: separate historical evidence

`runtime_second/bpftool_net.json` records successful execution of
`sudo -n /usr/bin/bpftool net show` at `2026-10-17T08:10:18.875667+00:00`:

```text
xdp:

tc:

flow_dissector:

netfilter:
```

`bpftool_prog.json` lists unrelated system programs but no firewall entrypoints.
Thus this snapshot establishes **no attached firewall XDP or TC program**, not
native or generic firewall enforcement. It does not establish today's state.

Container/route/link evidence resolves:

| Container | Address | Host peer | Bridge |
|---|---|---|---|
| client | 10.10.1.20 | vethe414f603 | incus-untrust |
| attacker | 10.10.1.10 | vethcb8b47ee | incus-untrust |
| webserver | 10.10.2.10 | vetha433fd60 | incus-protect |
| admin | 10.10.99.10 | veth1c182dd3 | incus-mgmt |

Use `*_veth.json`, `*_route.json`, `ip_d_link.json`, `bridge_link.json`,
`routes.json` and `forwarding.json` to substantiate topology. Veth names are
snapshot identifiers and must be resolved again for a new deployment.

The routing-consistent paths are:

```text
Forward: client eth0 -> vethe414f603 -> incus-untrust -> host routing/netfilter
         -> incus-protect -> vetha433fd60 -> webserver eth0
Return:  webserver eth0 -> vetha433fd60 -> incus-protect -> host routing/netfilter
         -> incus-untrust -> vethe414f603 -> client eth0
```

These are topology-derived paths, **not a correlated captured connection**.
No firewall hook can be inserted into them on the basis of this snapshot.

**Evidence defects:** `vethe414f603_qdisc.json` and other TC commands have
`exit_code: null` and `[Errno 2] No such file or directory: 'tc'`. Empty stdout
there is a failed observation, not proof that a qdisc/filter is absent.
`trace_packet_path.json` correctly prints empty BPF attachment sections but its
final narrative nevertheless invents bridge XDP and TC traversal. The script's
unconditional fallback narrative is not packet capture or hook-execution proof.
Do not reproduce it as a validated live trace.

The loader tries driver XDP and then SKB fallback
(`src/userspace/core/bpf_loader.c:42–69`). Hybrid selects XDP ingress and TC
egress; TC ingress is not automatically required in Hybrid. A future attachment
table needs per-interface IDs/modes/maps plus successful `tc qdisc/filter`
outputs and a functional flow/counter correlation. The PDF's native-veth claim
and `PACKET_PATH_VALIDATION.md`'s generic-bridge claim are not reconciled by the
available no-hook snapshot.

## Methodology content to carry into LaTeX

Do not substitute the example experiments in `05_TESTING_AND_VALIDATION.md`
for the actual generator. The prior local audit designates
`benchmark_results/benchmark_gen.sh` as the historical reference. Its defaults
do not prove historical overrides. See `VALIDATION_REQUIREMENTS.md`, sections
5–6, for exact local defaults and known defects.

| Measurement | Existing methodology to document | Required interpretation |
|---|---|---|
| TCP throughput | Local reference: 10 s single stream, 5 s multistream; Azure capacity: 5 s, three repeats, TCP1/4/8/16/32/64. Raw iperf receiver bytes/duration and sender retransmissions | Delivered application goodput, not wire line rate |
| HTTP latency | Local reference: 50 sequential curl requests; Azure baseline: 50 requests with raw status/exit/time; nearest-rank P50/P95/P99 in `resilience_workload.py` | End-to-end successful HTTP transaction latency, not isolated lookup time; report failures separately; 50-sample P99 is coarse |
| ICMP RTT | Local reference: 50 pings at 0.1 s; Azure baseline: 10 s at 0.2 s; preserve raw ping summaries | RTT min/avg/max/mdev; mdev is dispersion, not a separately defined inter-packet jitter measure |
| SYN load | Local reference: unpaced hping SYN port 80 for 8 s; Azure: bounded up-to-1000 PPS SYN port 18080 for 8 s with overlapping probes | Different workloads; achieved rate, replies/resets and successful overlap needed; not proven DDoS immunity |
| UDP load/drop | Local reference: port9999 unpaced load with actual DROP policy required; Azure: bounded port9999 load and prerequisite check; capacity UDP payloads1400/512/64 and rates100–1000 Mbps | Separate offered/delivered/drop PPS; inconsistent iperf packet accounting and unequal policy arms cannot support matched drop conclusions |
| CPU | Local mpstat and Azure receiver `/proc/stat` plus generator mpstat, exact sample windows and per-core logs | Whole host activity includes other work; CPU credit/offload/window caveats; no engine-only attribution |
| State | Active map/table snapshots and engine-specific forward/reverse/cache layouts | Entries are not necessarily logical connections; none-observability runs do not measure internal occupancy; sparse snapshots do not prove peak occupancy |
| Recovery | Azure: 5 s load, 15 s post-load probing, first of five successful probes below 120% of that repetition's baseline P95 | Script-defined recovery, not universal stabilization; use only valid generator trials and actual offsets |
| XDP-only vs Hybrid | Historical filenames and architecture description alone are insufficient; matching live hooks/engine/policy/traffic required | Azure three-engine Hybrid comparison is not a new XDP-only-vs-Hybrid experiment |
| Kernel timing | Timing reset before TCP startup; 8 s TCP workloads; collect count/avg/min/max after workload; setup/teardown/background hook invocations included | Instrumented operation/hook intervals, not complete network latency |

Azure authoritative controller/artifact mapping is in
`benchmark_results/public_vm_test/results/INDEX.md`, with retry relationships.
Capacity, logging-enabled and timing profiles must remain separate. Original
failed records remain evidence and should not be repaired in place.
The index's last stress entry predates the completed batched retry below.

## Latest retained Azure 8,000-stream timing data

Source: `benchmark_results/public_vm_test/results/private_timing_20261017_231425/`.
Read `results.json` for each test status and matching `ENGINE_tcp8000_r1.perf.json`
for timing. This is `t1-l1-full`, one attempt per engine, 63 private iperf pairs.

| Engine | Receiver-rate sum (Mbps) | Pipeline avg (ns) |
|---|---:|---:|
| FastCache | 4108.158512 | 477.04 |
| Stateful | 4097.614193 | 451.36 |
| Dual Map | 3470.636983 | 464.13 |

All three 8,000 tests are recorded completed. Independently timed instance
averages are summed, not measured in one synchronized aggregate interval.
These single trials do not establish significant engine rankings. Restoration
is recorded as successful in the manifest; no fresh independent hook inspection
was performed during this preparation.

**User exclusion:** 16,000 and above are excluded from performance comparisons.
All three 16,000 trials failed; preserve their diagnostics. 32,000/64,000 were
not attempted, and no engine capacity limit follows from the client timeouts.

## Kernel timing and derived rates

Current measurement references: `src/kernel/main.bpf.c`,
`src/kernel/core/timing.bpf.h`, `src/kernel/core/conntrack.bpf.h`,
`src/kernel/core/rules.bpf.h`, and `src/userspace/core/perf_mgr.c`.

- `bpf_ktime_get_ns()` measures elapsed monotonic kernel time, not a direct
  hardware cycle counter. Instrumentation and interruptions affect intervals.
- Each per-CPU metric accumulates count, total nanoseconds, minimum and maximum.
  Userspace average is `sum(total_time_ns) / sum(count)`; minima/maxima are reduced
  across nonempty CPU populations. The CLI saves rounded averages, not raw sums.
- Pipeline starts inside `process_packet`, after caller context initialization.
  Its end timestamp follows `process_packet_impl` and lookup/update-total metric
  recording. Its own final metric write follows the timestamp. TC preparation,
  final hook return, routing/netfilter, queues and applications are outside it.
- Stage counts differ; rule evaluation and event emission are conditional;
  explicit hash/cache timing is FastCache-specific. Mutation timing omits direct
  stores. Total pipeline is independently timed, not a sum of stage means/minima.
- Metrics can aggregate multiple hooks and background traffic. Report counts as
  recorded operations/invocations unless one-to-one packet attribution is proven.
- Historical October 4 timing boundaries differ from current consolidated code.
  Do not reuse one timing result as both XDP-only and Hybrid measurement.

The historical FastCache record has 73,589 pipeline samples, 510.56 ns average,
302 ns minimum and 43,778 ns maximum; protocol counters show 73,225 UDP,
314 TCP and 50 ICMP. Its 99.63% hit ratio is traffic-specific.

`1e9 / 510.56 ≈ 1.9586e6 invocations/s = 1.96 million invocations/s` is an
idealized reciprocal-time estimate, **not measured single-core sustained PPS or
Mbps**. Conversion to wire packet capacity additionally needs hook multiplicity,
full-path cost and packet-size assumptions. A minimum is not a sustained bound.

## Claim-to-evidence decisions

| Historical claim | Supported wording / disposition |
|---|---|
| Native-veth XDP, exact TC traversal | Unverified in available local snapshot; require actual deployment evidence |
| Trace script proves forward/return hooks | Reject: inventory narrative asserts hooks even with no attachments |
| Sub-microsecond datapath | Restrict to the particular instrumented mean; maxima exceed 1 µs; not end-to-end |
| 1.96 Mpps peak / line-rate headroom | Replace with idealized reciprocal-time estimate |
| Zero measurable HTTP overhead / cache causes lower P95 | Rounded single-run values do not establish equivalence or causality |
| Dual Map guarantees complete SYN/DDoS immunity | Architectural separation is not proof of immunity or preservation of every legitimate flow |
| 0 established-map entries proves 0 attack pollution/eviction | Requires table identity, sampling time, traffic/state correlation and existing legitimate flows |
| CPU savings caused by early native drop | Need matched offered rates/policy/CPU windows; generic mode already uses skb |
| Line rate, core saturation, discrete1500-byte frames | Not established by virtual-link goodput, offload toggles or requested UDP payload |
| Immediate/sub-second recovery | Restrict to valid timed probe criterion; historical label scheduling is defective |
| nftables superiority/parity figures | No controlled raw comparison identified; remove as experimental conclusions |
| Cache-refill/spinlock/frequency explains an outlier | Hypothesis unless separately instrumented; timing maxima alone do not identify causes |

## Existing-host/nftables baseline and completion gaps

The user selects the measured Azure `no-firewall` arm as the existing-host/
nftables baseline. This is a valid comparison of adding the eBPF implementation
on top of retained host/network controls versus those controls alone. It is
**not a demonstrated equivalent-policy nftables-versus-eBPF firewall comparison**.
In particular, allowed UDP delivery without eBPF and eBPF UDP9999 drops answer
different policy questions; do not attribute CPU differences solely to datapath
efficiency. Existing firewalld/Docker/Tailscale rules in the local snapshot belong
to a different environment. The PDF has no adequate direct nftables evidence and the
illustrative comparison figures in `05_TESTING_AND_VALIDATION.md` must not be
promoted into measured results.

Before drafting final claims, audit the confirmed private-run manifests, raw
outputs and analysis. Any separately requested equivalent-policy nftables
experiment must have agreed scope, same topology/workload and policy-level
verdicts, preserved host rules, owned cleanup and comparable offered traffic.
The supported baseline conclusion is limited to observed existing-host versus
added-eBPF performance under the recorded workload and retained controls.

The LaTeX report should separate: development history, current implementation,
observed runtime evidence, historical Incus results, Azure experiments,
measurement definitions/limitations, derived estimates, and pending validation.
Every table row should cite run folder + artifact/key, sample population,
units, profile, repeats and exclusions. Do not silently populate missing runtime
or nftables sections from source-code expectations.
