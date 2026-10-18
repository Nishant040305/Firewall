# Firewall validation: requirements, measurements and system changes

## 1. Agreed scope and current status

**October 18 addendum:** The author completed a separate Azure public HTTP flow
check for Dual Map `t1-l1-full`, Hybrid mode. Current native XDP on `eth0` and
TC egress were correlated with capture and selected TCP transition events;
ingress reports the associated `mlx5_core` VF index 3, egress `eth0` index 2.
Selected supplied excerpts are in `docs/validation/evidence/azure_public_flow_20261018/`.
This does not change the saved October 17 local no-hook finding or complete the
generic-XDP/container-path and attack-validation tasks below.

**Target: generic/SKB XDP, not native-driver XDP.** Validate the existing firewall;
do not add firewall features or rerun the entire benchmark suite by default.
Use `benchmark_results/benchmark_gen.sh` as the sole traffic-generation reference.
Do not use a different benchmark script as an interchangeable reference.

This is a requirements and execution plan, **not a claim that the measurements
below have been completed**. Additional traffic and temporary deployment changes
must be agreed before execution. Nothing in this plan authorizes replacing the
host firewall, restarting unrelated services or flushing host-wide state.

Read-only inventory on 2026-10-17 established:

- Privileged `bpftool net show` has empty XDP and TC sections. No firewall
  entrypoints appear in `bpftool prog show`.
- The second snapshot resolves client `vethe414f603`, attacker `vethcb8b47ee`,
  webserver `vetha433fd60`, and admin `veth1c182dd3`.
- Client/attacker ports belong to `incus-untrust`; webserver belongs to
  `incus-protect`; admin belongs to `incus-mgmt`.
- Client is `10.10.1.20/24`, gateway `10.10.1.1`; webserver is `10.10.2.10/24`,
  gateway `10.10.2.1`. Host forwarding is enabled.
- Current host kernel is `7.2.8-200.fc44.x86_64`; October 4 results record
  `7.2.4-200.fc44.x86_64`. These are different environments.
- The first snapshot caught a container lifecycle change. The old client host
  name was stale, and one container read failed. Prefer the second snapshot;
  never treat volatile host names as permanent identifiers.
- The host has firewalld, Docker and Tailscale-related nftables rules. These are
  existing system configuration, **not a measured nftables benchmark baseline**.

Raw outputs, timestamps, commands, errors and exits are under
`docs/validation/evidence/runtime/` and `runtime_second/`.
The repeatable read-only collector is `docs/validation/collect_runtime.py`.

### Remaining blockers

1. No firewall is running: no live generic-XDP attachment or firewall traversal
   can currently be demonstrated.
2. The exact historical active policy, binaries, build flags, tuning and raw
   latency/CPU samples are not preserved alongside the October 4 summaries.
3. No historical controlled nftables measurement was identified. Completing
   that comparison needs a temporary lab-scoped deployment and agreed policy.
4. Generic-only deployment is not enforced by the current loader: it tries
   driver mode first and generic mode on failure.

## 2. Systems and software needed

| System | Role and requirements |
|---|---|
| Existing Linux host | Incus lab, IPv4 routing, generic XDP, TC, BPF maps, nftables, CPU and interface instrumentation; sudo access for the agreed operations |
| `client` | `10.10.1.20`; legitimate TCP, HTTP and ICMP generator; `iperf3`, `curl`, `ping`, `ethtool` |
| `attacker` | `10.10.1.10`; bounded SYN/UDP generation with `hping3` and `timeout`; traffic confined to the owned lab |
| `webserver` | `10.10.2.10`; existing nginx HTTP endpoint and iperf3 server on TCP/UDP 5201; interface and server-side capture access |
| `admin` | `10.10.99.10`; optional separate management path, not a required traffic generator; do not filter or interrupt management |
| Analysis workstation | May be the host; Python 3, JSON/CSV tools and SHA-256 tools; preserve raw data and derived results separately |

Host tools: `ip`, `bridge`, `tc`, `bpftool`, `ethtool`, `sysctl`, `incus`,
`tcpdump`, `mpstat` (sysstat), `nft`, optionally `conntrack`, Git and Python 3.
Record exact tool versions; do not assume installed versions match old runs.
No public VM or public Internet traffic is necessary. Existing public-VM results
are a separate dataset, not comparable evidence for the Incus lab or nftables.

Keep identical hardware/VM allocation and topology across comparison arms.
Record CPU model, online/possible CPU count, frequency governor, affinity,
memory, kernel, Incus/container versions, iperf3 version, MTUs, link queues,
offloads, RPS masks, routing, bridge configuration and unrelated background load.
The generator's historical `cpus: 20` is not a substitute for this inventory.

## 3. Deployment decisions required before measurements

### 3.1 Choose one generic-XDP placement

**Recommended validation target:** generic XDP ingress and TC egress on the
host-side client and attacker veth ports. This retains the traffic boundary
described in the generator while changing only the XDP execution mode.
Re-resolve both names immediately before deployment.

An alternative is generic XDP on `incus-untrust`, with TC on explicitly selected
bridge interfaces. This is a different placement and must be separately proven
to encounter the routed traffic. Do not combine bridge and port attachments
silently: a packet can be evaluated multiple times.

Record the chosen placement, interfaces, mode, direction and object path.
Do not mix results from the two placements in one comparison table.

### 3.2 Explicit generic-only selection

`src/userspace/core/bpf_loader.c:52-59` currently attempts `XDP_FLAGS_DRV_MODE`
before `XDP_FLAGS_SKB_MODE`. For a controlled generic experiment:

- Prefer an existing explicit generic selector if one is verified available.
- Otherwise make a small, reviewed attachment-only change to use
  `XDP_FLAGS_SKB_MODE` for this agreed deployment; no datapath feature change is
  needed. Record the patch, rebuild and object/binary hashes.
- Merely choosing an interface believed to lack driver XDP is not sufficient
  evidence. Verify **every** attachment reports `generic`/SKB.
- Do not use a separate manual attachment with different maps from the daemon.

### 3.3 Policy and state

Current `config/rules.yaml` is catch-all allow. It does **not** block UDP 9999.
The generator's blocked-UDP experiment therefore needs an explicitly agreed
lab policy, saved with the run, or must be labelled an allowed-port load test.

Define allowed client HTTP/TCP 5201/UDP 5201/ICMP, attacker SYN-to-80 behavior,
UDP-to-9999 behavior, reverse traffic and default action. Use the same intended
verdicts for eBPF and nftables. Preserve both active policy dumps, not just YAML.
No-rule kernel behavior is DROP despite the YAML `default_policy: pass`; keep
an explicit catch-all if an allow default is intended.

Keep SYN port 80 as specified by the reference generator. Do not silently
replace it with a blocked SYN port from older documentation. An allowed SYN load
and a blocked-port load answer different questions.

## 4. Required attachment and packet-path evidence

Run inventory before and after each deployment change. Preserve full output:

```bash
ip link show
ip -d link show
sudo bpftool net show
sudo bpftool prog show
bridge link show
ip route show table all
ip rule show
sysctl net.ipv4.ip_forward
sudo bash scripts/trace_packet_path.sh
```

For **each** relevant bridge and host veth, collect:

```bash
ip -d link show dev INTERFACE
tc -s qdisc show dev INTERFACE
tc -s filter show dev INTERFACE ingress
tc -s filter show dev INTERFACE egress
ethtool -k INTERFACE
```

Required attachment table fields: interface, ifindex, bridge master/container
peer, program ID, full entrypoint name, program tag, XDP mode, TC direction,
qdisc, filter handle/priority, map IDs, loaded object/build, and verification time.
Join program IDs across commands; loaded-but-unattached is not active enforcement.
Hybrid ordinarily uses XDP ingress plus TC egress; `tc_ingress_prog` is expected
in TC mode, not automatically in Hybrid. Report absent hooks explicitly.

### Complete flow validation

Use one identifiable client HTTP TCP connection, with capture on client/server
`eth0` and the relevant host veth/bridge interfaces. Preserve PCAPs and filters.
Capture SYN, SYN-ACK, ACK, request, response, and FIN/RST; correlate the 5-tuple
and timestamps. Inspect firewall state/events before and after without flushing
unrelated state. Capture can affect timing: this is a functional test, not a
performance sample. Packet capture alone does not prove a particular BPF hook
executed; combine attachment evidence with isolated counter/state/event deltas.

For the recommended **port placement**, the proposed paths are:

```text
Forward:
client eth0 -> client host veth [generic XDP ingress]
 -> incus-untrust -> host routing/netfilter -> incus-protect
 -> server host veth -> webserver eth0

Return:
webserver eth0 -> server host veth -> incus-protect
 -> host routing/netfilter -> incus-untrust
 -> client host veth [TC egress] -> client eth0
```

These are deployment expectations, not observed firewall paths today. Annotate
any additional XDP/TC attachment encountered at every port/bridge in both
directions. XDP on the attacker port is not traversed by the client flow.
If only client/attacker ports are protected, server-originated traffic has no
firewall ingress hook there; return tracking occurs on the destination-port TC.
Validate the actual engine's handshake transitions, rather than assuming all
engines/modes have identical state observations.

**Generic-XDP caveat:** packet processing already uses an `sk_buff`. There is
no native-driver pre-allocation drop claim, and no “zero skb overhead” claim.

## 5. Measurements required and reference workload

Defaults below come from `benchmark_results/benchmark_gen.sh`; record actual
CLI/environment overrides for every run. Existing summaries alone cannot prove
which defaults were used. No `wrk` workload is defined by this reference.

| Measurement | Reference workload/duration | Required outputs and interpretation |
|---|---|---|
| Single-stream TCP | Client `iperf3 -c 10.10.2.10 -t 10 -J`; quick 5 s | Full raw JSON; sender and receiver Mbps, bytes, actual duration, retransmits, errors; receiver throughput is delivered application data |
| Multi-stream TCP | `iperf3 ... -t 5 -P N -J`; default N=1,4,8,16,32,64; CLI can override/linearize | Sender and receiver aggregate Mbps, retransmits, actual streams/duration; sample state table around 2.5 s; retain failed/timeout runs |
| HTTP baseline | 50 sequential curl requests; quick 20; `%{time_total}` and 2 s connect timeout | Every request's time, HTTP code, exit status; valid count, failures, mean/P50/P95/P99; distinguish successful-response latency from attempted-request latency |
| ICMP baseline | `ping -c 50 -i 0.1`; quick 20 | Raw replies/summary; sent/received/loss, min/avg/max/mdev RTT; mdev is RTT dispersion, not a separate precisely defined packet-to-packet jitter metric |
| UDP throughput/PPS | `iperf3 -u -b 500M -l L -t 10 -J`; quick 5 s; L=64,128,512,1024,1500; quick 64,512,1500 | Sender/receiver bytes and packets, duration, loss, jitter, achieved offered/delivered PPS; L is UDP payload length, not Ethernet frame size |
| Idle CPU | Host `mpstat 1 5` after baseline traffic | Full header and samples; all-CPU mean and per-core activity; unrelated background load |
| UDP-load CPU | Separate repeat of each UDP workload with `mpstat 1 DURATION` | Preserve both trials; CPU is not simultaneous with the original throughput trial; report that distinction |
| New TCP connection rate | 200 curl launches, batches of 20 concurrent; quick 100 | Start/end monotonic time, attempted and successful completions/sec, failure count, new-flow counter delta, state entries; reference description “sequential” is inaccurate |
| Conntrack occupancy/state | Mid-flight TCP streams; post connection burst and SYN load | Timestamped raw table/map dumps, occupancy, unique logical flows, states and forward/reverse counts; include iperf control connection; do not call every map entry a connection |
| State memory | Empty and after 100 concurrent HTTP attempts | Map type/key/value/max entries/memlock, engine and cache footprint; distinguish allocation from occupied payload and logical-flow memory |
| SYN load | Attacker `timeout 8 hping3 -S -p 80 --flood 10.10.2.10`; quick 5 s | Actual start/end, achieved offered/received/drop PPS, SYN/reply counts, policy verdicts, occupancy/states; no claim of blocked-SYN mitigation if SYNs are allowed |
| Legitimate traffic during SYN | After 1 s: 20 pings at 0.2 s, then 20 HTTP requests | Per-probe timestamps/results, overlapping versus post-load samples, RTT/loss, HTTP codes/success and latency; preserve all failures |
| UDP load | Attacker `timeout 8 hping3 --udp -p 9999 --flood ...`; quick 5 s | Confirm active DROP rule for this test; achieved PPS, rule-drop deltas, delivery at server, state behavior |
| Legitimate traffic during UDP | After 1 s: 15 HTTP requests, then 10 pings at 0.2 s | Per-probe times/results and verified load overlap; HTTP success, RTT/loss |
| Load CPU | `mpstat 1 (FLOOD_DURATION+2)` | Full per-second/per-core samples and exact overlap; separately summarize active-load and reference full-window means |
| Recovery | 5 s SYN load, then HTTP probes labelled 0,1,2,3,5 s; 10 pings at 0.1 s | Actual monotonic time since generator stop, HTTP status/time, state occupancy, RTT/loss; agreed return-to-baseline threshold and sustained window |
| XDP-only vs Hybrid | Same generic placement, engine/policy/build/traffic; XDP ingress versus XDP ingress+TC egress | Hook inventories and per-direction counts, forward/return state behavior, delivered throughput/latency/CPU; acknowledge differing return-path coverage |
| Kernel operation timing | Existing timing-enabled build and selected reference workloads | Raw `perf_map`/perf output, counts/sums/min/max, build flags, reset/read times, traffic mix and hook coverage; separately from application timing |

Do not present one traffic batch as many independent benchmark repetitions.
For **new controlled comparisons**, use at least three independent repetitions
per arm with counterbalanced order, identical sample counts and durations, and
median/range plus all individual values. More repetitions are needed for a
strong “no overhead” or small-difference claim; do not invent confidence bounds.
For P99, 50 samples have very coarse tail resolution; disclose that limitation
or agree on a larger count using the generator's `HTTP_COUNT` override.

## 6. Benchmark corrections required before new quantitative claims

Keep historical files unchanged; save corrected analyses separately.
Any generator changes should be narrowly scoped to measurement correctness and
raw evidence retention, not a new suite or new firewall functionality.

1. **JSON serialization:** `phase1_fw_stats` embeds unescaped JSON in a quoted
   string (`benchmark_gen.sh:958-983`). Several saved reports are invalid JSON.
   Use a real serializer and nested objects; validate every generated result.
2. **HTTP P50:** the awk expression at line 504 computes its target using FNR=1,
   yielding no median and then 0.00 ms. Recompute from raw samples when available;
   otherwise mark historical P50 invalid.
3. **HTTP success:** baseline checks time text, not HTTP status/exit success.
   Preserve both status and exit code. Avoid curl's printed time plus fallback
   text creating a malformed sample on failure.
4. **Percentiles:** define one convention, such as nearest rank
   `sorted[ceil(p*n)-1]`, across all arms. Existing P95/P99 use
   `int(p*n)+1` as a one-based rank; it differs at some sample counts.
5. **CPU softirq:** `$(NF-2)` selects `%guest_nice` for the conventional mpstat
   header, not `%soft`. Parse by header names under a fixed locale; retain raw
   output. Historical all-zero softirq values are not verified softirq results.
6. **Failures:** stop converting missing tools, command errors, invalid JSON and
   failed workloads into apparent numeric zeros or success. Save exits/stderr
   and mark invalid samples.
7. **XDP mode:** `xdp_mode: native_driver` is hard-coded at line 965. Obtain the
   live mode/interface/program IDs; generic runs must say generic/SKB.
8. **Load overlap:** SYN pings run before HTTP; requests may occur after the
   flood stops. UDP requests precede ping. Timestamp everything and label only
   samples inside actual load intervals “during attack.”
9. **PPS:** aggregate firewall counts include legitimate/background traffic and
   possibly multiple hook visits. Dividing by the flood timeout is an estimate,
   not a measured attacker rate or maximum firewall capacity. Measure boundary
   deltas and actual intervals; count drops and offered traffic separately.
10. **Recovery:** delays 0,1,2,3,5 each sleep only 1 s after the first probe.
    The last label is not a scheduled 5 s offset; requests add delay. Schedule
    by monotonic deadlines and record actual offsets. Define recovery instead
    of concluding it from one post-load request.
11. **Memory:** 160 bytes/connection and 65,536*160 are hard-coded, not measured.
    Current `flow_key` is 52 bytes and `flow_entry` 64 bytes before map overhead.
    Dual-direction storage differs by engine, and max entries is not max logical
    connections. Read active map metadata and account for caches separately.
12. **Payload/MTU:** UDP 1500-byte payload exceeds a 1500-byte IPv4 MTU once
    headers are included. Preserve fragmentation/loss evidence; do not claim
    discrete 1500-byte Ethernet semantics from disabling offloads alone.
13. **Tuning:** the generator changes host/container offloads, queues and RPS,
    suppresses errors and does not restore them. Capture successful settings
    before/after, hold them identical across arms, then restore owned changes.
14. **Provenance:** save full iperf JSON, ping output, HTTP samples, mpstat logs,
    command transcript, parameters, attachment inventories and active policy.
    The current generator discards several temporary raw records.
15. **Legacy binary:** generator uses `build/fw-ctl`; current builds use profile
    directories. Confirm the binary matches the live maps/object and do not
    silently substitute a stale legacy binary.

## 7. Kernel timing: exactly what must be explained

Current implementation reference:
`src/kernel/main.bpf.c`, `src/kernel/core/timing.bpf.h`,
`src/kernel/core/conntrack.bpf.h`, `src/kernel/core/helpers.bpf.h`,
`src/kernel/core/rules.bpf.h`, and `src/userspace/core/perf_mgr.c`.

- `bpf_ktime_get_ns()` provides elapsed monotonic kernel time, not application
  RTT and not exclusively CPU cycles. Timestamp/helper and profiling overhead
  affect the instrumented result.
- Extraction starts before Ethernet parsing and records after successful L4
  parsing; malformed/early non-IP paths do not all get extraction samples.
- Hash timing wraps the hash function; engine lookup/update/delete wrappers
  measure helper intervals; rule timing wraps the rule evaluator.
- `lookup_total` accumulates selected lookup/rule intervals for a packet.
  `update_total` accumulates instrumented map mutations, stats and event work.
  In-place state writes are not completely represented by map-helper timing.
- Stats timing encloses consolidated counter updates. Ringbuffer timing occurs
  only on selected emitted events when observability is enabled.
- Pipeline timing wraps `process_packet_impl`, after context initialization.
  It excludes caller context setup, TC skb preparation, the final hook return,
  Linux routing/netfilter/queues, container scheduling and application work.
  It includes executed internal instrumentation; its last metric update occurs
  after the end timestamp.
- Pipeline/total samples include invocations reaching this wrapper, even some
  early returns that do not increment `STAT_TOTAL_PACKETS`. Operation counts
  are therefore not uniformly one per packet. Shared maps can aggregate XDP
  and TC hook invocations; identify per-wire-packet multiplicity.
- Current per-CPU reducer uses `sum(total_time_ns)/sum(count)` for average;
  minimum is the minimum recorded value across nonempty CPUs, maximum likewise.
  Reads during traffic are not an atomic global snapshot. Stop the isolated
  workload before the final read; reset only owned metrics.
- Total pipeline is an independently timed interval, **not the sum of stage
  averages or minima**. Different stages have different populations and may
  overlap. Report operation-conditioned and packet-weighted values distinctly.

Historical `benchmark_results/json/2026-10-04/fastcache_timing.json` reports:
73,589 pipeline samples, average 510.56 ns, minimum 302 ns, maximum 43,778 ns;
73,225 UDP, 314 TCP and 50 ICMP packets; 99.63% cache hit ratio. It is heavily
UDP/cache-hit weighted, not a general all-packet latency bound.

`1e9 / 510.56 = approximately 1.96 million invocations/s` is a **derived idealized
single-core capacity estimate**, not measured packet throughput or delivered
Mbps. It excludes the rest of the packet path and contention, and depends on
the sample mix and hook multiplicity. Minimum timing is not sustained capacity.

Historical stats timing has 147,178 samples, twice the pipeline count, while
the current consolidated stats code differs. The original instrumented build
and run commands must be recovered before asserting identical timing boundaries.
Timing files lack enough build/attachment provenance to certify their results
as measurements of today's generic deployment.

## 8. Controlled nftables comparison still needed

No measured nftables baseline was identified in the saved local results.
`noramal_test_report` appears to be an eBPF-off run (zero BPF memory, N/A state),
not proof of nftables policy enforcement. Published comparison tables without
raw equivalent-policy runs are not sufficient evidence.

### Required comparison arms

1. Existing-host/eBPF-off reference, explicitly labelled with remaining host
   netfilter configuration; not called “no firewall” if host rules remain.
2. Generic XDP-only, agreed engine/policy/placement.
3. Generic Hybrid, same engine/policy/placement plus documented TC egress.
4. nftables stateful lab policy, eBPF detached for this arm.

For a minimal first comparison, agree which representative single-stream,
multi-stream, HTTP, ICMP and SYN/UDP-load cases are necessary. Reuse section 5
traffic exactly; do not automatically rerun all historical experiments.

### Controls and safe changes

- Use the same host/containers/routes/MTUs/tools/CPU allocation and verified
  offload/RPS/queue settings for each arm. No unrelated retuning between arms.
- Create only a uniquely named lab-scoped nftables table/ruleset matching the
  chosen traffic and interfaces. Check it before applying. Do not flush the
  system ruleset or remove firewalld/Docker/Tailscale rules.
- Keep unrelated netfilter hooks fixed across arms and describe their cost.
  A chain accepting a packet does not override a DROP in another base chain;
  verify actual reachability and policy verdicts rather than assuming it does.
- nftables `ct state established,related` is not exactly this firewall's state
  machine. Define equivalent policy-level behavior and disclose engine/state
  differences, default TCP tracking sysctls, helpers and timeout differences.
- Do not compare raw-prerouting stateless drops to a stateful forward-chain
  baseline without identifying that as a different experiment.
- Separate cold-state and established-flow measurements. Clear only owned BPF
  maps or narrowly scoped lab netfilter state when agreed; never host-wide
  conntrack. Record the reset and warm-up procedure.
- Retain actual achieved offered PPS. `--flood` is unpaced and generator CPU
  can change the offered rate. If rates differ materially, the CPU comparison
  is not controlled; report it as unmatched rather than “CPU savings.”
- Preserve raw per-core CPU; the host includes generator/server container CPU.
  Report whole-host activity separately from datapath attribution. CPU savings
  require matched offered traffic and matching drop/allow semantics.
- Stop only processes started for the comparison; remove only its table and
  owned attachments, restore owned tuning/config changes, and preserve a final
  inventory. Prepare cleanup before any temporary deployment.

**Pending authorization:** starting the firewall, attachment-selector edits,
temporary lab policy installation, service startup, load generation and tuning.
The user's choice of generic XDP does not imply consent to all these changes.

## 9. Documentation/claim corrections required

| Existing statement | Required correction/evidence |
|---|---|
| Native XDP / pre-skb drop / zero skb overhead | Replace with generic/SKB for this scope; skb already exists; no native-allocation saving claim |
| Exact bridge/veth hook diagram | Show only observed interfaces/program IDs; distinguish recommended deployment from runtime; today no firewall hooks exist |
| Trace script proves live traversal | Its final narrative is conditional boilerplate, not a packet trace; fix no-hook behavior and validate every claimed interface/hook |
| TC qdisc detection from `ip -d link` | Use `tc qdisc show` plus separate ingress/egress filter inventories; do not label all BPF filters by assumed entrypoint |
| Line-rate / line-rate headroom | Remove unless a defined link rate/frame size, delivered traffic and sustained loss bound are measured; software veth has no demonstrated fixed 1-Gbps line rate |
| Sub-microsecond processing | Limit to the saved instrumented average for its traffic/build; not every packet, end-to-end latency, or today's generic run |
| 1.96 Mpps peak throughput | Label reciprocal-time estimate, not measured maximum PPS |
| Zero measurable overhead | Requires matched repeated runs and uncertainty; otherwise report observed deltas without claiming zero |
| CPU reduction / up to 90% saving | Remove unsupported percentages; generic XDP lacks the stated pre-allocation mechanism; controlled CPU results still required |
| Successful SYN mitigation | Saved FastCache full report has zero SYN drops and 65,501 state entries; describe allowed SYN-load behavior, not rejected attacks |
| Blocked UDP 9999 | Requires actual historical/current DROP-policy evidence; current YAML allows it |
| Full versus XDP-only | `_full_report` filenames alone do not establish attachment mode; generator FULL means sample-duration mode, not Hybrid mode |
| Recovery in 5 s / immediate stabilization | Fix actual time offsets and define recovery; old labels do not establish a recovery bound |
| nftables parity/superiority figures | Mark unvalidated until equivalent-policy raw runs are available |

Primary documentation to correct after agreeing findings:
`docs/PACKET_PATH_VALIDATION.md`, `docs/05_TESTING_AND_VALIDATION.md`,
`docs/02_EBPF_DATAPLANE.md`, `docs/COMBINED_DOCUMENTATION.md`, and corresponding
sections of `Firewall_Documentation.html`. Preserve the original report rather
than rewriting it wholesale. Keep this requirements plan as the audit addendum.

`scripts/trace_packet_path.sh` needs narrow correctness changes: no invented
bridge hook when nothing is attached, per-interface program-ID matching,
reliable TC qdisc/filter queries, and no “line-rate”/“zero skb overhead” assertion
from detecting an attachment mode. It must distinguish inventory from actual
flow tracing. These changes are proposed, not made in this audit.

## 10. Evidence package and completion criteria

Each new run needs a unique run ID and directory containing:

- UTC timestamps; repository commit and dirty diff; object/control binary and
  script SHA-256 hashes; explicit engine/timing/logging/observability flags.
- CLI/environment parameters, full commands, exits/stderr, software versions.
- Pre/post topology, active policy, attachments, maps, offload/RPS/queue records.
- Raw workload outputs, per-request latency CSV, raw CPU logs, state dumps,
  functional PCAPs and timing counters. Separate functional capture from timing.
- Analysis code/version, validated results, exclusions/failures, repetition
  statistics, comparable-conditions checklist and cleanup inventory.
- Claim-to-evidence table: claim, exact file/key/sample population/unit,
  measured versus derived versus inferred, limitations, supported wording.

Preserve existing ignored `benchmark_results/` files; copy only relevant
artifacts into `docs/validation/evidence/` with an origin/hash manifest when
publishing the audit. Do not repair historical evidence in place.

Completion means: generic attachments verified; forward/return flow and every
hook accounted for; methodology documented; invalid metrics excluded or
recomputed from raw data; numerical claims linked to evidence; nftables
comparison measured or explicitly left pending with no comparative conclusion;
and temporary changes restored. Missing historical raw samples must stay
documented as missing, not reconstructed as invented measurements.
