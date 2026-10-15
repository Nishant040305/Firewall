# IPv6 integration validation — 2026-10-15

## Updated local branches

| Branch | Architecture retained | Packet tests |
| --- | --- | --- |
| `FastCache` | Per-CPU direct-indexed cache + authoritative LRU | 55 × 3 passed |
| `Statefull` | Single LRU state map | 55 × 3 passed |
| `SHARDED_DUAL_MAP` | Established hash + separate half-open LRU | 55 × 3 passed |
| `fastcache_time` | FastCache + component timing | 55 × 3 passed |
| `statefull_time` | Single LRU + component timing | 55 × 3 passed |
| `dual_map_time` | Dual map + component timing | 55 × 3 passed |
| `feat/network-visibility` | FastCache + structured visibility | 55 × 3 passed |

The three builds are normal, minimal observability and zero observability.
Tests use real kernel verification and `BPF_PROG_TEST_RUN` for XDP, TC ingress
and TC egress, without attaching to live network interfaces. Total: **1,155
packet assertions**. Address/CIDR/CLI tests and default YAML rule loading run
for every object. Normal/minimal timing objects also assert that their
component metrics are populated. All userspace, BPF and timing-tool builds pass.

Visibility branch: C logging tests and two Python viewer tests pass, including
IPv6 canonical address output and separate aggregation for addresses differing
only in their final word. `bash -n scripts/setup_env.sh` and `git diff --check`
pass. Detailed local execution logs are in `/tmp/opencode/*-tests.log` and
`/tmp/opencode/*-build.log`; these temporary logs are not committed.

No live Incus provisioning, network attachment or throughput benchmark was run.
The lab setup script is dual-stack ready, but DHCPv6 assignment and live
HTTP/iperf3 performance must be checked during intentional deployment. No
IPv6 throughput improvement claim is made. Temporary verifier pins were removed.

## Improvements included

- Correct IPv4/IPv6 CIDR parsing, family inference and invalid-input rejection.
- CLI destination-port matching now actually sets its required rule flag;
  source-port ranges are implemented and validated too.
- All configured rule slots are evaluated, not only the first 32.
- Shared rule hit/byte increments are atomic.
- IP-declared lengths, TCP data offsets and UDP lengths are checked.
- IPv4 fragments cannot bypass transport inspection by impersonating headers.
- Conntrack listing starts with a null iterator; flushing does not iterate
  using already-deleted keys.
- Userspace headers trigger rebuilds, including timing benchmark binaries;
  synthetic benchmark IPv4 keys include the new family identifier.

## Branch cleanup

Kept the seven requested branches above and `master` as the baseline.
Removed local `optimization` and `TrafficControl`, whose history is already
contained in retained branches. Removed obsolete experimental local `Analysis`
and `BPF_NO_COMMON_LRU` only after preserving them under annotated tags:

- `archive/Analysis-2026-10-15`
- `archive/BPF_NO_COMMON_LRU-2026-10-15`

All four removed branch tips and complete history were also saved in the
verified bundle `.git/obsolete-branches-2026-10-15.bundle`. For example:

```bash
git branch Analysis archive/Analysis-2026-10-15
git bundle verify .git/obsolete-branches-2026-10-15.bundle
```

Remote branches were not deleted or pushed. All implementation commits are
local, and the final checkout is `feat/network-visibility`.

## Deployment warning

Read [IPv6 support](IPV6.md) before restarting: the rule, flow and event ABI
changed, so matching BPF/userspace binaries and fresh maps are mandatory.
Fragment reassembly, ESP, jumbograms, VLAN parsing, full ND validation and
RELATED ICMP error tracking are not implemented. Existing TCP state-machine
semantics and lazy connection counters are deliberately retained.
