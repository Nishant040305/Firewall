# Dual-stack firewall

IPv6 is supported by `FastCache`, `Statefull`, `SHARDED_DUAL_MAP`,
`fastcache_time`, `statefull_time`, `dual_map_time`, and
`feat/network-visibility`. Each branch retains its original map architecture
and, where applicable, component timing metrics.

## Deployment

**Stop the old daemon, detach its programs and remove its old pinned maps using
the normal cleanup procedure before restarting.** Flow keys, rules and events
have a new ABI; old pinned maps must not be reused. Build and deploy matching
kernel and userspace binaries from the same branch. Existing connections reset.
The larger family-aware flow keys also increase map/cache memory usage.

```bash
make
sudo ./build/fw-ctl rule add --proto tcp --dst fd10:10:2::10/128 --dport 80 --action allow
sudo ./build/fw-ctl rule add --proto tcp --family ipv6 --src fd10:10:1::/64 --dport 5201
sudo ./build/fw-ctl rule add --proto icmpv6 --family ipv6 --action allow
```

CLI and YAML accept IPv4 and IPv6 addresses/CIDRs. Address filters infer the
family; mixed source/destination families and invalid addresses/prefixes are
rejected. `family: ipv4`, `family: ipv6`, or `--family` restrict port-only rules.
Rules without an address or family restriction apply to both families; `icmp`
means protocol 1, while `icmpv6` means protocol 58. IPv4 `/0` and IPv6 `/0`
remain family-specific. Source and destination port ranges are validated.

`scripts/setup_env.sh` upgrades existing lab bridges to dual-stack ULA networks:

| Network | Prefix | Hosts |
| --- | --- | --- |
| Untrusted | `fd10:10:1::/64` | attacker `::10`, client `::20` |
| Protected | `fd10:10:2::/64` | webserver `::10` |
| Management | `fd10:10:99::/64` | admin `::10` |

IPv6 routing is enabled, IPv6 NAT is disabled, and DHCPv6 is stateful.
Run setup only when lab/network reconfiguration is intended. Clients must
support DHCPv6; check assigned addresses after setup. The default policy adds
IPv6 HTTP/iperf3 and explicit ICMPv6 rules. Family-neutral DNS/SSH rules apply
to both families. No host network changes are required for packet unit tests.

## Packet handling and limits

- TCP/UDP use the branch's existing state engine, including reverse flows and
  cache entries. Full 128-bit addresses and family are compared; IPv4 cannot
  reuse IPv6 state even when ports match.
- IPv6 hop-by-hop, destination, routing and AH headers are length-checked in
  a bounded walk (up to five extensions followed by a transport header).
  Hop-by-hop is accepted only directly after the IPv6 base header.
- IPv4 and IPv6 fragments are dropped, including IPv6 atomic fragments.
  ESP, jumbograms, truncated headers and excessive extension chains are also
  dropped. There is no reassembly or IPsec decryption.
- TCP header length, UDP length and IP-declared packet boundaries are validated.
  IPv6 UDP zero checksums are rejected. Other checksums are validated by the
  receiving host stack, not by this firewall.
- Neighbor Solicitation/Advertisement and Router Solicitation/Advertisement
  can pass without a rule only with hop-limit 255, code zero and sufficient
  fixed message length. Router Advertisements must have link-local sources.
  This is basic ND validation, **not RA Guard** or complete ND option validation.
  Redirects are not exempt.
- Only echo messages enter ICMPv6 connection tracking. Other ICMPv6 messages,
  including Packet Too Big, are evaluated against policy on every packet, so
  an echo session cannot authorize unrelated control traffic. The default
  ICMPv6 rule permits errors for path MTU discovery; stricter deployments must
  provide an appropriate explicit policy. No RELATED error-payload tracking.
- Existing ICMP tracking groups echo traffic by endpoint pair rather than echo
  identifier. Existing TCP state semantics and lazy traffic counters are retained.
- Ethernet is untagged: VLAN encapsulation is not parsed by the current
  dataplane. Deploy on untagged interfaces or enforce tagged traffic elsewhere.

## Validation

```bash
make test-ipv6                 # Unprivileged address/CIDR/CLI regression tests
sudo make test-ipv6-kernel     # Real verifier + synthetic XDP/TC packet tests
make test-logging              # Visibility branch only
```

Kernel tests load programs without attaching them to live interfaces, use
`BPF_PROG_TEST_RUN`, and automatically release their maps/programs. They cover
IPv6 TCP handshake/cache, UDP return traffic, echo, CIDRs, default drops,
family isolation, extension parsing, malformed traffic, ND and IPv4 regressions
in normal, minimal-observability and zero-observability builds.

For live lab validation after intentional setup/attachment:

```bash
incus exec client -- ping -6 -c 3 fd10:10:2::10
incus exec client -- curl -6 --noproxy '*' --max-time 5 'http://[fd10:10:2::10]/'
incus exec client -- curl -6 --noproxy '*' --max-time 3 'http://[fd10:10:2::10]:8080/'
incus exec client -- iperf3 -6 -c fd10:10:2::10
```

The blocked-port curl must time out. Start the IPv6-capable server first.
On timing branches, extraction timing now includes the IPv6 extension walk,
and hash/key generation includes full IPv6 addresses. Use the existing timing
CLI and benchmark tooling with matching rebuilt headers; do not compare
instrumented results directly against non-instrumented throughput.
