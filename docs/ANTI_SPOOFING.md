# Per-interface source validation (anti-spoofing)

Anti-spoofing checks the packet's claimed source address against explicit prefixes
for its ingress interface. It does not authenticate a sender or detect spoofing
within an allowed subnet. It is not automatic reverse-path filtering.

## Enable deliberately

Build support defaults to `ANTI_SPOOF=1`, but runtime enforcement defaults to
**disabled**. Configure YOUR actual topology in `config/anti_spoof.conf` first:

```text
# interface action source-CIDR
lan0 allow 192.168.1.0/24
lan0 allow fd00:1::/64
wan0 allow 0.0.0.0/0
wan0 deny 192.168.1.0/24
wan0 allow ::/0
wan0 deny fd00:1::/64
```

Then set in `config/firewall.yaml`:

```yaml
anti_spoof:
  enabled: true
  path: config/anti_spoof.conf
```

These are examples, not a deployable policy for the container lab. Interface
names must appear in the firewall's attached-interface list. A nonempty valid
policy is required when enabled. Unmentioned interfaces remain outside this
check; on interfaces appearing in the policy, **unmatched sources are dropped**,
including an address family you forgot to configure.

The most-specific prefix wins; duplicate prefixes (including conflicting
allow/deny duplicates) are rejected. `/0` permits defining default behavior for
one address family on one interface. Host bits are normalized. A source allow
only continues processing; it does not bypass normal firewall policy.

Account for routed subnets, tunnels/VPNs, NAT placement, DHCP's `0.0.0.0` source,
and IPv6 link-local/Neighbor Discovery sources. IPv6 Duplicate Address Detection
may use `::`. No blanket exceptions are inserted: explicitly allow necessary
source prefixes. ARP/non-IP traffic is unaffected. Wrong prefixes can disconnect
legitimate clients, so validate from a local console before rollout.

Policy content and settings require restart. SIGHUP does not reload this policy;
changes to anti-spoof configuration on SIGHUP are rejected.

## Fast path and observability

After successful IPv4/IPv6 parsing, ingress performs an interface hash lookup
and, for protected interfaces, a longest-prefix trie lookup. No 128-rule loop is
used. This runs **before rate limiting, conntrack and flow-cache shortcuts**,
so existing connections cannot bypass source validation. TC egress is exempt.
The trie key includes exact interface and address-family fields followed by the
source prefix; prefixes cannot leak across interfaces or address families.

Policy is parsed/resolved before map writes, read back, and initialized before
any hooks attach. Invalid/empty policy or map failures prevent attachment.
Capacity: 1,024 prefixes, up to 16 protected ingress interfaces.

`fw-ctl stats show --json` exposes `anti_spoof_drops`; normal total/drop counters
also include rejected packets. These drops do not emit individual ring-buffer
events, avoiding flood logging overhead. `OBSERVABILITY=none` removes counters.
Performance must still be benchmarked on target hardware.

## Compile out entirely

```sh
make -j4 ANTI_SPOOF=0
make -j4 ANTI_SPOOF=0 RATE_LIMIT=0
```

`make select` offers both feature switches. Disabled anti-spoof builds append
`-a0` to the profile directory (after `-r0` if rate limiting is also omitted).
Checks, maps, policy manager/config fields and feature counters are excluded;
runtime anti-spoof settings are ignored. Use the matching profile's `fw-ctl`.

## Tests

```sh
make test-anti-spoof
make test-ipv6
sudo make test-ipv6-kernel
```

Parser tests cover IPv4/IPv6, normalization, `/0`, malformed/empty input and
duplicates. Kernel test-runs cover prefix allow/deny, more-specific overrides,
established-cache enforcement, family separation, TC ingress/egress and disabled
scope behavior. Tests load programs but do not attach live interface hooks.
