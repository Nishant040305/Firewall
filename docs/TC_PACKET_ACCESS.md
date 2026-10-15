# TC packet access

At TC ingress/egress, `skb->len` is the complete packet length, while
`skb->data_end - skb->data` is only the directly accessible linear head.
The shared IPv4/IPv6 parsers validate complete IP lengths against `data_end`.
Without linearization, valid packets with fragmented payload can therefore
be reported as malformed and dropped, including outgoing SSH data.

`pkt_ctx_init_skb()` now calls `bpf_skb_pull_data(skb, skb->len)` when the
linear head is shorter than the packet. It reads packet pointers only after
the helper, since the helper can relocate the buffer. Already-linear packets
avoid this explicit pull. Pull failures and truncated Ethernet headers are
dropped and counted as malformed; they are not allowed to bypass policy.
Full linearization can add allocation/copy overhead for large packets.

Run the mocked context regressions with:

```sh
make ENGINE=fastcache LOGGING=1 TIMING=0 OBSERVABILITY=full test-tc-context
```

These tests cover linear packets, fragmented payload, pointer relocation,
both TC directions, helper failure, and short Ethernet frames. They do not
replace kernel verifier or real non-linear/GSO traffic testing.

Before deployment, validate on an isolated interface with the target kernel
and NIC/offload settings. This change does not resolve unknown TCP state on
attachment, ingress-only tracking of outbound connections, or all possible
GSO header representations. Do not assume it makes management-interface
attachment safe; retain independent rollback and console access.
