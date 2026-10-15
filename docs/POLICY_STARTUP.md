# Policy initialization before attachment

Daemon startup now loads the BPF object and obtains its map descriptors without
attaching XDP or TC. It then parses a required, nonempty rules file, writes the
policy, and verifies each slot by reading it back from the object's rules map.
Only after policy verification and event/log initialization does it attach the
packet filters. Expected startup order:

```text
Loading BPF program into kernel...
Loaded and verified 1 rule(s) from 'config/rules.yaml'.
Attaching XDP program...
Attaching TC EGRESS program...
```

Missing, empty, unreadable, malformed, or oversized policies prevent attachment.
Unknown keys are rejected rather than silently weakening a rule. The supplied
catch-all policy is supported; an allow-all rule is not required for intentional
allowlist policies. The kernel's unmatched default remains DROP; this does not
implement the `default_policy` field from firewall.yaml.

Reload parses the complete file before touching live rule slots. Invalid files
leave rules unchanged. Valid replacements update slots directly, without first
flushing the map. Update/readback failure attempts to restore the previous
policy and reports any restoration failure. This is **not an atomic swap**:
packets can observe a mixed policy during replacement or restoration. Use a
lab or controlled restart for changes requiring atomic enforcement. Cached
established connections may retain their previous decisions.

Tests:

```sh
make logging test-rules-startup test-ipv6
```

`test-rules-startup` mocks map operations to exercise missing/empty/invalid files,
no modification on parse failure, catch-all readback, and rollback on map update
or verification failure. Kernel validation still requires BPF privileges.

This addresses empty-map attachment and skipped rule loading. It does not prove
the exact cause of the previous VM incident, preserve existing TCP state across
attachment, or make ingress-only tracking of outbound connections complete.
Validate in Incus before attempting management-interface attachment.
