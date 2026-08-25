# Firewall Design Document

## 1. Overview

This project implements a high-performance firewall using eBPF/XDP for packet filtering in the kernel and a separate userspace control plane for configuration, policy management, and observability. The design emphasizes early packet handling, a small kernel-side attack surface, and a clean split between fast-path enforcement and slow-path management.

The core idea is simple: the kernel should do the minimum work required to make an allow/deny decision, while userspace owns policy authoring, deployment, testing, and telemetry. That separation keeps the packet path fast and predictable and keeps higher-level logic out of the kernel.

## 2. Design Goals

The firewall is designed around the following goals:

1. Filter traffic as early as possible to reduce overhead and limit exposure to unwanted packets.
2. Keep the kernel program small, deterministic, and easy to verify.
3. Make policy changes manageable from userspace without rebuilding kernel logic.
4. Support a testable architecture that can be exercised in isolated network environments.
5. Provide a structure that can grow from basic packet filtering into richer enforcement and telemetry.

## 3. High-Level Architecture

The repository is intentionally split into three layers:

- Kernel dataplane: eBPF programs under `src/kernel/` perform packet inspection and enforcement.
- Userspace control plane: code under `src/userspace/` loads programs, applies policy, and reports status.
- Shared definitions: headers under `include/` hold common constants, protocol types, and reusable structures.

This layout separates concerns by execution context. The kernel path handles packets at line rate, while userspace can afford more flexibility for parsing configuration, coordinating updates, and producing logs or telemetry.

## 4. Packet Processing Model

The packet path follows a layered decision model:

1. A packet arrives at the network interface.
2. The XDP/eBPF program inspects the frame before the kernel networking stack performs full processing.
3. The program classifies the packet using protocol-aware filters and policy rules.
4. The packet is either passed through, redirected, or dropped depending on the configured rule set.

The main design choice here is to move enforcement as far left as possible in the networking stack. That reduces the amount of work done on traffic that will ultimately be denied and helps the firewall scale under load.

## 5. Kernel Side Responsibilities

The kernel side should remain focused on a narrow set of responsibilities:

- Parse only the packet metadata needed for an enforcement decision.
- Evaluate protocol-specific conditions using small, predictable helpers.
- Apply the policy result immediately.
- Emit lightweight telemetry or counters when necessary, but avoid expensive per-packet work.

The `src/kernel/` tree suggests a modular organization for the dataplane, with separate areas for core logic, protocol handling, and filters. That structure supports incremental growth without turning the fast path into a monolith.

## 6. Userspace Responsibilities

Userspace owns the higher-level firewall lifecycle:

- Load and attach the eBPF programs.
- Read firewall configuration and rule definitions.
- Translate human-readable policy into kernel-friendly structures.
- Coordinate updates safely when rules change.
- Surface status, counters, and diagnostics.

This separation is a deliberate design choice. If policy logic stays in userspace, the kernel program remains simpler and easier to validate. It also becomes easier to extend policy formats over time without destabilizing the dataplane.

## 7. Policy Model

Policy is expected to be expressed as explicit firewall rules rather than embedded directly in code. The repository includes `config/firewall.yaml` and `config/rules.yaml`, which indicates a configuration-driven approach.

The intended policy model is:

- Define network segments and firewall behavior in a declarative form.
- Describe allow, deny, and inspection rules at a protocol-aware level.
- Keep rule ordering and precedence explicit so behavior is predictable.
- Push only the normalized representation required by the kernel into the dataplane.

This approach keeps policy easier to audit. It also allows the firewall to be retargeted to different environments without rewriting the enforcement logic.

## 8. Shared Types And Constants

The `include/` tree is reserved for shared types, constants, and protocol definitions used by both kernel and userspace code. This is important for eBPF projects because both sides must agree on structure layouts, protocol values, and limits.

The design principle here is to keep shared headers stable and minimal:

- Shared definitions should be small enough to compile cleanly into both environments.
- Kernel-visible layouts should avoid unnecessary fields.
- Constants should capture protocol limits, buffer sizes, and decision codes in one place.

This minimizes drift between the control plane and dataplane and reduces the risk of layout mismatches.

## 9. Observability And Telemetry

Firewall systems are only useful if decisions can be explained. The repository includes a `src/userspace/telemetry/` area, which suggests a separate observability path for counters, event reporting, or trace output.

The design preference is to keep observability lightweight in the kernel and richer in userspace:

- Kernel-side counters can capture packet totals, drops, and rule hits.
- Userspace can aggregate, format, and export those signals.
- Logs should explain why a packet was blocked without forcing the kernel to do string processing or expensive formatting.

This maintains fast-path performance while still giving operators enough information to debug policy behavior.

## 10. Test And Deployment Model

The scripts in `scripts/` show that the firewall is meant to be exercised in an isolated lab environment. The setup uses Incus containers representing attacker, client, webserver, and admin roles, with separate virtual networks for untrusted, protected, and management traffic.

That test topology is a strong design choice because it allows the firewall to be validated against realistic traffic flows:

- Untrusted hosts simulate hostile or uncontrolled traffic.
- Protected hosts represent the service being defended.
- A management segment supports administration and inspection.

This makes it possible to verify policy behavior without depending on a production network.

## 11. Design Tradeoffs

The chosen architecture makes a few explicit tradeoffs:

- More logic moves into configuration and userspace, which increases control-plane complexity but reduces kernel risk.
- Packet decisions are fast and simple, but advanced policy evaluation must be normalized before reaching the kernel.
- The system is modular and testable, but requires discipline to keep shared definitions aligned across components.

These tradeoffs are intentional. For a firewall, predictability, observability, and safety are generally more valuable than embedding complex behavior directly in the dataplane.

## 12. Security Considerations

The design tries to minimize the kernel attack surface by keeping the dataplane small and data-driven. Important security principles include:

- Reject traffic as early as possible.
- Parse only what is needed for a decision.
- Avoid unbounded loops or expensive kernel work.
- Treat userspace input as untrusted until validated and normalized.
- Keep rule updates atomic or clearly versioned so partial state does not leak into enforcement.

The firewall should also fail closed where appropriate. If policy cannot be loaded or validated, the safe default is to deny rather than accidentally permit traffic.

## 13. Extensibility

The directory structure is prepared for future growth without changing the core architecture. Likely expansion points include:

- Additional protocol handlers under `src/kernel/protocols/` and `src/userspace/protocols/`.
- More detailed rule engines under `src/userspace/rules/`.
- Richer telemetry and reporting.
- Alternate deployment modes or test topologies.

Because the kernel and userspace paths are already separated, these features can be added incrementally without entangling policy management with packet enforcement.

## 14. Summary

The firewall is designed as a split architecture: eBPF/XDP provides the fast enforcement path, while userspace manages policy, deployment, and observability. This is the right shape for a firewall because it balances performance, safety, and maintainability. The result is a system that is easy to reason about, easy to test in isolated network labs, and flexible enough to evolve as the rule model becomes more sophisticated.
