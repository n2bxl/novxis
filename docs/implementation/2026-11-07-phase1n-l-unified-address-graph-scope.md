# Phase 1N-L: Unified Address Evidence Graph, sprint scope

- **Date:** 2026-11-07
- **Status:** Stage 1 merged and accepted (849 M5 tests); Stage 2 merged and validated with 876 passing M5 tests plus en5 JSON inspection; Stage 3 2D view implemented on a feature branch, M5 and Safari acceptance pending.
- **Starting baseline:** 794 passing M5 Python tests after Phase 1N-K Stage 3
- **Target:** one read-only, typed IPv4/IPv6/MAC evidence graph without inferred devices

## Why now

The local 2D debugger already presents ARP sender claims and separate
NDP NS-source/NA-target option-backed observations. The same interface
may show one MAC asserted for IPv4 and several IPv6 addresses.
Keeping those protocol address nodes separate supports inspectable
provenance; sharing a scoped hardware node makes corroborating
address claims visually understandable.

The goal is *not* to construct a complete subnet or physical topology.
A shared IP/MAC pair, default gateway address or DNS service name
cannot on its own prove a physical host, cable, route or active service.

## In scope

### A. Pure unified graph adapter

- Consume **existing** ARP sender evidence and NDP address claims.
  No changes to packet decoding, NDP/ARP source-of-truth state, or
  capture privileges.
- Project stable, deterministic typed IDs keyed by capture/session
  context and interface, address family, normalized address or MAC.
  The current live session supports one interface; the schema
  should not make future cross-sensor collisions unavoidable.
- Separate IPv4 and IPv6 protocol-address nodes; emit one
  qualified hardware-address evidence node for each identical
  MAC within the permitted source scope.
- Emit typed `arp_sender`, `ndp_ns_source_slla`,
  and `ndp_na_target_tlla` edges, each with source kind,
  observation counts and first/last capture times, plus evidence
  references when already available.
- Preserve simultaneous contrary MAC assertions for one IPv6
  address and independent same-MAC assertions across interfaces.
  Omit no claim solely to produce a cleaner drawing.

### B. Reference UI

- Add a **Unified addresses** mode or tab **alongside** the
  existing ARP-only map, not as an in-place replacement.
- Keep pan/zoom, manual arrangement where applicable, node and
  edge selection, and a provenance Inspector explaining the
  exact evidence that justified each link.
- Preserve the NDP unlinked/DAD read-only view and all existing
  Services, Subnet, Host and Evidence functionality.
- Do not trigger extra capture activity, browser network requests,
  probes, or router lookups when switching views.

### C. Tests and live acceptance

- Synthetic fixture: IPv4 and IPv6 addresses converge on one
  interface-scoped MAC evidence node with *distinct typed edges*.
- Same MAC on two interfaces or independently scoped capture
  sessions stays separate.
- Competing NDP LLAs for one IPv6 stay visible as independent
  edges, not a resolved identity.
- NA-without-TLLA, DAD and malformed/unusable link-layer options
  create **no** address-to-MAC edge.
- Deterministic ordering/IDs and reproducible observed metadata;
  no invented TTL, liveness, device name or subnet membership.
- Existing ARP canvas behavior and the entire M5 test suite remain
  clean; most recently reported baseline **794 tests**.
- Optional manual Safari check on authorized `en0` and `en5`
  combined passive captures, with only sanitized validation
  observations committed to the repository.

## Explicitly out of scope

- DNS-SD nodes, PTR/SRV/A/AAAA graph edges or service ownership.
  Existing service inspection shortcuts remain unchanged.
- Default gateway or router as graph center, inferred physical
  topology, LLDP/CDP, switch port/AP attachment and subnet grouping.
- Active discovery (future "clear the fog"), agent deployment,
  endpoint configuration access or remote `ipconfig /all`.
- Automatic assignment of "device" identities, OS discovery
  or confidence scores that pretend certainty.
- UI compact cards, human-readable timestamp overhaul, 3D
  cyberspace implementation or nonlocal web hosting.

## Work order and handoff

1. Build and unit-test pure typed graph projection from ARP/NDP.
2. Add graph adapter and regression coverage without modifying the
   existing ARP-only graph API contract.
3. Add the separate read-only unified mode with edge inspection.
4. Validate focused and full M5 pytest plus Safari workflow.
5. Document observed behavior, open a PR for owner squash-merge.

Do not treat a proposed milestone as already merged or verified.
Design decision: [ADR 0002](../architecture/0002-evidence-first-address-relationships.md).
Historical milestone notes: [archived README](../archive/README-milestone-history-through-2026-11-07.md).
