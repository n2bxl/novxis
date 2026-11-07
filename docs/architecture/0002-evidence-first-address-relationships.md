# ADR 0002: Evidence-first IPv4, IPv6, and hardware address relationships

- **Date:** 2026-11-07
- **Status:** Accepted modeling direction; Phase 1N-L implementation pending
- **Applies to:** Typed evidence projection, permanent 2D debugger, future 3D renderer

## Context

ARP and ICMPv6 NDP are independently implemented and live-visible.
NOVXIS currently keeps IPv4 ARP address nodes in one graph and
IPv6 NDP observations in a separate sidebar. DNS-SD AAAA-to-NDP
navigation is an evidence cross-reference, not an automatic
host/device association. The latest reported M5 run passed 794 tests.

A network diagram with a central gateway and addresses grouped under
devices would be attractive, but it would overstate what a single
capture interface knows. DHCP-advertised routers/DNS, observed DNS
requests, MAC claims, and an OS-selected route are different evidence
sources. None may silently supersede the others.

## Decision

1. **Separate address nodes:** each IPv4 or IPv6 protocol address has a
   typed node, even when different addresses are associated with one
   link-layer address. Node keys must include observation/capture scope,
   address family, and canonical address.
2. **Shared scoped hardware nodes:** observations involving the same
   normalized MAC on the same capture interface/scope can converge
   on one hardware-address evidence node. Do **not** fuse across
   independent capture scopes merely because MAC bytes match.
3. **Typed evidence edges:**
   - ARP IPv4 sender → reported sender hardware address.
   - NS IPv6 **source** → Source Link-Layer Address option.
   - NA IPv6 **target** → Target Link-Layer Address option.
   Each edge retains protocol, kind, interface/scope, first/last
   captured time and observation count, with references to the
   underlying recorded observations when available. Multiple
   protocols can support independently typed edges; rendering
   may group them visually but never discard provenance.
4. **Unlinked observations stay unlinked:** DAD tentative targets,
   NA without TLLA, NS without usable SLLA, invalid/ambiguous
   options, and targets seen only in DNS-SD do not produce
   fabricated hardware association edges.
5. **No identity or topology upgrade:** a hardware node denotes an
   *address claim endpoint*, not a physical device. A shared MAC
   is corroborating evidence, not proof of one host. An ARP/NDP
   line is not a cable or direct L2 adjacency.
6. **Gateway is context/role evidence, not the root of the graph.**
   Locally reported default-route information, packet advertisements
   and eventual LLDP capabilities remain separate typed evidence.
   LLDP capability alone cannot identify the OS-selected gateway.
7. **Time and provider boundaries:** retain capture timestamps,
   do not assign an invented NDP TTL, and do not conflate
   passive packets with locally reported OS configuration.
   Future active discovery is explicitly initiated and logged
   as *solicited* evidence, not silently treated as passive.

## Consequences

- The first implementation is a **pure, deterministic, renderer-neutral**
  projection consuming existing bounded ARP/NDP state. No protocol
  decoder, capture privilege or existing state machine is modified.
- The browser offers a **Unified addresses** view alongside the
  existing ARP-focused debugger; selection of an edge reveals its
  typed source and original observation metadata.
- Conflicting claims and identical MACs across capture interfaces
  remain distinguishable. Visual layout coordinates do not form IDs.
- DNS-SD service-name/record graph branches, physical topology,
  LLDP, router role rendering, active probes and collapsible
  hardware cards remain deferred to separate milestones.

## Acceptance invariant

For a fixed synthetic observation set, interface/capture scope and
snapshot time, the semantic output is deterministic. Every emitted
edge must map to a valid ARP sender or option-backed NS/NA observation.
No missing-TLLA NA or tentative DAD may create a connection. Rendering
and node rearrangement do not change the evidence model.

See [Phase 1N-L scope](../implementation/2026-11-07-phase1n-l-unified-address-graph-scope.md)
and [ADR 0001](0001-permanent-2d-reference-and-shared-graph.md).
