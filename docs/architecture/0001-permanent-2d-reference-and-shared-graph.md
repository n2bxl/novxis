# ADR 0001: Permanent 2D Reference Explorer and Shared Evidence Graph

- **Date:** 2026-11-02
- **Status:** Accepted design direction
- **Applies to:** NOVXIS core, renderer-neutral graph adapters, 2D diagnostic explorer, future 3D cyberspace

## Decision

**The 2D explorer is a permanent network-evidence reference and debugging
interface. A future 3D cyberspace experience is an additional presentation
and interaction layer, not a replacement for 2D or an alternative source of
network truth.**

The current browser implementation is deliberately minimal. Retaining 2D
does not commit us to its current CSS, two-column layout, HTTP adapter,
frontend framework, or packaging technology.

## Context

Phase 1N-A (PR #32) added an immutable, UI-neutral observed ARP address map.
Phase 1N-B (PR #33) added a browser-based localhost preview consuming that
projection. It was squash-merged to main as `c574d43`; M5 acceptance on
2026-11-02 included **14/14 focused web tests**, **501/501 full Python tests**,
and user-confirmed Safari panning, zooming and selection.

As NOVXIS grows, a 3D scene will add camera navigation, spatial occlusion,
animation, depth and selection mechanics. The 2D view supplies a stable,
reproducible tool for distinguishing semantic-model errors from renderer
errors and for inspecting exact observed evidence.

The current web view is **offline ARP sender-association evidence only**,
not a live host-inventory, reconstructed physical wiring diagram, or complete
multiprotocol subnet map.

## Architecture and invariant

```text
capture / PCAP replay / local OS context / authorized discovery
                            |
                protocol evidence and events
                            |
                 bounded, scoped network state
                            |
       typed, versioned, renderer-neutral evidence graph
                  /                          \
        2D reference explorer            3D cyberspace
        (permanent diagnostic)           (future renderer)
```

Renderers consume a shared semantic graph/snapshot contract. They must not
independently interpret packet objects, reverse-engineer console text, or
derive new network facts from visual geometry.

For the same observation scope, snapshot time and evidence inputs:

- **Entity identity:** stable typed IDs/keys correspond to the same
  semantic object in both views. Layout coordinates are never identity.
- **Relationships:** edge kinds and direction remain identical in the
  underlying graph, even when the view intentionally filters or hides them.
- **Provenance and scope:** retain capture source/interface, original
  evidence references, bounded observation context and per-record freshness
  or conflict information where available.
- **Time:** distinguish event/capture-clock semantics from wall-clock time.
  Replay is not evidence that an entity is currently online.
- **Uncertainty:** an ARP sender association is not a cable, a physical
  device, or verified address ownership. An ICMP exchange is not proof
  of direct physical adjacency. DNS/DNS-SD claims are names or
  advertisements, not authenticated host identity.
- **Interaction semantics:** selection and examination are read-only;
  any future active investigation requires explicit, separately scoped
  authorization irrespective of whether it is invoked in 2D or 3D.

Renderers may differ in camera, layout, colors, animation, grouping,
label density and UX. Those differences must never silently mutate shared
graph facts or flatten known ambiguities.

## Permanent responsibilities of the 2D explorer

The 2D map is both a user-facing diagnostic interface and a development
reference for the future 3D scene. Preserve a direct path to:

1. Typed node/edge inspection with original evidence and source scope.
2. Capture-time and freshness context; explicit conflicting or missing facts.
3. Protocol/relationship filters and diagnostic overlays (planned).
4. Deterministic graph arrangement and repeatable fixture/snapshot replay
   for reproducing rendering defects (planned; current layout is basic).
5. Timeline/as-of replay controls with consistent semantics (planned).
6. Comparing expected shared graph facts against what each renderer shows
   to localize any 3D-only rendering failure (planned).

The **current** 2D browser preview implements a subset: offline sanitized
ARP replay, typed address nodes, sender-claim edges, pan, zoom, selection
and evidence inspection. Advanced filters, multiprotocol joining, timeline
and 3D parity checks are not yet implemented.

## Development sequencing

1. Maintain the current working 2D baseline and its tests.
2. Gather local interface, prefix, route and neighbor context to define a
   *reported* subnet boundary without guessing the physical network.
3. Add typed, provenance-preserving ICMP, DNS, DHCP and mDNS relationships.
4. Evolve the 2D view into a useful multiprotocol inspection/debugging tool.
5. Stabilize the shared graph versioning, replay snapshots, selection keys
   and semantic parity tests across independently written renderers.
6. Implement 3D on that same contract, without retiring the 2D explorer.

**Acceptance rule for future 3D:** replay a controlled fixture at a
defined snapshot time. Compare semantic IDs, typed edges, scope, time and
evidence as seen by both renderers. Presentation may differ, but shared
data must not.

## UI and packaging boundaries

The 2D reference may retain practical sidebars, detailed inspector panels
and debugging controls. Future immersive Cyberspace HUD placement, keyboard
navigation and atmospheric design are separate UX concerns; they do not
invalidate the 2D diagnostic layout.

Current deployment is a local web app. A later standalone desktop window
may wrap or reuse web UI code, but desktop packaging is not a prerequisite
for this decision and no specific framework is chosen.

## Consequences

**Benefits:** One source of truth; stable debugging reference; reproducible
fixture checks; independent UI development; lower risk when introducing 3D.

**Costs:** Two view implementations to maintain; graph contract and
versioning discipline; shared semantic tests; explicit handling of
filters, selection and time without allowing presentation to become state.

## Related documents

- [Phase 1N-A ARP observed-address graph](../implementation/2026-11-01-arp-observed-address-map.md)
- [Phase 1N-B 2D browser evidence preview](../implementation/2026-11-02-2d-web-evidence-preview.md)
- [OAIOS companion decision](https://github.com/n2bxl/obsidian-ai-os) (private vault, NOVXIS project folder)

This ADR records a product/architecture commitment, not a claim that
the full 2D debugger or the future 3D renderer has already been built.
