# Stage 4 closeout: permanent 2D evidence map layout and connector routing

- **Date:** 2026-11-14
- **Status:** Merged and locally accepted on `main`
- **Post-merge regression:** **1,041/1,041 passing** on macOS Python 3.14.6 and pytest 9.1.1, 5.35 seconds
- **Scope:** Presentation-only follow-up to Phase 1N-M's renderer-neutral DNS-SD service evidence graph

## Accepted merge sequence

| Stage | PR | Shipped behavior |
| --- | --- | --- |
| Phase 1N-M Stage 3 | [#61](https://github.com/n2bxl/novxis/pull/61) | Services map, full/wrapped instance names, compact variable-height cards, individually inspectable ARP/NDP/DNS-SD paths |
| Stage 4A | [#62](https://github.com/n2bxl/novxis/pull/62) | Center shorter Hardware/IP/Services columns against the tallest **rendered** column, preserving internal order and drag slots |
| Stage 4B.1 | [#64](https://github.com/n2bxl/novxis/pull/64) | Responsive Services column positions plus a user-controlled horizontal spacing slider |
| Stage 4B.2 | [#65](https://github.com/n2bxl/novxis/pull/65) | Shared endpoint port ordering by opposite card's vertical position, not merely edge ID |

Earlier Phase 1N-M Stages 1–2 projected versioned, scope-qualified service
evidence into `unified_service_graph` via the existing local-only API.
The three map modes remain independently selectable and retain their own
cameras, selections, and arrangements. Stage 4 did **not** change the
capture producer, protocol parser, receiver validation, privileges, wire
evidence or the API contract.

## Presentation contract at closeout

1. **Evidence first.** ARP sender, NDP NS/NA with valid link-layer option,
   and supported DNS-SD PTR → SRV → A/AAAA paths remain separate typed
   relationships. Nodes are observed addresses and advertised instances;
   neither an IP/MAC grouping nor a service path proves physical device
   ownership, topology, port openness or application reachability.
2. **Capture limits remain explicit.** Interface and capture scope delimit
   relationships. Retained expired DNS-SD paths show dashed TTL-expired
   styling and support record inspection. A capped capture is labeled
   **CAP REACHED (incomplete evidence)** rather than presented as a full
   inventory.
3. **Layout is presentation, not evidence.** Hardware and address grouping
   obeys existing evidence-driven ordering; Services is one compact
   variable-height column, sorted by the earliest supporting displayed IP
   rank unless the user manually rearranges it. Vertical centering measures
   rendered card extents, not simply numbers of addresses. No other
   column is reordered to reduce connector crossings.
4. **Horizontal spacing is independent.** Services uses the measured canvas
   width with a 1080 SVG-unit minimum. The **Column spacing** slider adds
   0–3000 horizontal graph units in 100-unit steps (default +600). Hardware
   anchors left; IP sits between hardware and Services. Card heights,
   Y coordinates and evidence order do not change when the slider moves.
5. **Connector routing is independent.** Outgoing port placement sorts by
   destination vertical center; incoming placement sorts by source vertical
   center. Equal positions use stable evidence IDs. Paths keep distinct
   record identities, hit targets, accessible labels, TTL styling and the
   existing cubic Bézier construction. Crossings between different pairs
   can still be unavoidable; no global crossing optimization is claimed.
6. **Camera/interaction remains separate.** Reset view continues to fit
   the *rendered bounds* using the existing uniform fit formula. A very
   tall graph may therefore appear narrow when fully framed. Panning,
   zoom, independent sidebars, manual move/keyboard navigation, and the
   separate ARP-only and Unified layouts are preserved.

## Evidence and acceptance record

- Stage 4A: focused regression, full **1,011** tests, 7/7 Safari checks;
  separately observed tall-IP and tall-Services centering scenarios.
- Stage 4B.1: complete native Cairo dependency verification for optional
  brand-raster tests; full **1,032** then **1,036**-test branch baselines
  (the latter also includes new spacing control contracts), and owner
  Safari inspection of zoom, resize, spacing and evidence paths.
- Stage 4B.2: full **1,041/1,041** tests before and after the PR #64
  squash-merge branch reconciliation; final **1,041/1,041 in 5.35s**
  on updated `main` after PR #65 merged. Safari recordings showed
  clearer parallel/competing DNS-SD paths and no identified visual blocker.
- A finite, authorized Wi-Fi capture observed 34 advertised services,
  69 endpoint paths, 74 nodes and 82 evidence edges, with the capture cap
  explicitly indicating incomplete evidence. This was **one observed
  capture window**, not a stable device inventory or proof of 69 reachable
  services.
- Source-level renderer tests and local Safari reviews are complementary;
  they do **not** constitute a complete automated end-to-end browser
  accessibility audit or benchmark of global path intersections.

## Architecture checkpoint for later 3D work

```text
Authorized capture / replay + separately sourced local OS context
           |
Bounded decoders, normalized observations and scoped state
           |
Typed, renderer-neutral graph projection (nodes, edges, provenance)
           |
          +-----------------------------+
          |                             |
Permanent 2D reference            Future 3D renderer
          |
2D layout (node X/Y, order, grouping)
          |
2D port assignment / connector routing
          |
Camera, hit testing, visual styles and evidence inspector
```

The **node layout**, **connector routing**, and **camera/view interaction**
are distinct presentation responsibilities even though their present code
lives in the browser's `novxis/web/static/app.js`. A later extraction into
reusable, testable helpers can separate these algorithms further without
altering the Python evidence model. A future 3D renderer may choose its
own spatial anchors but must consume the same typed graph and preserve
independently inspectable evidence.

## Deferred (not Stage 4 commitments)

- Fixed, sanitized graph fixtures for reproducible crossing and camera
  comparisons (live traffic varies between tests).
- Quantitative connector congestion metrics, optional path routing/bundling,
  hysteresis for adaptive spacing, and measured performance at scale.
- Multiple capture interfaces, LLDP/CDP topology, and explicitly authorized
  active investigation, each with independent evidence boundaries.
- User device annotations and optional OUI vendor clues
  ([parking-lot issue #66](https://github.com/n2bxl/novxis/issues/66)).
- A complementary 3D Cyberspace renderer. The existing 2D debugger remains
  permanent and does not depend on the 3D engine.

## References

- [Stage 4A layout](2026-11-08-stage4a-column-centering.md)
- [Stage 4B.1 adjustable column spacing](2026-11-08-stage4b1-responsive-horizontal-layout.md)
- [Stage 4B.2 spatial connector ports](2026-11-14-stage4b2-spatial-evidence-ports.md)
- [Services Stage 3 implementation](2026-11-07-phase1n-m-stage3-services-map.md)
- [ADR 0001: permanent 2D and shared renderer-neutral graph](../architecture/0001-permanent-2d-reference-and-shared-graph.md)
- [ADR 0002: evidence-first address relationships](../architecture/0002-evidence-first-address-relationships.md)
