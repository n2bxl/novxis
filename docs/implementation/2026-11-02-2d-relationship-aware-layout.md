# Phase 1N-D: Relationship-aware 2D address layout

Date: 2026-11-02
Status: Feature branch, M5 Safari and focused/full test acceptance pending.
Baseline: Phase 1N-C live ARP accepted at 524/524 tests and merged via PR #35.

## Problem

The original renderer sorted protocol addresses and hardware addresses
independently. The graph's ARP claims were accurate but a protocol address
near the bottom could be associated with a hardware address at the top.
The resulting diagonal lines crossed needlessly, obscuring the evidence
when many addresses became visible.

## Decision and behavior

Keep the **semantic graph completely unchanged**. Improve only the
browser's layout:

1. Retain consistent address ordering for protocol addresses.
2. Order hardware addresses by the average vertical row of the protocol
   addresses that actually have an \`arp_sender\` claim to them.
3. Break ties deterministically by interface, raw address, then stable
   semantic ID. Unknown/unconnected hardware addresses follow the
   connected addresses.
4. Support an explicitly enabled **Rearrange** mode. In this mode the
   operator drags an address to move it to another row **in its column**.
   Rearrangement uses stable semantic IDs and is kept during live graph
   refreshes. New observed nodes are appended to a manually reordered
   column until the operator resets it.
5. Support **Shift+ArrowUp/ArrowDown** on a focused address while
   Rearrange mode is active.
6. An **Auto arrange** button clears both manual column orders and
   recomputes the evidence-based alignment.
7. Normal mode retains the already-validated interactions:
   dragging anywhere on the map (including on a node) pans the camera,
   wheel zooms, and short clicks select address evidence.
8. Selection, pan/zoom, provenance and claim counts are unaffected
   by arranging the view. No rearrangement is saved to the network
   model or shared across sessions.

## Scope and limitations

The first algorithm is a deterministic **two-column barycentric sort**,
not a general force-directed physical network topology solver.
Many-to-one associations may still create angled edges. No layout
algorithm can prove device identity or physical cable placement, and
visual proximity remains presentation-only.

Manual moves are snapped into row slots to avoid accidental overlap.
The arrangement isn't persisted across browser restarts; this is
deliberate for the first local debugger. Rearrangement must remain
explicit to protect the default node-drag-to-pan interaction.

As live ARP observations add new nodes, the automatic arrangement may
change when the underlying edge relationships change. An operator
manually arranging a column gets a stable order for existing nodes
until Auto arrange is requested. Later work can add animated layout
transitions, saved debugger workspaces or algorithms for multiprotocol
graphs without modifying this milestone's network evidence.

## Validation plan on the M5

    git fetch origin
    git switch --track origin/ai/phase1n-relationship-aware-2d-layout-2026-11-02
    python -m pytest tests/web -q
    python -m pytest
    python -m novxis.cli.web_preview

Open http://127.0.0.1:8765/ in Safari and confirm:

- The sanitized ARP graph's connected IP and MAC pairs are more closely
  aligned instead of independently sorted.
- Normal dragging from nodes still pans; zoom and selecting a node work.
- Enabling Rearrange lets a node move to a different vertical row in
  its column and its observed-claim curve follows.
- Auto arrange removes manual changes while retaining evidence and view
  selection.
- Keyboard Shift+Up/Down reorders a focused node in Rearrange mode.
- In live ARP mode, manual order persists during observation refreshes.
- No changed addresses, relation types, timestamps or evidence counts.

A small standalone JavaScript smoke evaluation of the pure layout functions
validated reverse-sorted one-to-one claims, manual movement and reset.
A real Safari interaction test is still required.

## Deferred

Free-form node coordinates, topology-style clustering, animation/springs,
long-term layout persistence, physical device grouping, 3D, protocol
fusion and active discovery are separate future work.
