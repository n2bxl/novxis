# Phase 1N-B: First browser-based NOVXIS 2D evidence preview

Date: 2026-11-02
Status: M5 Safari interaction acceptance and focused/full Python regression tests passed on 2026-11-02; ready for review.
Base: Phase 1N-A squash-merged as commit 8118fa8 (#32).

## Purpose

Put existing observed ARP sender associations on an interactive 2D canvas.
This is a deliberately small **offline replay** spike, not a final UX,
visual identity, application framework commitment or full network topology.

The source of truth remains the existing evidence pipeline:

    PCAP -> ARPStatePipeline -> NetworkState.arp_bindings
         -> project_arp_address_map -> typed graph JSON
         -> localhost-only HTTP -> SVG canvas and evidence inspector

The server binds only to 127.0.0.1. The graph API serves typed address
evidence, never raw packet bytes. There is no active scan or background
network capture, and changing the visual layout cannot change the
underlying graph. Input captures are processed once at server startup.

## Initial capabilities

- Offline replay defaults to the public, sanitized Phase 0 PCAP.
- Two-column representation of protocol and hardware address nodes.
- Directed observed ARP sender-claim associations.
- Click or keyboard-select any address node for evidence details.
- Pointer pan and wheel/button zoom; Reset View.
- First/last timestamps in Unix capture-clock seconds and observation
  counts are retained as strings, rather than pretending a replay
  represents a current live network state.
- Minimal dark neutral styling is provisional and intentionally easy
  to replace.
- The initial prototype uses packaged static HTML/CSS/JS and Python's
  standard-library HTTP server, with no frontend dependencies. A
  future React/TypeScript interface can consume the same JSON schema
  without changing the network decoder or state layer.

## Run on the M5 Mac

    git fetch origin
    git switch --track origin/ai/phase1n-web-map-spike-2026-11-02
    python -m pip install -e ".[dev]"
    python -m pytest tests/web -q
    python -m pytest
    python -m novxis.cli.web_preview

Open http://127.0.0.1:8765/ in Safari. Stop with Ctrl+C.

To replay a *private local* capture without committing it:

    python -m novxis.cli.web_preview --pcap "/path/to/private.pcapng" --interface-label en5

For alternate local ports use --port 8766. The development server
intentionally does not support a non-loopback host binding.

## Acceptance targets (validated on M5)

- HTML/JS/CSS load locally without CDN or npm build.
- 8 sanitized frames result in 6 claims and 12 typed address nodes.
- Click an IP node and inspect its ARP claim to a hardware address.
- Canvas pan, zoom, reset, keyboard selection and inspector.
- Focused tests and full Python regression suite pass.
- No false inferred host/device identity, cable, liveness or subnet.
- No browsing external URLs; local-only read-only API.

## Safari canvas drag-selection regression

During first on-screen validation in Safari, panning the SVG map could
also produce native text-selection highlighting across the map's labels.
The canvas now applies WebKit-compatible selection suppression to the SVG
and its descendants, cancels the native selection/drag defaults, and calls
preventDefault() on the canvas pointerdown gesture. A short node click
remains distinct from dragging that node. Inspector content is intentionally selectable.

A static regression test covers the scoped CSS and pointerdown guard.
The later M5 Safari review confirmed the original unintended-selection issue
was resolved alongside the wheel and pan interactions.

## Whole-canvas zoom and node-origin pan fix (2026-11-02)

The first browser preview exposed two related pointer-hit-testing behaviors:

1. Safari wheel zoom responded over painted address nodes, but did not
   respond reliably while hovering blank regions of the SVG canvas.
2. Pointer-down on an address node was explicitly excluded from starting
   a pan, so only blank-canvas drags moved the graph.

The wheel listener now attaches to the full `.canvas-wrap` rather than
the SVG element. It continues to prevent the page scroll and anchors
zoom to the pointer's position in SVG coordinates.

The shared pan gesture now starts over either background or node. A
5-SVG-unit movement threshold distinguishes a drag from a click:
stationary node pointer-up selects the address; moving beyond the
threshold pans instead and does not change selection. Node keyboard
Enter/Space selection remains supported. The inspector remains
selectable for copying evidence, and the panning cursor applies when
starting over a node. Pointer cancellation never selects a node.

Static regression tests cover both code paths. A JavaScript smoke
check exercised blank-canvas wheel and node-origin pan handlers in
a mocked environment and passed. These are not substitutes for a
real Safari acceptance test on the M5. Confirm all four cases:
wheel over empty background, wheel over nodes, drag from empty
background, and drag starting on a node. Confirm a simple click still
updates the inspector, that dragging does not select a new node, and
that inspector text remains copyable.

## M5 Safari interaction acceptance (2026-11-02)

The user confirmed the previously reported browser interaction issues
are resolved in the latest preview and provided a new ~40-second screen
recording. Reviewed sampled frames showing the live 2D map at different
pan/zoom positions and selected protocol/hardware address inspectors.
The user's explicit confirmation covers the original text-selection,
blank-canvas wheel hit-testing and node-origin panning complaints.
No visual redesign is necessary to proceed.

This manual browser UI acceptance is complemented by the focused and full
Python regression test results recorded below.

## Final M5 acceptance: automated tests (2026-11-02)

The user supplied terminal output from the updated Phase 1N-B branch:

- macOS Darwin, Python 3.14.6, pytest 9.1.1, pluggy 1.6.0.
- `python -m pytest tests/web -q`: **14/14 passed in 3.12 seconds**.
- `python -m pytest`: **501/501 passed in 3.41 seconds**.
- No pytest failures or errors in either run.
- The earlier Phase 1N-A merged acceptance was 487 passing tests;
  this iteration adds 14 tests (the reported suite total is 501).
- Browser-based manual interaction validation was separately confirmed;
  the Python suite does not substitute for full cross-browser UI tests.

**Phase 1N-B acceptance complete.** Ready for PR review/squash merge.

## Deferred

No 3D scene, framework adoption, live capture, port scanner, physical
topology inference, mDNS/DNS/ICMP combined graph, authentication for
remote access, websocket updates, native desktop wrapper or visual
theme decisions. Handle these as later independent milestones.
