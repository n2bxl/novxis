# Stage 4B.1: responsive Services column spacing

Date: 2026-11-08

## Decision
Use the **actual canvas viewport width** as the horizontal baseline. On wider
windows, spread the three existing columns horizontally while preserving card
width, text sizes, service order, vertical centering and independent evidence
paths. Do not infer congestion from the number of captured packets.

## Mechanics
- The Services-view horizontal coordinate system uses the canvas CSS width
  with a **1080 SVG-unit minimum** for smaller windows.
- Hardware stays at 24 units; the 282-unit Services card occupies the right
  margin; the IP column sits halfway between hardware and Services columns.
- Services headers and empty-state text follow the same coordinates as nodes.
- The Services SVG viewBox width follows this dynamic horizontal extent.
- A Services-only **Column spacing** slider overlays the map (without reducing
  its height). It adds 0–3000 horizontal SVG units in 100-unit increments,
  defaulting to +600. Hardware remains anchored at x=24; IP moves halfway
  across the expanded gap; Services moves to the right edge.
- Moving the slider changes only Services-view X coordinates, the SVG
  horizontal extent, and the resulting connector shapes. It does not modify
  Y coordinates, card sizes, evidence records, camera state, or manual orders.
- The original Reset view/fit formula remains untouched. For exceptionally
  wide gaps on a short or narrow screen, the existing fit-to-all algorithm may
  still scale the complete graph uniformly to keep all content visible.
- A ResizeObserver redraws only the Services presentation when canvas width
  changes. It does not reset the camera or manual ordering.
- Stage 4A longest-rendered-column vertical centering remains in place.
- Other views (ARP only and Unified) retain their original geometry.

## Follow-up after merge (2026-11-14)

Stage 4B.1 was squash-merged as [PR #64](https://github.com/n2bxl/novxis/pull/64).
Stage 4B.2 subsequently shipped as
[PR #65](https://github.com/n2bxl/novxis/pull/65), ordering shared
connector ports by their opposite endpoint's vertical position. That
**local crossing reduction** is not density-based automatic spacing.

Global intersection detection, quantitative congestion metrics, automatic
width adjustment, and layout hysteresis remain deferred. They should be
measured against a fixed evidence fixture, not packet count or arrival rate.

## Validation
Run:

```bash
python -m pytest tests/web/test_responsive_service_columns.py \
  tests/web/test_services_canvas.py \
  tests/web/test_column_centering.py \
  tests/web/test_preview_camera_fit.py \
  tests/web/test_viewport_workspace.py -q
python -m pytest
```

Expected full suite: **1036 tests** (1032 latest passed baseline + four new
spacing-control contracts).

## Safari acceptance
1. Compare narrow and wide Safari windows: wider windows spread the three
   columns while leaving card width and text size unchanged.
2. Resize repeatedly with Services selected. Cards and headers stay aligned,
   paths reconnect, and manual ordering/selection remain stable.
3. Confirm Stage 4A vertical centering when Services or IPs dominate height.
4. Confirm Reset view, zoom-to-read, pan, mousewheel zoom and sidebar scroll.
5. Confirm service names, TTL expiry, individual evidence selections and
   keyboard movement are unchanged.
6. Switch between ARP/Unified/Services. The spacing slider is visible
   only in Services, and its value persists across map-mode switches.
7. On the 34-service stress capture, drag Column spacing from +600 toward
   +1600 or more. Confirm Hardware stays on the left, IP stays between the
   columns, and Services moves farther right; no card height, row position,
   ordering or service evidence changes.
8. Compare Reset view before/after spacing changes. Confirm original
   fit-to-all behavior is preserved. With extreme spacing, check whether
   the width becomes the limiting fit dimension; do not interpret fit-to-all
   shrinkage as a vertical-layout change.

This stage does not claim density-aware routing or edge crossing reduction.

## Final acceptance

The combined Stage 4B implementation passed **1,041/1,041** tests on
post-merge `main` (2026-11-14, 5.35s), including the eight final
responsive-spacing source contracts. Original expected counts and Safari
checklist above are preserved as implementation-time context. See
[Stage 4 closeout](2026-11-14-stage4-closure.md).
