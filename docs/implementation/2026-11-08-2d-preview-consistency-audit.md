# 2D preview consistency audit: camera fit (2026-11-08)

## Scope

Behavior-only follow-up to Phase 1N-M Stage 3. No changes to passive
ARP/NDP/DNS-SD evidence collection, models, serialization, or visual identity.

## Code findings

- ARP only, Unified addresses, and Services already have independent saved
  cameras, selections, and manual order overlays, with common pointer, wheel,
  keyboard, and mode-switch controls.
- Layout remains intentionally mode-specific: ARP two-column, Unified
  MAC-centered groups, Services three-column with sparse endpoint-aligned rows.
- Before this change, **Reset view** only assigned camera origin/scale, even
  though the Services hint promised a fit. A sparse service graph could appear
  offset with unhelpful blank space.
- Wheel zoom was bounded to 0.4, making the first gesture after fitting a
  sufficiently dense graph jump abruptly to that floor.

## Changes in this branch

- Reset view fits the actually rendered viewport content using the SVG
  bounding box. It centers evidence, includes padding, does not magnify beyond
  100%, and falls back to the original camera when nothing has measurable
  bounds. This is the same control in all three map modes.
- Reduce the wheel minimum scale to 0.05 so zoom after fitting dense evidence
  is less likely to jump to 0.4.
- Make tooltip and Services hint describe framing rather than a misleading
  reset-to-origin.
- Add focused static browser contracts to guard this behavior.

## Remaining acceptance and audit work

1. Run `python -m pytest tests/web/test_preview_camera_fit.py
   tests/web/test_services_canvas.py tests/web/test_unified_canvas.py
   tests/web/test_layout_controls.py -q`, then `python -m pytest`.
2. In Safari, on each map mode: pan, zoom, Reset view, and verify all displayed
   nodes and relationship edges are in frame, especially sparse Services.
3. Verify keyboard access and screen-reader labels for graph controls.
4. Rearrange a MAC, IP, and service, switch modes, return, and verify that
   camera, selection, and per-mode manual ordering remain independent.
5. On live snapshots, verify TTL expiry/retraction and new ARP/NDP claims do
   not unexpectedly reposition manually arranged nodes.
6. Check that the Services sidebar tab and top-of-map Services mode remain
   distinguishable to users.

Tests here are source-level contracts; passing them alone would **not** prove
Safari rendering, pointer, or zoom behavior. The separate NOVXIS logo UI
direction should inform a later design-system overhaul, not this patch.
