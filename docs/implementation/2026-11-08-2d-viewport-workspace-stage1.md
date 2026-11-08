# Stage 1: Viewport-constrained 2D evidence workspace

Date: 2026-11-08

## Goal

Keep the top bar, canvas controls, map legend and footer disclaimer
visible inside the desktop browser viewport while long Services/NDP
evidence scrolls inside its own right-hand tab panel.

This stage is intentionally **only CSS layout**. No changes to the
network evidence model, API, JavaScript interaction handling, camera,
graph geometry, card content or visual branding.

## Implementation

- Desktop shell height is `100dvh` (with `100vh` fallback).
- Desktop workspace, map panel and canvas can shrink below their old
  660px / 440px minima. Flex containers use `min-height: 0`.
- Header, map controls, legend and page disclaimer keep natural height.
- The right-hand inspector fits the allocated height and its active
  sidebar page scrolls independently; other tab states are unchanged.
- At 900px width and below, use the existing stacked view with normal
  document scrolling, a usable minimum map area and a bounded inspector.
  A tall mobile browser is not forced into a cramped desktop grid.

## Local tests

```bash
python -m pytest tests/web/test_viewport_workspace.py \
  tests/web/test_services_canvas.py \
  tests/web/test_unified_canvas.py \
  tests/web/test_layout_controls.py -q
python -m pytest
```

## Safari acceptance checklist

1. On a normal desktop window, open ARP, Unified and Services. Confirm
   legend and footer disclaimer stay visible without page scrolling.
2. In Services sidebar, scroll long PTR/SRV/A/AAAA content and verify
   the map and top bar stay stationary. Repeat with IPv6 neighbor tab.
3. Reduce desktop browser **height** without reducing its width;
   confirm the canvas shrinks without overlaying the legend or footer.
   Test map selection, pan, zoom, Reset view and rearrangement.
4. Resize width below 900px: layout stacks and page scrolling becomes
   intentional, with enough space for the canvas and a scrollable sidebar.
5. Check tab switching and keyboard focus in the sidebar, including
   scrolling a selected tab via keyboard.
6. Check a dense Services graph: all content remains available via
   camera pan/zoom and inspector scrolling, without evidence omission.
7. Look for unexpected inner scrollbars and clipped map controls at
   narrow or short viewport sizes.

## Validation limits

Static CSS/HTML contract tests do **not** prove Safari layout.
The branch needs local M5 regression and live Safari acceptance before
being marked ready or merged.

## Live Safari finding: dense graph zoom ceiling

The owner supplied two 2026-11-08 Safari recordings demonstrating that
both wheel zoom and the `+` control hit the fixed 3.5 camera scale limit
while tall Services graphs still had very small node labels. The SVG's
`viewBox` height scales with the retained row count, so its entire content
is visually miniaturized as it is fitted into a shorter browser canvas.

The follow-up keeps the existing dynamic `viewBox` implementation and
makes the maximum camera scale proportional to the graph height
(`3.5 * max(1, stageHeight / 620)`). Both zoom controls share `zoomAt()`.
This is a presentation-only correction: it does not change graph content,
evidence identity, row ordering or retained packet observations.

### Extra Safari acceptance

1. With a tall Services capture, zoom in until a service label is comfortably
   readable. Confirm the wheel and `+` button continue working beyond the
   former visual limit.
2. Confirm pan, Reset view and zoom after Reset view still work.
3. Switch to ARP and Unified views and check there is no unintended jump in
   saved per-mode camera state.
4. In a shorter capture, confirm ordinary zoom behaves as before.


## Wide-window zoom follow-up

The owner reported and recorded a further Services zoom ceiling in a wide
Safari window after the original height-based adjustment. Review showed
that logical SVG height alone is not sufficient to set a useful camera
maximum: the browser's default `xMidYMid meet` aspect-ratio behavior
fits the viewBox using the smaller of its horizontal and vertical CSS
scale factors.

The revised `maximumZoomScale()` reads the SVG's actual client rectangle
and viewBox, computes the effective CSS pixels per graph unit, and derives
a ceiling from that displayed scale. The original 3.5 maximum remains
the floor for smaller maps, and missing/zero geometry falls back to 3.5.
Wheel and `+` controls still call the same `zoomAt()` function.

This work preserves all evidence semantics and existing map modes.
It requires fresh Safari acceptance at both wide/short and normal sizes,
including Reset view, scrolling zoom, button zoom, and cross-mode camera
retention. Static contract checks alone cannot validate actual CSS layout.
