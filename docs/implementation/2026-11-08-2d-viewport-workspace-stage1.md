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
