# Stage 4A: center shorter Services-view columns

Date: 2026-11-08

## Motivation
On a live multi-service capture the three graph columns may have different
rendered heights. Center each shorter column vertically relative to the
tallest *rendered* column while keeping the Stage 3 single compact Services
list and the existing evidence-driven automatic ordering.

## Implementation
- After the usual Services layout computes all node coordinates, measure
  each nonempty column's actual visible top and bottom. Address and hardware
  cards are 64 SVG units tall; DNS-SD service cards use the existing
  dynamic `serviceCardHeight(node)` calculation.
- Use the tallest rendered column's vertical center as the reference.
  Translate other columns vertically so their bounds share that center.
- Preserve the existing node ordering and spacing within each column,
  including MAC-first address groups, compact Services layout, and
  manually reordered services.
- Compute service drag slot centers **after** the centering translations so
  dragging continues to target the currently displayed locations.
- Extend the SVG stage to the lowest translated card; keep `Reset view`
  using actual rendered bounds.
- Do not alter observation types, interface/capture scope, endpoint
  evidence, service TTL semantics, or the ARP-only and Unified views.

## Local regression

```bash
python -m pytest tests/web/test_column_centering.py \
  tests/web/test_services_canvas.py \
  tests/web/test_service_name_wrapping.py \
  tests/web/test_viewport_workspace.py -q
python -m pytest
```

Expected full suite: 1,011 (1,007 baseline + four new checks).

## Safari acceptance
1. With one column clearly longer than the others, confirm the shorter
   columns are vertically centered against the longest column.
2. Repeat when Services is the tallest column due to many advertisements,
   and when IP addresses are the tallest column. Observe compact gaps and
   complete service names.
3. Rearrange and drag nodes between top and bottom positions. Confirm no
   discontinuity or unexpected snapping; independent connectors reattach.
4. Confirm TTL expiry styles, selection, keyboard navigation, reset/zoom,
   and independent sidebar scrolling remain correct.
5. Switch to ARP-only and Unified: their previous geometry should remain
   unchanged.

Horizontal widening and edge-path congestion work are explicitly deferred
to a separate Stage 4 step to isolate presentation regressions.
