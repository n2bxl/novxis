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
- A ResizeObserver redraws only the Services presentation when canvas width
  changes. It does not reset the camera or manual ordering.
- Stage 4A longest-rendered-column vertical centering remains in place.
- Other views (ARP only and Unified) retain their original geometry.

## Future density-aware extension: Stage 4B.2
Density should measure **visible evidence-edge crowding near a column gap**
instead of packet count or raw number of edges. Candidate signals include
distinct endpoint fan-in/out ports, path intersections and segment proximity.
Apply additional *bounded* horizontal spacing only after evidence-based
metrics and a Safari baseline exist. Avoid visual changes driven by network
packets with no new graph relationship.

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

Expected full suite: **1015 tests** (1011 baseline + four new contracts).

## Safari acceptance
1. Compare narrow and wide Safari windows: wider windows spread the three
   columns while leaving card width and text size unchanged.
2. Resize repeatedly with Services selected. Cards and headers stay aligned,
   paths reconnect, and manual ordering/selection remain stable.
3. Confirm Stage 4A vertical centering when Services or IPs dominate height.
4. Confirm Reset view, zoom-to-read, pan, mousewheel zoom and sidebar scroll.
5. Confirm service names, TTL expiry, individual evidence selections and
   keyboard movement are unchanged.
6. Switch between ARP/Unified/Services. Only Services uses the new horizontal
   geometry.

This stage does not claim density-aware routing or edge crossing reduction.
