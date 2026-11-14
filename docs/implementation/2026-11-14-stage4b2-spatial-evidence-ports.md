# Stage 4B.2: spatially ordered connector ports

Date: 2026-11-14

## Why
The Services renderer already keeps each evidence edge separately selectable
and spreads convergent paths across small ports on each card. However, the
ports were previously sorted solely by stable evidence IDs. That ordering
does not reflect where the opposite card appears, so paths sharing a service
(e.g. AirPlay) could unnecessarily cross one another near the destination.

## Presentation-only behavior
- For each **outgoing port** on a card, order edges by the **vertical center
  of the opposite destination card**.
- For each **incoming port**, order edges by the **vertical center of the
  originating card**.
- For equal vertical centers, use the original stable evidence ID as a
  deterministic tie breaker. This preserves consistent ordering for
  parallel evidence records between identical endpoint pairs.
- Preserve the original fan-out range (maximum 16 SVG units between ports,
  total 52 SVG units), Bézier curve form, hit areas, expired TTL styling,
  source-record identities, and accessibility labels.
- No node is moved or reordered. Stage 4A centering, Services manual
  arrangements, service-first-supporting-IP ordering, the adjustable
  Stage 4B.1 column gap, and independent map cameras are unchanged.
- No new capture, network probes, inferred identity, endpoint claims or
  merging of distinct evidence paths.

This is a **local port-order optimization**, not a guarantee of globally
minimum crossings. Opposite-order endpoints between different cards may
still require real intersections. Automatic full-layout reordering and
path bundling are intentionally out of scope.

## Branch and dependency
PR #64 (Stage 4B.1) has been accepted and squash-merged. This focused
Stage 4B.2 branch is based directly on the merged `main`, containing only
its own renderer, tests and documentation changes.

## Validation
```bash
python -m pytest tests/web/test_spatial_port_routing.py \
  tests/web/test_services_canvas.py \
  tests/web/test_column_centering.py \
  tests/web/test_responsive_service_columns.py -q
python -m pytest
```

Expected full suite at the current branch snapshot: **1041 collected**
(1032 previously passed before four Stage 4B.1 spacing control tests,
plus five new Stage 4B.2 port-routing tests). Local execution is
required to confirm.

## Safari acceptance
1. Compare the recorded AirPlay convergence case: incoming paths from
   higher IP rows should generally attach above paths from lower IP rows.
2. Check the complementary fan-out: paths leaving one IP toward higher
   service cards should leave from higher ports.
3. Confirm parallel evidence records remain visibly distinct and separately
   clickable, including expired dashed DNS-SD paths.
4. Test manual movement, Rearrange/Auto arrange, +0 to +3000 gap settings,
   Safari window resizing and Reset view; node placement and camera behavior
   must not regress.
5. Switch among ARP/Unified/Services; only the Services routing renderer is
   changed.
6. Compare a fixed sanitized evidence graph (when available) to distinguish
   routing improvement from differences in live capture traffic.
