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

## Final status and merge sequence

[PR #64](https://github.com/n2bxl/novxis/pull/64) (Stage 4B.1) and
[PR #65](https://github.com/n2bxl/novxis/pull/65) (Stage 4B.2)
were squash-merged to `main`, in that order. PR #65 was rebased
as a focused three-file change against the merged #64 baseline.
This implementation is complete; the branch workflow described during
the sprint is historical.

## Validation
```bash
python -m pytest tests/web/test_spatial_port_routing.py \
  tests/web/test_services_canvas.py \
  tests/web/test_column_centering.py \
  tests/web/test_responsive_service_columns.py -q
python -m pytest
```

**Verified:** 1,041/1,041 passed in 5.35 seconds on the
developer's updated `main` (macOS Python 3.14.6, pytest 9.1.1,
2026-11-14). Five spatial-port tests and eight responsive-layout
tests are included. Local Safari recordings were reviewed for
connector readability, drag behavior and evidence inspection;
not every individual parallel hit target was exhaustively tested.

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

## Closeout link

See [Stage 4 merged acceptance and 3D renderer boundary](2026-11-14-stage4-closure.md).
