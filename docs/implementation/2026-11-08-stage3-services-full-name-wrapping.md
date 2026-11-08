# Stage 3: full DNS-SD service names in the Services SVG

Date: 2026-11-08

## Purpose

Make each advertised DNS-SD service name readable directly in its SVG map
card, including long local service instances, without relying on hover titles
or cutting names off with an ellipsis.

## Presentation-only implementation

- The Services view splits the original instance name into several SVG text
  lines, preferring punctuation or whitespace boundaries and splitting long
  escaped segments when necessary. The original name is not modified.
- Each card gains 16 SVG units per additional name line, with service type
  and PTR freshness/retained interface metadata shifted downward.
- The Services column is one compact vertical list with a consistent
  12-unit gap between variable-height cards. Automatic order follows the
  earliest linked IPv4/IPv6 address in the visible IP column, then service
  type/name for ties. Services without eligible links come last.
- Manual reordering preserves the chosen order, with drag targeting based
  on actual card centers rather than an assumed fixed-size row. Rearrange
  resets the manual order to the evidence-based ordering.
- The SVG stage height includes the last service card's actual bottom;
  viewport-aware Reset view remains responsible for framing the graph.
- DNS-SD connectors attach to the vertical midpoint of the target service
  card, retaining independent port fans, hit targets, and stale-path styles.
- Address and hardware card geometry and the separate ARP/Unified modes do
  not change. No capture or inference logic changes.

## Regression check

```bash
python -m pytest tests/web/test_service_name_wrapping.py \
  tests/web/test_services_canvas.py \
  tests/web/test_preview_camera_fit.py \
  tests/web/test_viewport_workspace.py -q
python -m pytest
```

Expected full suite: 1007 tests (1002 on main plus five new contracts).

## Safari acceptance

1. Inspect a service with a short instance name. It should retain its
   original compact card size.
2. Inspect long service instances (including escaped spaces and punctuation).
   Verify the **entire name** is visible without hover and text stays inside
   the card's right/bottom boundaries.
3. Verify service type and PTR freshness are below the wrapped name and do
   not overlap each other.
4. Verify all services appear as one compact ordered column without
   group-sized gaps. Rearrange sorts by the first supporting IP in visible
   address order, with unlinked services at the bottom. Manual dragging
   changes list order without snapping to spatial evidence clusters.
5. Follow A/AAAA -> Service connectors. Endpoint paths should terminate at
   the middle of the taller card, remain independently selectable, and still
   become dashed on TTL expiry.
6. Check Reset view, pan, zoom, cross-mode state, sidebar scrolling, and
   keyboard selection in Safari.

## Explicitly excluded

Widening service columns, adjustable column spacing, branded UI assets,
network topology inference, or revisions to passive packet evidence. These
belong to later work.

These are source-level regression contracts. Safari review is necessary
before marking the PR ready to merge.
