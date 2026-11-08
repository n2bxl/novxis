# Stage 2: readable DNS-SD and IPv6 neighbor evidence metadata

Date: 2026-11-08

## Scope

Browser-only presentation improvement on top of Stage 1 viewport-constrained
workspace. The underlying ARP/NDP/mDNS evidence model, service reconciliation,
packet capture, graph rendering, map-camera behavior, scope constraints, and
independent navigation are unchanged.

## Change

The Services sidebar previously appended resource-record details as long,
dot-delimited strings that the browser wrapped at arbitrary locations. IPv6
Neighbor Discovery entries used the same dense inline formatting.

Add a shared `appendEvidenceMetadata(parent, detail)` helper that converts
the existing dot-separated textual record summaries into separate DOM `p`
elements, one field per line. The first field retains its primary claim label;
subsequent fields use a leading dot and consistent spacing. Original claim
values, observation counts, timestamps, TTLs, same-/cross-response provenance,
and freshness wording are unchanged.

All network-derived data continues to use `textContent`. Existing direct
navigation buttons to independent ARP or NDP evidence still appear after their
corresponding endpoint metadata. No fake NDP TTL is introduced.

Sidebar scrolling remains bounded by the Stage 1 viewport layout so longer
metadata does not expand the whole document on desktop.

## Test commands

```bash
python -m pytest tests/web/test_evidence_metadata_layout.py \
  tests/web/test_mdns_service_links.py \
  tests/web/test_ndp_sidebar.py \
  tests/web/test_viewport_workspace.py -q
python -m pytest
```

## Safari acceptance

1. Open Services sidebar and select a PTR-backed service with an SRV target
   and multiple A/AAAA endpoints. Verify each TTL, observation count,
   time, freshness and source-reconciliation field is on its own line.
2. Inspect the same service's independent ARP and NDP shortcuts and verify
   they still navigate to the original supporting evidence.
3. Open IPv6 Neighbor evidence and verify NS/NA claims, advertised Ethernet
   addresses, observation counts, and first/last timestamps appear on
   distinct lines.
4. Verify unlinked NDP observations still describe their uncertainty.
5. Scroll long Services and IPv6 lists; confirm map, legend, and footer
   remain visible without whole-page scrolling at desktop width.
6. Verify fresh/expired evidence wording is unchanged; no NDP TTL or
   physical device identity is inferred by presentation formatting.

## Excluded from this stage

- Multiline **SVG map service names** and dynamic card dimensions (Stage 3)
- Wider service map and column spacing (Stage 4)
- Brand/logo-driven UI redesign

Static regression contracts cannot establish Safari appearance; owner review
required before merging.
