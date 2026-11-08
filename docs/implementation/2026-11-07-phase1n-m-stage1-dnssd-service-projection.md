# Phase 1N-M Stage 1: Pure DNS-SD Service Evidence Projection

- **Date:** 2026-11-07
- **Status:** Implementation and post-fix M5 regressions accepted; ready for owner review and squash-merge
- **Previous merged baseline:** 895 passing tests in 4.60 s after Phase 1N-L
- **Planning proposal:** PR #50, Phase 1N-M design and acceptance

## Scope

This stage **does not** introduce the three-column browser map. It adds a
pure, immutable evidence projector with input and scope validation, plus
synthetic tests. It does not modify the existing ARP/NDP graph, live ingestion,
capture pipeline, privilege boundary, /api/graph endpoint, or JavaScript.

Implementation: `novxis/views/dnssd_service_graph.py`

Tests: `tests/views/test_dnssd_service_graph.py`

## Inputs and evidence boundary

`project_dnssd_service_graph(address_graph, mdns_evidence, *,
interface, capture_scope)` consumes:

- An existing `UnifiedAddressGraphSnapshot` with ARP sender and option-backed
  NDP address relations.
- An already receiver-validated, bounded `LiveMDNSState.snapshot()` mapping
  from the **same capture interface**. Its PTR-backed service instances
  contain the accepted, and possibly cross-response reconciled,
  PTR → SRV → A/AAAA chain. Its `as_of` time defines TTL freshness.
- A capture session identifier supplied by the unprivileged owner, not
  from network packets.

The projector **does not** parse DNS records or infer a new relationship
by matching service names, hardware addresses or packet sender fields.
It neither revisits explicitly cleared reconciliation overlays nor
fabricates connections for missing SRV/A/AAAA components.

Stage 2 is responsible for supplying these validated inputs to the
projector and serializing its separate versioned JSON graph.

## Output contracts

- `DNSSDServiceGraphSnapshot` (frozen, slots): capture scope, interface,
  as-of snapshot time, sorted typed nodes/edges, mDNS truncation/omission
  metadata, and count of syntactically valid but non-unicast A/AAAA
  endpoint addresses intentionally omitted from edges.
- `DNSSDServiceNode`: a PTR-backed advertised instance, with stable
  scope/interface/type/instance identity. Its retained `DNSSDPTRRecord`
  has timestamp, TTL, observation count and snapshot freshness. A service
  without an accepted endpoint chain remains an unconnected service node.
- `UnifiedAddressNode`: **reuses the exact node ID and kind** for any
  observed ARP/NDP IPv4 or IPv6 address. A valid DNS-SD-only A/AAAA
  address may create an otherwise unlinked address node. No new
  hardware-address edges are invented.
- `DNSSDEndpointEdge` (kind `dnssd_advertised_endpoint`): a distinct
  IP → advertised service path with `DNSSDPTRRecord`, `DNSSDSRVRecord`
  and `DNSSDAddressRecord` provenance, record keys, exact SRV target and
  port, source (`same-mdns-response` or `cross-mdns-response`),
  timestamps, TTLs, component freshness, and overall path freshness.
  Parallel record paths to the same IP/service remain independently
  inspectable. Duplicate identical retained paths are idempotent.
- Existing `UnifiedAddressEdge` records remain **unchanged**, including
  independent and conflicting NS/NA/ARP hardware claims.

### Freshness and historical evidence

A component is fresh at the snapshot's `as_of` time only if its TTL is
positive and `observed_at <= as_of < observed_at + TTL`. An accepted
DNS-SD endpoint path is fresh only if its PTR, SRV and A/AAAA
components all meet that condition. Stale-but-retained paths are still
returned with `path_fresh=False`; a **retracted** reconciliation path
does not reappear.

A displayed service or a stale/fresh path is still only an observed
advertisement, never proof of a running process, open port, reachable
host, stable MAC or physical device.

### Scope and resource bounds

- One capture scope/interface for the mDNS overlay; no joins across
  capture sessions or interfaces.
- Up to 128 PTR-backed instances, two SRV targets per instance,
  and three addresses per target, matching existing receiver caps.
- Canonical IP parsing and separate IPv4/IPv6 nodes. Multicast,
  unspecified and IPv4 limited-broadcast A/AAAA values do not become
  advertised endpoint links; unsupported counts are explicit.
- Plain display names and case-insensitive service identity are kept
  separate. Graph IDs are deterministic length-prefixed strings,
  never positional row numbers or layout coordinates.
- No new raw packet data, TXT payload, DNS query, privilege or active
  endpoint probe is introduced.

## Focused M5 validation

From the Stage 1 branch:

```bash
git fetch origin
git switch --track origin/ai/phase1n-m-service-evidence-projector-stage1-2026-11-07
python -m pytest tests/views/test_dnssd_service_graph.py \
  tests/views/test_unified_address_graph.py \
  tests/web/test_mdns_live.py \
  tests/web/test_mdns_service_links.py -q
python -m pytest
```

**M5 acceptance (2026-11-07, after PTR TTL fixture correction):** focused suite **124 passed in 0.11 s**; complete suite **938 passed in 4.64 s** (43 additional passing cases over the Phase 1N-L baseline of 895). Platform: macOS, Python 3.14.6, pytest 9.1.1. The two initial failing exact-PTR-expiry parameter cases were corrected by making the *synthetic* PTR/SRV composite freshness flag consistent with the shortened PTR TTL. The projector's strict freshness validation was unchanged.

## Synthetic acceptance examples

1. PTR + SRV + A/AAAA yields one service, existing shared IPv4/IPv6
   identity, original MAC evidence and a service-only address node
   with **no** fabricated MAC edge.
2. PTR-only and PTR + SRV without A/AAAA never form a service-IP edge.
3. Multiple services/one IP, multiple IPs/one service and independent
   SRV target/port paths remain separate selectable evidence records.
4. Record TTL expiry labels retained history accurately. At an exact
   TTL boundary the path must no longer be fresh.
5. Accepted cross-response reconciliation may support a path, but an
   explicit reconciliation clear retracts it.
6. Different interfaces/scopes, contradictory MAC claims, malformed
   input, noncanonical addresses, unicast filtering, and bounded
   omissions are handled without identity inference or mutation.
7. Same evidence in different collection order yields the same
   immutable semantic snapshot.

## Deferred until later stages

- Stage 2: receiver adapter, versioned `unified_service_graph` JSON,
  standalone service-specific semantic revision and mDNS integration.
- Stage 3: third **Services** map selector, **HARDWARE → IP → SERVICES**
  columns, automatic service clustering, clickable service connectors,
  and full PTR/SRV/A/AAAA Evidence Inspector.
- Stage 4: local Safari validation, full three-mode UX acceptance and
  final milestone documentation.

The post-fix Stage 1 focused and full suites have both passed on the M5. This branch is ready for owner review and squash-merge; no merger, Stage 2 integration, or Safari graph behavior is claimed here.
