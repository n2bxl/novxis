# Phase 1N-M: DNS-SD Service Evidence Graph implementation plan

- **Date:** 2026-11-07
- **Status:** Design approved for planning; no Phase 1N-M implementation started
- **Baseline:** Phase 1N-L merged, 895 full-suite Python tests passing on M5 in 4.60 s
- **Purpose:** Extend the existing local, passive NOVXIS 2D evidence debugger with an independently selectable **Services** graph mode, while preserving **ARP only** and **Unified addresses** exactly as separate tools.

## Decisions agreed

1. Three map modes: **ARP only**, **Unified addresses**, and **Services** (full title: "Unified address and service evidence map").
2. **Services** uses three left-to-right columns: **HARDWARE ADDRESSES → IPv4 / IPv6 ADDRESSES → SERVICES**.
3. Hardware MAC evidence remains the arrangement anchor; IP nodes group by their retained ARP/NDP relations; service instances appear in their own selectable boxes and may attach to multiple supported IP nodes. Selecting or rearranging a MAC should move its *layout cluster*, not claim that the MAC identifies a permanent physical host.
4. **Every visible connector is interactive** (pointer plus Enter/Space), and the Evidence inspector shows the underlying assertion/provenance. ARP, NDP, and DNS-SD connections retain distinct typed semantics.
5. Services are **advertised instances**, not verified listening or reachable services. The graph is not a cable diagram, host inventory, gateway hierarchy, or service ownership assertion.
6. Each map mode retains its own camera, selected node/edge, automatic layout and manual arrangement. Existing ARP and Unified views must not be rewritten to make Services possible.
7. Only existing authorized passive ARP/mDNS/NDP events are used. No new capture privileges, active scanning, DNS queries, remote calls, or new externally accessible API routes.

## Existing implementation we will reuse

- `novxis/web/mdns_live.py`: bounded, validated unprivileged mDNS metadata and PTR-backed service instance snapshots. Includes retained PTR service name/type/observation count and TTL; SRV hostname/port/TTL/observed time; A/AAAA address/family/TTL/observed time; fresh/path_fresh and same- vs cross-response source flags.
- Existing reconciliation logic validates cross-response names and chronology, and supports explicit reconciliation retractions. We must **use** these acceptance decisions, not independently infer correlations from matching text.
- `novxis/web/live_state.py`: same-interface, session-scoped ARP/NDP and mDNS snapshots under a thread-safe owner. The current `/api/graph` response contains legacy ARP fields, separate `unified_address_graph` and `mdns_evidence`.
- `novxis/views/unified_address_graph.py` and `novxis/web/unified_live.py`: address-only scoped node/edge projection with deterministic keys; ARP sender, NS source-SLLA and NA target-TLLA. No DAD, NA without TLLA or inferred device identity.
- `novxis/web/static/app.js`: permanent SVG camera, MAC-first layout, drag/reorder, mode-specific selection and independently selectable evidence edges. Services sidebar remains a separate text-focused view.

### Important data limits

Live mDNS retains up to 128 PTR-backed instances, two SRV targets per retained advertisement and three A/AAAA addresses per target, with explicit truncation/omission markers. The data is **not** an exhaustive persistent mDNS cache. Raw TXT content and raw packet payloads are not available across the privilege boundary; the graph must not invent them.

## Semantic design: graph nodes and edges

### Node kinds

- **hardware**: reuse the existing interface- and capture-scope-qualified address evidence nodes. No device identity.
- **ipv4 / ipv6**: reuse the same exact stable node IDs when an address already appears in the ARP/NDP graph. An otherwise absent IP **may be introduced as a DNS-SD-advertised-only address node** if a retained, supported A/AAAA path names it; in that case it has *no fabricated hardware edge*.
- **dnssd_service**: exactly one node per capture scope + interface + canonical DNS-SD service type + case-insensitive instance name. Preserve the original observed display spelling separately. A PTR-backed instance without a supported SRV/A/AAAA path remains a standalone service node with an explicit "no supported endpoint path" state.

### Typed edges

- Existing `arp_sender`, `ndp_ns_source_slla` and `ndp_na_target_tlla` remain untouched and selectable.
- New **`dnssd_advertised_endpoint`**: a directed **IP → advertised service** visual relationship backed by the full **PTR(instance) → SRV(target, port) → A/AAAA(target-address)** chain. The underlying DNS records link *names and advertised addresses*, not the physical IP device to a guaranteed running service.
- A service may have multiple endpoint paths (several addresses, SRV targets or ports). Represent each **distinct supported path** as an individually inspectable edge, even when two paths share the same visual endpoints. The graph may visually offset/bundle parallel paths only if each retains independent drill-down.
- Do not emit an endpoint edge from PTR-only, SRV-only or A/AAAA-only metadata, nor from an unaccepted stale/cross-response inference. A missing chain means **no edge**, not a best-guess link.
- If a retained path later becomes TTL-expired, show it as **historical/stale evidence** (e.g. dashed line), never as current confirmed availability. This is contingent on the existing bounded state still retaining the path; do not promise indefinite history. If reconciliation is explicitly cleared, remove the invalidated joined path rather than resurrect it as "stale."
- Freshness is a **snapshot-time property**: compute it from the already validated PTR, SRV and A/AAAA component freshness flags. Do not invent a composite DNS record or apply a DNS TTL to NDP/ARP edges.

### Service edge Inspector contract

Selecting an IP ↔ service edge must display all of:

1. Evidence kind `dnssd_advertised_endpoint` and a clear statement that it is an *advertised endpoint path*, not a verified service.
2. Service type and instance (PTR owner/target), PTR observed timestamp, TTL, observation count, and current freshness.
3. SRV target hostname, port, observed timestamp, TTL, freshness, and same-response/cross-response source.
4. A/AAAA type, exact canonical advertised address, observed timestamp, TTL, freshness, and source.
5. Overall path freshness and the snapshot `as_of` time used for evaluation.
6. Capture interface, capture scope, stable evidence/path reference and any known omission or retention-limit marker.
7. If the path is stale, which supporting component(s) are no longer fresh; if unlinked, the absent support. Never silently substitute a MAC association or report application reachability.

The existing Evidence inspector must continue to display ARP/NDP node and edge provenance unchanged, including selectable parallel/conflicting claims.

### Identity, comparison and validation boundaries

- Keys are deterministic for identical inputs, independent of arrival order: capture scope, interface, normalized service type + instance, canonical IP address/family, and the typed SRV/target/port/path evidence fields as required to distinguish parallel paths.
- Case-insensitive DNS owner-name comparison follows the decoder/reconciler's established semantics. Display labels must not be substituted for unique IDs.
- Never cross interfaces or session capture scopes; no MAC/IP/DNS name match may override this boundary.
- A matching service endpoint address and ARP/NDP claim supports two **distinct** evidence paths converging on the same address node. It does not validate a device owner or that a port is open.
- If multiple MACs claim an IP, retain every address evidence edge. The graph's MAC-first arrangement picks only a **visual anchor**, not a winner.

## Implementation work breakdown

### Stage 1: Pure service evidence projection

**Candidate module:** `novxis/views/dnssd_service_graph.py` (exact module name chosen at implementation).

- Define immutable renderer-neutral service nodes and advertised-endpoint chain edges; project from receiver-validated PTR-backed DNS-SD state plus the existing unified address graph, with an explicit capture scope/interface and snapshot time.
- Reuse existing IPv4/IPv6 node identity where possible. Include service-only address nodes without artificial MAC connections.
- Design stable IDs, first-class typed chain provenance and freshness/retention status. Keep deterministic output and bounded cardinality.
- Tests: PTR-only, incomplete chains, mixed A/AAAA, one service/multiple addresses, multiple services/one address, repeated/case-varied names, multiple SRV paths/ports, stale PTR/SRV/address component, TTL=0, accepted cross-response reconciliation vs invalid/cleared path, conflicting MAC claims, wrong interface/scope, deterministic order and caps.

**Exit criterion:** pure synthetic projection passes focused tests without capture, HTTP, DOM or OS network context.

### Stage 2: Unprivileged live graph adapter

**Candidate modules:** `novxis/web/dnssd_service_live.py` and additive changes to `novxis/web/live_state.py`.

- Convert only already validated, bounded `mdns_evidence` from the existing snapshot into the Stage 1 service projection. Do not pass raw DNS packets, TXT values, new privileged commands or browser-controlled source IDs.
- Add a separate **versioned** `unified_service_graph` payload to the current same-origin `/api/graph` response for authorized combined sessions. Do not mutate top-level ARP `nodes`/`claims`, legacy revisions, `unified_address_graph`, NDP view or `mdns_evidence` shape.
- Track a **service-specific semantic revision**. Changes in accepted PTR/SRV/A/AAAA state, explicit reconciliation/retraction or TTL freshness transition should update the service graph without forcing ARP-only re-layout. Avoid treating routine unrelated packet counts as graph changes.
- Expose truncation, stale/omitted chains and source-scope boundaries honestly. A combined session with no service advertisements can still expose a valid **empty Services mode**, not fabricated service nodes.
- Tests: JSON serialization, separate revisions, stream ingestion and session isolation, no-mDNS/offline compatibility, atomic mDNS validation, snapshot expiry/retraction and omission markers.

**Exit criterion:** a local `/api/graph` inspection shows an accurate bounded service snapshot while the existing UI is unchanged.

### Stage 3: Third 2D map mode and evidence interaction

**Candidate assets:** `novxis/web/static/index.html`, `app.js` and `styles.css`, plus browser-contract tests.

- Add a third top-of-map selector **Services**. Leave **ARP only** as default, **Unified addresses** as the unchanged middle mode. Services enables when a versioned same-interface service projection is available; it may have zero service nodes.
- Services uses the three-column layout **HARDWARE → IPv4/IPv6 → SERVICES**, without silently reversing the two existing modes.
- Reuse the SVG renderer, pointer/keyboard edge hit targets, camera and node reorder functions. Add a distinct state bucket for Services (selection, manual order per column, camera and last semantic revision).
- Deterministic automatic layout: MAC evidence anchors on the left; all supported related addresses group centrally; service cards cluster beside their supported addresses on the right. If a service spans multiple IPs, show it **once**, place it using a stable visual tie-break/median, and draw all independently typed endpoint paths. Service-only and IP-only nodes remain visible without invented upstream links.
- Distinguish ARP/NS/NA from DNS-SD edges and **fresh** from **stale** DNS-SD endpoint paths. Every visible connector can be selected by pointer or Enter/Space and opens the exact chain in Evidence, preserving original names, ports, TTLs, timestamps and sources.
- Optional compact IP-card indicator like "2 advertised services" is **derived presentation only** and does not replace independent service nodes.
- Preserve original Services sidebar, DNS-SD-to-ARP/NDP inspection shortcuts, unlinked/DAD view, accessibility, no HTML injection, single local fetch, and mode-specific camera/manual-order retention.

**Exit criterion:** real Safari can drill from a MAC claim through the same address node to a service advertisement, selecting each edge to reveal its *independent* provenance.

### Stage 4: Final tests, UX acceptance and merge

- M5 focused tests, full `pytest` and Safari live capture; starting observed baseline **895 passed (4.60 s)**. Do not predict the new total.
- Validate all three map modes, keyboard controls, zoom/pan, drag-to-reorder, independent layouts/selection, live revision refresh, stale styling and explicit empty/truncated states.
- Controlled synthetic fixture must reproduce the full PTR/SRV/A and PTR/SRV/AAAA chains, parallel edges, missing links, expiry, cross-response joins, explicit retractions and scope conflicts.
- Capture only sanitized counts and nonidentifying synthetic examples in the repository. No raw PCAP, private IP/MAC/service names or user screen recording is committed.
- Use separate reviewable PRs for Stage 1 projector, Stage 2 adapter and Stage 3 UI (or split Stage 3 further if needed). User reviews and squash-merges each stage. Final acceptance documentation closes the milestone.

## Things deliberately deferred

- Verified service health, TCP connect checks, HTTP requests, port scanning, active probes or reachability indicators.
- Full DNS response history, service ownership, automatic device identity, DNS TXT payload rendering, Bonjour browsing commands or other unobserved packets.
- Physical network topology, default-gateway rooting, LLDP/CDP, 3D cyberspace and "quickhack" execution.
- Collapsing IP/MAC/service chain into one guessed physical host node.

## First development checkpoint

Start with a small **synthetic evidence fixture**: one scope/interface, a valid PTR/SRV/A and PTR/SRV/AAAA chain resolving to one service instance, one ARP IPv4 sender claim, one NDP option-backed IPv6 claim and an additional service-only address. Before writing UI code, confirm all node identities, edge kinds, independent record provenance and expiry behavior in a pure projection unit test.

**Planning-only PR:** this document is a proposal/implementation handoff, not a claim that Phase 1N-M code or tests have been completed.
