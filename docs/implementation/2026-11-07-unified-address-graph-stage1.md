# Phase 1N-L Stage 1: Pure Unified Address Evidence Projection

**Date:** 2026-11-07
**Status:** M5 focused/full regression accepted; ready for owner PR review
**Baseline:** 794 passing tests reported on the M5 after Phase 1N-K Stage 3

## Scope delivered

The **pure, renderer-independent** projection in
`novxis/views/unified_address_graph.py` accepts the existing
`ARPBinding` records and Stage 2 option-backed `NDAddressClaim`
records. It requires an explicit `capture_scope` string to distinguish
independent capture sessions, even when their interface names and MACs
match.

It outputs frozen, deterministic `UnifiedAddressGraphSnapshot` data:

- **Nodes:** separate IPv4, IPv6, and interface + capture-scoped
  Ethernet hardware-address evidence nodes.
- **Typed edges:** `arp_sender`, `ndp_ns_source_slla`,
  and `ndp_na_target_tlla`. NS evidence attaches the source
  IPv6; NA evidence attaches the target IPv6, never the Ethernet
  frame sender alone.
- **Provenance:** interface, capture scope, first/last observed
  timestamps, observation count, evidence kind and a stable
  `source_record_key`. This key points to the aggregated
  ARP/NDP state record identity, **not an individual packet**.
  The source models do not provide persistent raw-packet IDs.
- **Ambiguity:** different asserted MACs for one IPv6 address
  remain separate edges; one MAC can be shared between independent
  IPv4 and IPv6 nodes when supported by a claim.
- **Input boundaries:** unlinked NDP evidence (DAD, missing TLLA,
  ambiguous options) is intentionally **not an input**. Only
  Stage 2-validated `NDAddressClaim` instances can form NDP
  edges. Unexpected or malformed claims fail closed.
- **Explicit exclusions:** the existing ARP view can display
  non-Ethernet hardware and non-IPv4 protocol types, but the
  first unified **Ethernet/IPv4/IPv6** projection deliberately
  skips those ARP records and reports the skipped count.

No source-of-truth state machine, network capture, router/gateway
inference, DNS-SD record relation, UI drawing, service ownership,
physical link, or verified device identity is created.

## Capture-scope contract

`capture_scope` is a required, stable identifier assigned by the
caller **per independent capture or replay session**. Interface
alone is insufficient; repeated `en0` and MAC values on another
sensor/session must not merge. Length-prefixed UTF-8 node/edge IDs
include this scope, interface, family and original address bytes.
The graph IDs are for evidence/selection, not host identity.

Use the same `capture_scope` when re-projecting one running session;
use a new value for another independent capture or sensor. The
current Stage 1 function does not mint or persist session IDs.

## Example: typed state to graph (offline, no network request)

~~~python
from novxis.views import project_unified_address_graph

# arp_bindings = ARPStatePipeline().state.arp_bindings
# ndp_claims = NDStatePipeline().state.snapshot().claims
# Both collections must originate in the same capture/replay scope.
snapshot = project_unified_address_graph(
    arp_bindings,
    ndp_claims,
    capture_scope="authorized-capture-session-001",
)
for edge in snapshot.edges:
    print(edge.evidence_kind, edge.first_seen, edge.last_seen)
~~~

This example assumes `arp_bindings` and `ndp_claims` have
already been obtained by the existing pipelines. It does not
implement a new live packet producer or web endpoint.

## Regression coverage

Synthetic tests in `tests/views/test_unified_address_graph.py`
cover the following invariant groups:

1. Shared scoped MAC with independent IPv4/IPv6 nodes and
   protocol-specific edges.
2. Two IPv6 addresses or two NS/NA provenance kinds on the
   same MAC without collapsing their typed evidence.
3. Multiple MAC assertions for one IPv6 address, with neither
   automatically resolving the other.
4. Scope and interface separation (including Unicode/colon
   safety in deterministic length-prefixed IDs).
5. First/last capture timestamps, counts, frozen typed
   snapshots, and references to aggregated source records.
6. Input-order independence, idempotent duplicate records and
   rejection of inconsistent state duplicates.
7. DAD and missing-TLLA unlinked records cannot create edges;
   invalid/ambiguous NDP claims and unsupported Ethernet/ARP
   formats are rejected or explicitly skipped.
8. No device identity, network layout, liveness status, or
   invented NDP TTL is added.

## M5 test handoff

~~~bash
git fetch origin
git switch --track origin/ai/phase1n-l-unified-address-projection-2026-11-07
python -m pytest tests/views/test_unified_address_graph.py -q
python -m pytest
~~~

**M5 acceptance reported on 2026-11-07:**

- Focused: `python -m pytest tests/views/test_unified_address_graph.py -q` → **55 passed in 0.06s**.
- Full: `python -m pytest` → **849 passed in 4.15s** on macOS, Python 3.14.6, pytest 9.1.1.
- Full test growth: **794 → 849**, with no reported failures.

The developer executed both commands on the Stage 1 feature branch.
The results verify the evidence-projection tests and existing
regression suite, **not** a new browser visualization or physical
network validation. Stage 2 and Stage 3 remain deferred.
No private network identifiers or raw captures were committed.

## Deferred stages

**Stage 2:** adapt the pure graph for the local (non-root) web
projection without changing the ARP-only graph schema or
capture pipeline.

**Stage 3:** add an optional **Unified addresses** 2D mode,
preserving canvas pan/zoom, the existing sidebar, independent
IPv6 evidence and edge inspector provenance.

DNS-SD branches, LLDP physical topology, gateway-role overlays,
active probes, compact cards and 3D remain separate milestones.
