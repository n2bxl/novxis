# Phase 1N-M Stage 2: Live DNS-SD Service Evidence Graph Adapter

- **Date:** 2026-11-07
- **Status:** Implemented on a draft branch; M5 regressions and live acceptance pending
- **Prerequisites:** Phase 1N-M plan (PR #50) and pure Stage 1 projector (PR #51) merged
- **Observed merged baseline:** 938 passing M5 Python tests in 4.68 s
- **Scope:** Add a bounded, versioned, read-only service graph to the existing
  localhost API. No new packet capture, probe, OS configuration lookup,
  browser graph mode, parser, or endpoint is introduced.

## Implemented

- `novxis/web/dnssd_service_live.py` accepts the existing validated ARP
  bindings, option-backed NDP claim snapshot and bounded PTR-backed
  `LiveMDNSState.snapshot()` data from the same capture interface.
- Reuses the same pure `project_unified_address_graph` and sanitized
  `_validated_claims` conversion used by Stage 1N-L. NS/NA frame source
  addresses, DAD and NAs lacking usable target TLLA cannot become
  hardware-address claims.
- Builds the immutable `DNSSDServiceGraphSnapshot` from Stage 1 and
  serializes each node/edge as JSON-safe, versioned dictionaries. All
  PTR/SRV/A/AAAA record chain details are retained in separate nested
  objects for the future Evidence Inspector.
- `LiveARPGraphState.snapshot()` adds `unified_service_graph` only for
  an authorized combined ARP+mDNS+NDP session, alongside the existing
  `nodes`/`claims`, `unified_address_graph`, `mdns_evidence`,
  `ndp_evidence`, host/subnet context and their original revisions.
- The existing `/api/graph` localhost endpoint serves this additive
  field; the browser currently ignores it. Legacy ARP-only, ARP+mDNS,
  and offline replay responses do not gain the new field.

## Service graph JSON contract

`unified_service_graph` contains:

- `schema_version: 1`, `origin: "passive-arp-ndp-mdns"`,
  `capture_scope`, `interface`, `revision` and `as_of`.
- `nodes`: existing IPv4/IPv6/hardware address node shapes and IDs,
  plus `kind: "dnssd_service"` nodes with service type, instance and
  separately inspectable `ptr` metadata.
- `edges`: the **unchanged** serialized ARP/NDP evidence edge shapes
  and one or more typed `dnssd_advertised_endpoint` paths with
  `source` (IP node ID), `target` (service ID), `ptr`, `srv`,
  `address`, `path_fresh`, interface and capture scope.
- Each PTR/SRV/A/AAAA record object contains a stable aggregated
  `source_record_key`, timestamp, TTL and freshness, with
  same- or cross-response provenance for SRV and address records.
  The SRV object includes hostname and advertised port.
- Transparent coverage markers: `mdns_truncated`,
  `omitted_mdns_advertisements`, `skipped_unsupported_addresses`,
  `arp_bindings_truncated`, `omitted_ndp_claims`,
  `omitted_ndp_unlinked` and overall `truncated`.
- `limitation` explicitly states that an advertisement is not
  verified reachability, an open port, a service owner or a physical
  network connection.

## Independent service semantic revision

The service graph's `revision` changes only when its actual
**address + DNS-SD service evidence semantics** change: node/edge
content, source record provenance/epochs/counts, TTL component
freshness, source truncation or ARP/NDP omitted-claim status. The
continuously advancing `as_of` snapshot time alone does **not** change
the revision.

- The existing top-level `revision`, ARP `graph_revision` and
  `unified_address_graph.revision` are left on their own historical
  update policies. Service TTL expiry without new packets does not
  trigger ARP-only or Unified addresses re-layout.
- Initial empty combined snapshot starts at service revision 0.
- Service signature/revision updates are made under the same live
  state lock as the source snapshots, so concurrent reads cannot
  assign semantic revisions based on mixed capture snapshots.
- An explicitly retracted cross-response reconciliation is removed,
  not resurrected as a stale path. A retained path that expires only
  by TTL remains with `path_fresh: false`.
- Legacy `mdns_evidence` cross-reference shortcuts continue to be
  built separately as before; the new graph does not alter them.

## M5 test commands

From the feature branch:

```bash
git fetch origin
git switch --track origin/ai/phase1n-m-stage2-live-service-graph-2026-11-07
python -m pytest tests/web/test_dnssd_service_live.py \
  tests/views/test_dnssd_service_graph.py \
  tests/web/test_unified_live.py \
  tests/web/test_mdns_live.py \
  tests/web/test_mdns_service_links.py -q
python -m pytest
```

**No Python tests have yet been reported on the new branch.**
The preceding 938-test result is the already merged Stage 1 baseline,
not a claim of Stage 2 test success.

## Optional authorized live acceptance (same local toolchain)

Start a finite, authorized combined session from the M5:

```bash
sudo .venv/bin/python -m novxis.cli.network_live_stream en0 \
  --count 2000 --timeout 120 \
  | .venv/bin/python -m novxis.cli.web_live
```

With that local server still running, inspect only safe aggregate
metadata (avoid posting private address/service values):

```bash
python - <<'PY'
import json
from urllib.request import urlopen
with urlopen("http://127.0.0.1:8765/api/graph") as r:
    data = json.load(r)
g = data.get("unified_service_graph")
if g is None:
    print("No combined service graph for this capture session")
else:
    print("schema/origin:", g["schema_version"], g["origin"])
    print("interface:", g["interface"], "revision:", g["revision"])
    print("nodes:", len(g["nodes"]), "edges:", len(g["edges"]))
    print("service instances:", sum(n["kind"] == "dnssd_service"
                                    for n in g["nodes"]))
    print("advertised endpoint paths:",
          sum(e["kind"] == "dnssd_advertised_endpoint"
              for e in g["edges"]))
    print("truncated:", g["truncated"])
PY
```

An empty service graph is valid if no PTR-backed service chain was
observed in the finite capture; do not infer absence of services from
the local network. The server remains loopback-only.

## Synthetic acceptance cases

- Empty combined session and original ARP-only/ARP+mDNS/offline behavior.
- One same-scope ARP + NDP + PTR/SRV/A/AAAA snapshot shares exact
  IPv4/IPv6/hardware identity without new inferred edges.
- DNS-SD-only address nodes have no MAC relation until independent
  ARP/NDP evidence appears.
- PTR-only and missing-address paths show service nodes without
  invented endpoint lines.
- Every endpoint edge independently retains the complete typed
  record chain, source, TTL, count, port, timestamps and freshness.
- Expired PTR changes service revision and `path_fresh` while leaving
  original ARP and unified revisions intact.
- mDNS query counters with no service semantics do not reset
  service layout/camera through a new graph revision.
- Accepted cross-response joins appear, explicit reconciliation
  retractions remove them, bad/wrong-interface data is rejected.
- Separate capture scopes remain distinct; NDP unlinked observations
  do not become hardware claims.
- When the bounded NDP receiver sees a 129th distinct claim (128-claim
  default), it evicts the oldest retained claim, increments its omission
  counter and updates the address and service views. The test must
  expect one old IPv6 node/edge removed and the newest retained claim
  replacing it, not frozen node/edge lists. The PTR-only service
  remains unlinked to all of these IPv6 hardware observations.
- Existing localhost API returns JSON-serializable additive metadata,
  and the same NDJSON producer still drives the entire service view.

## Next stages

Stage 3: introduce the separately switchable **Services** mode,
left-to-right **HARDWARE → IPv4/IPv6 → SERVICES**, with independently
selectable and drillable ARP/NDP/DNS-SD edges, preserving the existing
two maps.

Stage 4: live Safari interaction, cross-mode camera/rearrangement
preservation, stale link UX, complete regressions and acceptance.

No raw captures, private network addresses, local service names or
user screen recordings belong in this repository document.
