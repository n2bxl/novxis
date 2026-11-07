# Phase 1N-L Stage 2: Unprivileged live Unified Address Graph adapter

- **Date:** 2026-11-07
- **Status:** Implemented on a draft PR; focused and full M5 tests pending
- **Starting regression baseline:** 849 passed on M5 after Stage 1 merged (PR #47)
- **Scope:** A separate JSON-ready evidence graph assembled from existing
  bounded, validated live ARP and NDP metadata, without new capture traffic.

## Design

```text
privileged existing network_live_stream (ARP + mDNS + ICMPv6 NDP)
             |
     bounded sanitized NDJSON (unchanged wire format, MAX_LINE=4096)
             |
     unprivileged LiveARPGraphState, single session/interface
             +-- existing ARP bindings and ARP-only graph (unchanged)
             +-- existing LiveNDPState (validated claims + unlinked)
             |        |
             |        +-- only option-backed, retained NDP claims
             +-- unified_live metadata adapter
                      |
             Stage 1 pure project_unified_address_graph
                      |
            /api/graph["unified_address_graph"] (additive payload)
```

The already-existing receiver maintains strict source validation.
No raw Ethernet frame, packet payload, NDP option bytes, PCAP, elevated
capture context or new network operation enters the web process.

## Runtime semantics

- **Session capture scope:** `LiveARPGraphState` generates one opaque
  local UUID-derived capture scope per state instance. No untrusted
  NDJSON sender supplies or overrides it. Scopes are stable through
  repeated snapshots and distinct between independent live instances.
  The existing capture interface remains a separate key dimension.
- **Existing source records:** Stage 1 takes already-validated
  `ARPBinding` records and `NDAddressClaim` metadata. The NDP adapter
  reconstructs a typed *metadata-only* `NDAddressClaim`, with
  `latest_observation=None` intentionally signifying that raw packet
  provenance did not cross the privileged/unprivileged boundary.
  The projection reads only address, kind, scope and observation
  summary fields and never dereferences that optional-free reference.
- **Edge types:** `arp_sender`, `ndp_ns_source_slla`,
  `ndp_na_target_tlla`. No NA without TLLA, DAD probe or NS target
  without an SLLA creates a graph edge.
- **Independent revision:** `unified_address_graph.revision`
  increments on accepted ARP binding events and accepted
  option-backed NDP claims. Missing-option/DAD observations and NDP
  decode errors do not create graph edges or increment this revision.
  The original top-level `graph_revision` remains ARP-only.
- **Payload placement:** for opt-in triple-protocol live sessions
  (`["arp","mdns","ndp"]`), the existing `/api/graph` response gains
  a **separate** `unified_address_graph` field. The original
  top-level `schema_version=1`, `nodes`, `claims`,
  `graph_revision`, `mdns_evidence`, `ndp_evidence`,
  `host_context` and `subnet_evidence` retain their semantics.
  Legacy ARP-only and ARP+mDNS sessions, plus offline replay,
  do **not** add this field.
- **JSON contract:** `schema_version=1`, `origin=passive-arp-ndp`,
  `capture_scope`, `interface`, `revision`, `nodes` and `edges`
  with deterministic IDs, normalized hex and human-readable IP/MAC,
  typed edge source and target, `source_record_key`, first/last
  capture time strings, counts, and separately identified truncation
  information. `source_record_key` references an *aggregated source
  state record*, **not an original raw packet**.
- **Retention and honesty:** the graph uses only retained ARP and NDP
  claims; it does not reconstruct overwritten ARP mappings or dropped
  NDP evidence. Existing ARP and NDP caps remain authoritative.
  Expose `arp_bindings_truncated`, `omitted_ndp_claims`,
  `omitted_ndp_unlinked` and a combined `truncated` indicator.
  Unsupported ARP address families/types stay visible in the
  original ARP-only view, but are counted as skipped in this
  Ethernet/IPv4/IPv6 projection.

## Tests and acceptance

The new `tests/web/test_unified_live.py` covers:

1. One ARP IPv4 and one NDP IPv6 joining through the same scoped MAC
   evidence node without modifying top-level ARP graph state.
2. Distinct NS **source** and NA **target** edges; multiple IPv6
   addresses and contradictory MAC claims kept independently.
3. DAD and NA without TLLA remaining unlinked, no fallback to the
   Ethernet frame source MAC.
4. Repeated claim timestamps and counts, current ARP MAC replacement,
   session identity and capture interface isolation.
5. ARP-only and ARP+mDNS legacy compatibility and offline replay.
6. Rejected NDP validation, NDP decode errors, bounded ARP/NDP caps,
   truncation metadata and exact-scope validation.
7. JSON serializability, local `/api/graph` HTTP response, and
   existing finite NDJSON pipe ingestion without changing the producer.

On the M5:

```bash
git fetch origin
git switch --track origin/ai/phase1n-l-live-unified-graph-adapter-2026-11-07

python -m pytest tests/web/test_unified_live.py tests/web/test_ndp_live.py \
  tests/web/test_live_arp.py tests/web/test_server.py -q
python -m pytest
```

Expected full-suite baseline is **849 prior passing tests plus Stage 2
tests**, but no new total is claimed before execution on the M5.

The Stage 2 payload can be inspected without changing the Safari UI:

```bash
sudo .venv/bin/python -m novxis.cli.network_live_stream en0 \
  --count 2000 --timeout 120 \
  | .venv/bin/python -m novxis.cli.web_live
```

Open `http://127.0.0.1:8765/api/graph` locally and find
`unified_address_graph`. Stage 2 still renders the **old ARP-only
canvas**; the new node/edge visualization and edge inspector belong
to Stage 3. Any live capture observations should remain private.
No packet contents or personal IP/MAC values belong in public PR docs.

## Initial private en5 live observation (2026-11-07)

The developer supplied a private Safari screen recording of an
authorized combined capture on Ethernet interface `en5`. The recording
shows an **ended** ARP + mDNS + NDP capture and confirms that the
existing browser workflow remains usable; it does **not** display
the new `unified_address_graph` JSON payload or prove its edge
serialization yet. No recording, raw capture, device identifiers,
IP addresses, MAC addresses, or private service names are committed.

Sanitized visible totals from the recording:

- **ARP:** 26 legacy ARP address nodes, 13 sender claims, 61 binding
  updates; original ARP canvas, selection and Inspector still present.
- **mDNS:** 134 messages; the Services sidebar continues to distinguish
  address matches from records lacking same-interface evidence.
- **NDP:** 24 NS/NA messages (**16 NS**, **8 NA**, of which **2** are
  DAD probes); **4 retained option-backed** claims,
  **7 unlinked observations**, **0 multiple-LLA address conflicts**
  reported by the sidebar.
- A single MAC appeared independently in an IPv4 ARP sender claim
  and an IPv6 NS source-SLLA observation on `en5`.
  A DAD target mentioning a different IPv6 address remained
  an *unlinked tentative observation*, not an IPv6-to-MAC claim.

These are **UI field observations**, not a new test-suite result
and not proof of physical-host identity. The recording does not
show the new JSON graph field, cross-session UUID isolation,
truncation branches, synthetic error handling or the full
Python regression suite.

**Still pending for Stage 2 acceptance:** focused and full
M5 pytest results, plus inspection of `/api/graph`'s additive
`unified_address_graph` field (node/edge types and counts).
Keep the PR in draft until those are confirmed.

## Deferred

- Visual unified canvas mode, selection and edge inspector (Stage 3).
- DNS-SD graph branches, LLDP physical topology, gateway-role inference,
  active probes and automated endpoint identity.
