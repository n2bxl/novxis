# Phase 1N-L Stage 3: Unified Address 2D Visualization

**Date:** 2026-11-07
**Status:** Full M5 regression suite passed and live Safari graph interactions validated; Stage 3 ready for owner review and squash-merge.
**Baseline:** 876 tests passed on the M5 after merged Stage 2 (PR #48).

## Purpose

Render the **existing Stage 2 `unified_address_graph` JSON projection**
in the permanent reference 2D debugger without replacing or
reinterpreting the original ARP-only canvas.

NOVXIS is an **evidence graph**, not a physical network topology.
The interface- and capture-scope-qualified MAC node remains an
address-claim endpoint, **not** a verified host, cable, access point,
network center, gateway or identity record.

## What changed

- An accessible two-button **ARP only / Unified addresses** mode
  selector appears in the map header. **ARP only** remains the
  initial/default mode, including offline replay.
- **Unified addresses** enables only when the local
  `/api/graph` response is from a live ARP session with a
  same-interface, versioned `passive-arp-ndp` projection and
  well-formed top-level node/edge arrays. ARP-only/ARP+mDNS and
  offline sessions leave the mode disabled, with a visible reason.
- A single existing SVG renderer draws IPv4 and IPv6 **separate
  protocol-address nodes** plus interface+capture-scoped hardware
  address nodes. One hardware node may be referenced by both
  protocols when their independent packet claims support it.
  Long IPv6 labels wrap instead of silently truncating the address.
- Visible, typed, individually selectable edges represent
  `arp_sender`, `ndp_ns_source_slla`, and
  `ndp_na_target_tlla`. Each has its own legend treatment.
  A wider transparent pointer target improves interaction, and
  Enter/Space activates a focused edge for keyboard access.
- Selecting an **edge** reveals its source kind, exact IPv4/IPv6
  protocol address, advertised Ethernet address, capture interface,
  capture scope, first/last observed timestamp strings, count and
  aggregated `source_record_key` (not a raw packet ID).
- Selecting a **node** lists its independently observed incident
  edges, each of which can be opened individually in the inspector.
  Evidence strings use DOM `textContent`, never HTML injection.
- The previous ARP-only inspector, gateway-match annotation,
  Subnet, Host, Services and IPv6 sidebar tabs continue to exist.
  DNS-SD-to-ARP navigation returns to the **ARP only** map; IPv6
  DNS-SD navigation continues to open independent NDP evidence,
  not a fabricated service-to-device graph edge.
- Pan/zoom, camera reset, move-node mode, keyboard row
  rearrangement and automatic address arrangement remain
  available. In Unified addresses, **MAC evidence nodes anchor**
  deterministic layout groups: same-MAC IPv4 and IPv6 addresses
  are stacked together, and the MAC card is vertically centered
  beside its observed address group. The original ARP-only layout
  algorithm is unchanged. Manual order, camera and selected
  node/edge state are stored **separately per map mode**.
  Switching modes never changes the producer's observations or
  the semantic graph IDs.
- Live polling still reads only `/api/graph` once per second.
  ARP-only redraws use top-level `graph_revision`, while the
  Unified addresses view uses `unified_address_graph.revision`.
  The visible summary switches immediately and reports the
  correct mode's node/edge counts. The original NDP tab retains
  its unlinked/DAD evidence even when no graph edge exists.

No active probes, new endpoints, web access, remote hosting,
LLDP topology, DNS-SD graph branches, router-root inference,
agent execution, or verified device identity is added.

## MAC-first layout refinement following the private en0 Safari review

The developer reviewed a local, authorized **133-second Safari capture**
showing the Stage 3 graph successfully rendering typed ARP and NDP edges.
At the end, the owner manually rearranged three observed protocol
addresses (one IPv4, two IPv6) adjacent to their shared hardware-address
evidence node. The relationship becomes materially easier to read when
the hardware column, not the lexically sorted IP column, anchors the
automatic layout. No private identifiers, recording or packet data are
committed.

The refined **Unified addresses / Auto arrange** algorithm:

1. Sort scoped MAC evidence nodes deterministically by capture scope,
   interface, MAC bytes and stable node ID, rather than using the mean
   IP-row rank as the MAC's order.
2. For each IP address, inspect **only retained typed Stage 2 edges**
   with matching interface and capture scope. Use observed ARP IPv4
   sender edges or NDP option-backed IPv6 NS/NA edges, never DAD,
   frame-source coincidence, link-local guesswork or DNS name matches.
3. Group observed IPv4 and IPv6 nodes under each MAC in a stable
   family/address order, with IPv4 first. A MAC card is placed beside
   the vertical **center** of its IP cluster. Separate MAC anchors
   receive enough vertical space to avoid overlapping clusters.
4. An IP with multiple legitimately observed MAC associations is shown
   **once**. It receives one deterministic *layout position* using
   the first sorted eligible MAC as a tie-break; **all edges remain
   drawn and inspectable**. This never marks one MAC as the true owner.
5. If an unassociated protocol node or orphan hardware node appears,
   reserve space for it without inventing a relation.
6. Preserve user-controlled per-mode manual order and camera. Reordering
   a MAC in the unified mode moves its cluster in the automatic IP
   ordering unless the user has deliberately rearranged IP addresses.
   Resetting **Auto arrange** clears manual placements only in the
   active map mode. The legacy ARP-only arrangement is unchanged.

The refinement adds four Python source-contract tests to
`tests/web/test_unified_canvas.py` for MAC-first sorting, conflict
handling, vertical centering and ARP-only regression isolation.
A developer-side V8 exercise passed synthetic deterministic-order,
cross-claim, orphan, and manual order cases; a mocked-DOM exercise
rendered six separate nodes and four independent edges, selected an
NS-source claim, then switched back to ARP without losing selection.
**These checks do not replace the M5 Python regression or actual Safari
validation of this follow-up commit.**

The hardware evidence node is a useful visual **anchor**, not a
permanent physical-device record. Randomized/private MAC addresses,
multiple capture scopes and changing evidence must not be fused into
device identity or physical links.

## Tests

New `tests/web/test_unified_canvas.py` protects the renderer
contract, including disabled mode availability, separate view
data sources, typed edge selection and inspector fields, long
IPv6 labels, independent camera/order state, ARP compatibility,
NDP unlinked sidebar, DNS-SD navigation and same-origin-only API.

The change has also passed an isolated JS syntax check and a
mock-DOM interaction smoke check performed during development:
an ARP-only canvas was rendered, Unified addresses was enabled
by a sample same-interface live payload, and selecting a
synthetic NS-source SLLA edge displayed its provenance.
These are **not** a substitute for actual Safari interaction
testing or the M5 Python suite.

### M5 regressions

```bash
git fetch origin
git switch --track origin/ai/phase1n-l-unified-2d-visualization-2026-11-07
python -m pytest tests/web/test_unified_canvas.py \
  tests/web/test_layout_controls.py tests/web/test_ndp_sidebar.py \
  tests/web/test_server.py -q
python -m pytest
```

**Post-refinement M5 result (2026-11-07):** `pytest` collected **895** tests and reported **895 passed in 4.57s**, on macOS Python 3.14.6 with pytest 9.1.1. This is 19 additional passing cases over the prior Stage 2 baseline (876). The full suite includes the Stage 3 `tests/web/test_unified_canvas.py` group (19 passing cases).

### Safari acceptance (authorized local capture)

```bash
sudo .venv/bin/python -m novxis.cli.network_live_stream en0 \
  --count 2000 --timeout 120 \
  | .venv/bin/python -m novxis.cli.web_live
```

Use whichever interface is actually being captured (`en0`
Wi-Fi or `en5` Ethernet). Confirm the browser header and
NDP sidebar show the same interface and use the correct
loopback port. The local server remains open after capture
completion until Ctrl+C.

**Manual acceptance checklist**

- [ ] Offline/ARP-only replay: ARP-only mode works, unified mode
      remains disabled, no extra HTTP requests are emitted.
- [ ] Combined live ARP/mDNS/NDP session: unified mode becomes
      available, while original ARP-only nodes/claims stay intact.
- [ ] Switch to Unified: distinct IPv4/IPv6 nodes and scoped MAC
      nodes appear, with ARP/NS/NA edge types and correct legend.
- [ ] Select an IPv6 node and an individual NS/NA edge. Check
      correct source vs target address, metadata, scope, count,
      first/last timestamps and aggregated record key.
- [ ] A unicast NS without usable SLLA, an NA missing TLLA,
      or DAD remains **unlinked**, not a fabricated address edge.
- [ ] Matching ARP and NDP MAC options on one capture interface
      converge on the same *hardware evidence* node without
      claiming one proven physical device.
- [ ] The initial Unified **Auto arrange** stacks same-MAC IPv4/IPv6
      addresses contiguously and vertically centers the MAC card
      beside the cluster; the original ARP-only auto arrangement is unchanged.
- [ ] A synthetic conflicting IPv6-to-multiple-MAC claim, if replayed,
      has a single IP node with all original typed evidence edges,
      not duplicated addresses or an inferred permanent owner.
- [ ] Pan/zoom, keyboard selection, rearrangement and camera
      controls work in **both** modes; switching away/back
      preserves independent arrangements and selection.
- [ ] Capture updates update the active canvas by its own
      revision without resetting the camera; sidebar tabs
      continue to operate independently.
- [ ] DNS-SD 'Inspect independent ARP address' still opens the
      original ARP-only inspector; IPv6 shortcuts continue to
      the NDP sidebar. No DNS-SD service graph links inferred.

Only sanitized aggregate counts and synthetic test data should
be committed in public docs. Do not publish captures, private
service names, or actual IP/MAC addresses.

## Follow-up Safari observation after MAC-first refinement

The developer provided a second authorized private Safari recording on
2026-11-07, after enabling the MAC-anchored layout refinement. The
**Unified addresses** view visibly groups option-backed IPv6 and ARP IPv4
address evidence around their shared interface-scoped hardware node.
The owner confirmed that manually rearranging a hardware-address node
also moves its correlated IP address cluster as a group, and reported
that the revised arrangement is preferable to the prior IP-first sort.

The recording also shows the independent IPv6 sidebar continuing to
display missing-TLLA Neighbor Advertisements as unlinked observations,
rather than inventing hardware-address evidence. This is a **qualitative
Safari acceptance of the new layout and interaction**, not an assertion
that every acceptance checklist case has been executed. The private
recording, MAC/IP identifiers and individual service details are not
committed.

**Follow-up accepted:** After the layout refinement, the developer reported the complete M5 regression suite green (**895/895, 4.57s**) and provided private Safari screenshots showing the same-interface Unified addresses graph plus individually selected ARP and NS source-SLLA edges and their Evidence Inspector provenance. Address/MAC values and screenshots stay private. These observations support owner review, without claiming that every manual checklist item was independently re-executed.


## Live polling status observed in final Safari screenshots

Two private screenshots displayed the status **`Live update unavailable:
Load failed`** while the previously loaded graph and its inspector
remained interactive. Browser-side `loadGraph()` retries
`/api/graph` once per second and retains the last valid snapshot on a
fetch failure. This is consistent with stopping the local server while
the Safari page stays open, but the images alone cannot establish why
the request failed. The operator should confirm the `web_live` process
still listens on the chosen localhost port if this warning occurs during
an intentionally active session. The warning is not evidence of
missing ARP/NDP relationships or a failure of the graph projection.

A minor visual issue remains: the bottom-left navigation hint can
obscure the lowest row of nodes when the vertically stacked graph is
larger than the viewport. Treat hint positioning/canvas scrolling as
follow-up UI polish, not an address-identity or evidence-correlation
change.

## Deferred

- PTR/SRV/A/AAAA service-record graph branches (separate milestone).
- Router/default-gateway role overlays and LLDP-backed physical
  neighbor links (later, evidence-scoped milestones).
- Explicitly authorized active discovery and differentiated
  solicited evidence, compact cards, true 3D cyberspace layout.
