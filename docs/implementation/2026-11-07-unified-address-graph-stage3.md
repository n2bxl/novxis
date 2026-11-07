# Phase 1N-L Stage 3: Unified Address 2D Visualization

**Date:** 2026-11-07
**Status:** Implemented on an unmerged feature branch; M5 Python and
Safari UI acceptance are pending.
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
  available. Manual order, camera and selected node/edge state
  are stored **separately per map mode**. Switching modes never
  changes the producer's observations or the semantic graph IDs.
- Live polling still reads only `/api/graph` once per second.
  ARP-only redraws use top-level `graph_revision`, while the
  Unified addresses view uses `unified_address_graph.revision`.
  The visible summary switches immediately and reports the
  correct mode's node/edge counts. The original NDP tab retains
  its unlinked/DAD evidence even when no graph edge exists.

No active probes, new endpoints, web access, remote hosting,
LLDP topology, DNS-SD graph branches, router-root inference,
agent execution, or verified device identity is added.

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

Prior full baseline was **876**, not a claim of Stage 3 test
results. This branch adds new Python assertions, so the expected
new total is higher but must come from the actual run.

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

## Deferred

- PTR/SRV/A/AAAA service-record graph branches (separate milestone).
- Router/default-gateway role overlays and LLDP-backed physical
  neighbor links (later, evidence-scoped milestones).
- Explicitly authorized active discovery and differentiated
  solicited evidence, compact cards, true 3D cyberspace layout.
