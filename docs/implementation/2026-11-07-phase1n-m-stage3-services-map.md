# Phase 1N-M Stage 3: Three-column Services evidence map

- **Date:** 2026-11-07
- **Status:** Implemented on feature branch; focused and full M5 regressions
  and live Safari acceptance pending
- **Prerequisites:** Phase 1N-M Stage 1 pure projector and Stage 2 local
  `unified_service_graph` JSON merged into `main`
- **Accepted Stage 2 merged baseline (M5):** 966 passing tests in 5.23 s
- **Scope:** Browser-only three-mode visualization, service card layout,
  selectable typed DNS-SD endpoint connectors and complete Evidence
  Inspector drill-down. No capture, decoder, backend, API or privilege change.

## Three independent map modes

| Top-of-map selector | Semantic data | Presentation |
| --- | --- | --- |
| **ARP only** (default) | Existing ARP sender claims | Original two-column ARP map; unchanged |
| **Unified addresses** | `unified_address_graph` | Original MAC-first IPv4/IPv6 + hardware nodes; unchanged |
| **Services** | `unified_service_graph` | **HARDWARE ADDRESSES → IPv4 / IPv6 ADDRESSES → ADVERTISED SERVICES** |

**Services** enables only for a live, versioned
`passive-arp-ndp-mdns` graph with the same interface and capture scope as
the accepted Unified graph. An empty authorized service projection is
still available and explicitly says that no PTR-backed advertisements
were retained during this capture. Offline replay and legacy sessions
cannot turn on Services, even when previous capture state was visible.

The existing **Services sidebar tab** is independent of the new top-of-map
**Services visualization mode**. No links or functionality were removed
from the sidebar.

## Layout and presentation

- The Services renderer is separate from the ARP-only and Unified
  address renderers; their existing SVG paths, node order, camera and
  evidence semantics have not been replaced.
- Addresses and MACs reuse identical typed node IDs from the Stage 1N-L
  graph. Existing ARP/NS-source-SLLA/NA-target-TLLA edges remain visible
  and selectable. A hardware box represents an address-claim endpoint,
  **not** an established physical host or a topological parent.
- Services appear as individual `dnssd_service` boxes on the right.
  Each is keyed by its actual Stage 2 ID and retains the advertised
  instance, type and PTR freshness. Gold (`#af9600`) provides a
  dedicated service visual cue.
- A service box appears **once**, even when several A/AAAA addresses or
  different SRV paths support independently inspectable connectors.
- Existing MAC-first grouping places IPv4/IPv6 evidence centrally;
  service cards are ordered and automatically positioned near the
  mean row of the **address nodes actually supported by DNS-SD
  endpoint edges**. This is only presentation, not service ownership.
  Services with no complete endpoint paths remain visible.
- DNS-SD-only IPs appear without fabricated hardware edges. When
  several MACs claim one IP, the visual MAC anchor is only a
  deterministic layout choice; **all** source edges are still drawn.
- Automatic arrangement may shift service rows when incoming evidence
  changes, while manual ordering remains a per-view overlay. Each
  map retains independent camera, selection and manual column orders.
  **Auto arrange** clears only the current map's manual orders.
- Complete service instance names are available in the SVG
  accessible label, SVG title tooltip, and Evidence Inspector. A
  visibly ellipsized card label does not silently change its identity.
- Parallel paths between the same two boxes are visually offset by
  distinct slots and receive narrower, independently selectable
  pointer hit targets. They are also individually keyboard selectable
  and listed as distinct buttons in the Evidence Inspector.

## Every line is inspectable evidence

Click or keyboard-select **each individual connector** (Tab and
Enter/Space). In Services mode:

1. **ARP / NDP edge:** opens the **existing Unified address claim
   inspector** with its type, source/target address, scope, timestamps,
   observation count and aggregated evidence key. No NDP TTL invented.
2. **DNS-SD advertised endpoint edge:** opens a new full provenance
   inspector for the retained **PTR → SRV → A/AAAA chain**, displaying
   three distinct source-record sections:
   - **PTR:** advertised service type/instance, capture time,
     observation count, TTL, record freshness and source key
   - **SRV:** target hostname, advertised port, capture time,
     TTL, record freshness, same- or cross-response provenance and key
   - **A/AAAA:** record family, advertised IP, owner hostname, capture
     time, TTL, freshness, same- or cross-response provenance and key
3. The edge inspector also displays interface, capture scope, complete
   path ID, snapshot `as_of` time, combined path freshness and any
   expired component(s).
4. Selecting a **service node** displays its PTR evidence and buttons
   to inspect every supported endpoint path. A PTR-only service has an
   explicit "no complete retained endpoint path" message.
5. Selecting an **IP or hardware node** displays its independent
   supporting typed edges. An advertised-only IP has an explicit
   "no retained independent ARP/NDP MAC association" notice.

Retained expired path evidence remains selectable and is drawn
**dashed**. An expired PTR-only service card also has a dashed outline.
Reconciliation retraction removes a formerly accepted path when it is
absent from the live model; the renderer never re-joins DNS records.

**Never interpret an advertised service or endpoint path as proof of an
open TCP port, a reachable service, an assigned host IP, a physical
cable, a stable device identity, or service ownership.** A false
"complete network inventory" inference is explicitly excluded.

## Live updates and UI safety

- Existing `/api/graph` is the **only** fetch call and localhost route
  used by this change. No additional endpoint, privileged capture
  mode, mDNS query, WebSocket, or active scan is added.
- Services uses the Stage 2 `unified_service_graph.revision` to decide
  when to redraw. ARP-only and Unified retain their independent
  existing semantic revisions. The service snapshot's moving
  `as_of` clock alone does not cause needless redraw/reposition.
- Camera, selection and manual ordering persist through fresh live
  updates and mode switches. A selected expired path updates the
  inspector when its evidence changes.
- All network-derived labels are assigned to `textContent`, SVG
  attributes or plain element text. **No `innerHTML`** or executable
  interpolation is introduced.
- Distinct edge hit targets remain keyboard accessible
  (role button, tabindex, Enter/Space activation); the existing
  mouse selection, canvas pan, scroll zoom, node drag and Shift+Arrow
  reorder interactions remain in place.

## Focused M5 regression check

From the Stage 3 feature branch:

```bash
git fetch origin
git switch --track origin/ai/phase1n-m-stage3-services-map-2026-11-07

python -m pytest tests/web/test_services_canvas.py \
  tests/web/test_unified_canvas.py \
  tests/web/test_layout_controls.py \
  tests/web/test_mdns_service_links.py \
  tests/web/test_dnssd_service_live.py -q

python -m pytest
```

`tests/web/test_services_canvas.py` adds 16 static browser-contract
test functions, verifying mode availability, scope matching,
per-view state, layout, distinct edge selection, complete provenance,
TTL appearance, empty state, and no added capture or API surface.

**Validation status:** JavaScript syntax and a synthetic rendered
DOM interaction smoke check passed during implementation. The smoke
check built a MAC, an IPv4 node and a PTR-backed service, rendered both
ARP and DNS-SD edges, selected the DNS-SD edge, checked the displayed
SRV port, and confirmed selection survived a Unified→Services switch.
This is **not** a report of an M5 pytest run or a live Safari acceptance.

## Safari manual acceptance

Start a finite, authorized capture in Terminal 1:

```bash
sudo .venv/bin/python -m novxis.cli.network_live_stream en0 \
  --count 2000 --timeout 120 \
  | .venv/bin/python -m novxis.cli.web_live
```

Open `http://127.0.0.1:8765/` in Safari.

1. Confirm default **ARP only** still shows the original sender
   map and Evidence sidebar. Select a normal ARP node.
2. Switch to **Unified addresses** and check the MAC-first graph,
   ARP and NDP typed connector selection, and keyboard Enter/Space.
3. Switch to **Services** and confirm **Hardware → IP → Services**
   columns. If PTR advertisements are retained, service instances
   appear as separate boxes. The observed counts may differ from
   earlier live sessions due to time, interface and capture scope.
4. Select an ARP/NDP connector in Services mode: the original
   typed address evidence should appear in **Evidence**.
5. Select each DNS-SD connector, including any parallel paths.
   Verify the original **PTR, SRV and A/AAAA** record sections,
   advertised port, source keys, TTLs, timestamps, freshness and
   same/cross-response labels. A service should not be treated
   as a proven listening port.
6. Select a service card and use its supporting-path buttons.
   Verify PTR-only cards remain unlinked when appropriate.
   DNS-SD-only IPs should have no invented MAC line.
7. Pan and zoom; switch between all three modes and back.
   Verify the independent camera, selected node/edge and manual
   arrangement states. In **Rearrange**, drag or use Shift+Arrow.
   **Auto arrange** should reset only the active view.
8. A retained path that ages out of TTL freshness should become
   dashed and report the expired component(s) in Evidence. If the
   capture cannot naturally reproduce expiry, the deterministic
   Stage 1 and Stage 2 tests already cover TTL boundaries.
9. Confirm the existing **Services sidebar tab**, IPv6 neighbor
   sidebar, and service-to-ARP/NDP inspection shortcuts still work.
10. Check the browser console for uncaught JS errors and
    pan/selection issues. Avoid posting private host names,
    MAC/IP addresses or screenshot contents.

Only sanitized counts, anonymized descriptions and test results
belong in the public PR discussion.

## Exit criteria

- Focused and full Python test suites pass on the M5 with the new
  static UI contract tests.
- Live Safari shows independently selectable service node cards,
  actual typed DNS-SD endpoints and individual complete record-chain
  Evidence Inspector panels whenever the authorized capture
  retained corresponding advertisements.
- No regression to ARP-only or Unified maps, keyboard/pan/zoom,
  sidebar navigation, capture scope, or source retention behavior.
- Owner reviews and squash-merges the Stage 3 PR after acceptance.
  Do not start a new protocol, imply physical topology, or merge
  without the owner's review.

Stage 4 completes the milestone's final end-to-end acceptance and
documentation after Stage 3 merges.
