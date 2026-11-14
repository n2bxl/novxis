"""Phase 1N-M Stage 3: permanent, separately selectable Services 2D map.

These are static browser-contract checks, not a substitute for live Safari
interaction. No packet capture, network calls or DOM packages are required.
"""

from importlib import resources
from pathlib import Path


def assets():
    root = resources.files("novxis.web.static")
    return (
        root.joinpath("index.html").read_text(encoding="utf-8"),
        root.joinpath("app.js").read_text(encoding="utf-8"),
        root.joinpath("styles.css").read_text(encoding="utf-8"),
    )


def section(script: str, start: str, end: str) -> str:
    return script[script.index(start):script.index(end, script.index(start))]


def test_three_opt_in_map_views_keep_arp_as_default():
    html, js, css = assets()
    assert 'id="map-mode-arp" type="button" aria-pressed="true"' in html
    assert 'id="map-mode-unified" type="button" aria-pressed="false"' in html
    assert 'id="map-mode-services" type="button" aria-pressed="false"' in html
    assert 'disabled title="Requires a live ARP + mDNS + NDP service graph"' in html
    assert 'id="services-legend"' in html
    assert 'id="unified-legend"' in html
    assert 'id="arp-legend"' in html
    assert 'mapModeServices.addEventListener("click", () => switchMapMode("services"));' in js
    assert 'let activeMapMode = "arp";' in js
    assert '.map-view-switch button:disabled' in css


def test_services_requires_same_live_versioned_service_and_address_scope():
    _, js, _ = assets()
    view = section(js, "function updateMapModes(", 'mapModeArp.addEventListener("click"')
    for condition in (
        'payload.mode === "live-arp"',
        'unified?.schema_version === 1',
        'unified?.origin === "passive-arp-ndp"',
        'unified.interface === payload.source?.interface',
        'services?.schema_version === 1',
        'services?.origin === "passive-arp-ndp-mdns"',
        'services.interface === payload.source?.interface',
        'services.capture_scope === unified.capture_scope',
        'Array.isArray(services.nodes)',
        'Array.isArray(services.edges)',
        'mapModeServices.disabled = !serviceAvailable;',
    ):
        assert condition in view
    assert 'if (!serviceAvailable && activeMapMode === "services") {' in view
    assert 'mapSelections.services = { node: selectedId, edge: selectedEdgeId };' in view
    assert 'activeMapMode = "arp";' in view


def test_camera_selection_and_rearrangement_state_is_per_map():
    _, js, _ = assets()
    for required in (
        'services: { node: null, edge: null },',
        'services: { x: 0, y: 0, scale: 1 },',
        'const serviceManualOrders = { protocol: null, hardware: null, services: null };',
        'if (activeMapMode === "services") return serviceManualOrders;',
        'mapSelections[activeMapMode] = { node: selectedId, edge: selectedEdgeId };',
        'mapCameras[activeMapMode] = { ...camera };',
        'camera = { ...mapCameras[mode] };',
        'if (mode === "services" && mapModeServices.disabled) return;',
        'serviceManualOrders.protocol = null;',
        'serviceManualOrders.hardware = null;',
        'serviceManualOrders.services = null;',
        'manualOrderForView()[kind] = updated;',
    ):
        assert required in js
    assert 'const unifiedManualOrders = { protocol: null, hardware: null };' in js
    assert 'const manualOrders = { protocol: null, hardware: null };' in js


def test_old_two_view_renderers_retained_and_service_view_is_additive():
    _, js, _ = assets()
    assert 'return activeMapMode === "unified" ? graph?.unified_address_graph : graph;' in js
    assert 'if (activeMapMode === "services") return graph?.unified_service_graph;' in js
    assert 'if (activeMapMode === "unified") return layoutUnifiedGraph(active);' in js
    assert 'if (activeMapMode === "services") return layoutServiceGraph(active);' in js
    assert 'function computeAutoOrders(snapshot)' in js
    assert 'function computeUnifiedAutoOrders(snapshot)' in js
    assert 'const edges = activeMapMode === "unified" ? active.edges : graph.claims;' in js
    assert 'for (const claim of edges)' in js
    assert 'function renderServicesCanvas(snapshot, locations)' in js
    assert 'renderServicesCanvas(active, locations);' in js
    assert 'function showUnifiedInspector()' in js
    assert 'function showServiceInspector()' in js
    assert 'if (activeMapMode === "unified") {' in section(
        js, "function showInspector()", "function setSelected(",
    )


def test_hardware_ip_service_columns_have_separate_graph_node_types():
    _, js, css = assets()
    view = section(js, "function layoutServiceGraph(", "function preserveManualOrder(")
    for required in (
        'const automatic = computeUnifiedAutoOrders(snapshot);',
        'const hardware = preserveManualOrder("hardware", automatic.hardware);',
        'const protocol = preserveManualOrder("protocol", defaultProtocol);',
        'node.kind === "dnssd_service"',
        'edge.kind !== "dnssd_advertised_endpoint"',
        'const services = preserveManualOrder("services", automaticServices);',
        'orderedByKind = { protocol, hardware, services };',
        'const locations = new Map();',
        'const span = Math.max(count, 1);',
        'addressSlots.push(row + index);',
        'for (const ip of automatic.ungrouped) addressSlots.push(row++);',
        'serviceColumns.hardware',
        'serviceColumns.protocol',
        'serviceColumns.services',
    ):
        assert required in view
    assert 'HARDWARE ADDRESSES' in js
    assert 'IPV4 / IPV6 ADDRESSES' in js
    assert 'ADVERTISED SERVICES' in js
    assert '.map-node.dnssd_service rect' in css


def test_services_are_compact_and_sorted_by_first_supporting_ip():
    _, js, _ = assets()
    view = section(js, "function layoutServiceGraph(", "function preserveManualOrder(")
    for expected in (
        'serviceRanks.get(service.id).add(protocolRank.get(ip.id));',
        'return ranks.size ? Math.min(...ranks) : Number.POSITIVE_INFINITY;',
        'firstRank(a) - firstRank(b)',
        'const services = preserveManualOrder("services", automaticServices);',
        'const SERVICE_CARD_GAP = 12;',
        'let lastServiceBottom = ROW_START - SERVICE_CARD_GAP;',
        'const y = lastServiceBottom + SERVICE_CARD_GAP;',
        'lastServiceBottom = y + serviceCardHeight(service);',
        'renderedBottom + 175',
    ):
        assert expected in view
    assert 'serviceSlots' not in view
    assert 'preferredServiceSlot' not in view
    assert 'lastServiceSlot' not in view

def test_service_only_ip_cannot_gain_a_mac_edge_through_frontend_layout():
    _, js, _ = assets()
    arrange = section(js, "function computeUnifiedAutoOrders(", "function layoutUnifiedGraph(")
    # Only original, typed ARP and option-backed NDP relationships select
    # presentation MAC anchors. DNS-SD paths cannot become these edges.
    assert 'edge.kind === "arp_sender"' in arrange
    assert 'edge.kind === "ndp_ns_source_slla"' in arrange
    assert 'edge.kind === "ndp_na_target_tlla"' in arrange
    assert 'else ungrouped.push(ip);' in arrange
    service = section(js, "function layoutServiceGraph(", "function preserveManualOrder(")
    assert 'const automatic = computeUnifiedAutoOrders(snapshot);' in service
    assert 'edge.kind !== "dnssd_advertised_endpoint"' in service
    assert 'serviceRanks.get(service.id).add(protocolRank.get(ip.id));' in service


def test_service_node_renders_full_accessible_name_with_wrapped_label():
    _, js, css = assets()
    view = section(js, "function renderServicesCanvas(", "function renderGraph(")
    for required in (
        'node.kind === "dnssd_service"',
        '"aria-label": service',
        'const fullName = String(node.instance);',
        'const nameLines = serviceNameLines(fullName);',
        'nameLines.forEach((line, index) =>',
        'const title = makeSVG("title");',
        'title.textContent = fullName + " (" + node.service_type + ")";',
        '"service-name-text"',
        '"service-type-text"',
        '"service-status-text"',
        '"data-node-id": node.id',
        'setSelected(node.id);',
        'reorderNode(kind, node.id,',
    ):
        assert required in view
    assert '.map-node.dnssd_service .service-name-text' in css
    assert 'role: "button", tabindex: "0"' in view


def test_every_service_and_original_arp_ndp_edge_remains_interactive():
    _, js, css = assets()
    view = section(js, "function renderServicesCanvas(", "function renderGraph(")
    for required in (
        'for (const edge of snapshot.edges) {',
        'edge.kind === "dnssd_advertised_endpoint"',
        '"map-edge evidence-" + edge.kind',
        '"data-edge-id": edge.id',
        '"map-edge-hit"',
        'setSelectedEdge(edge.id);',
        'if (event.key === "Enter" || event.key === " ")',
        'viewport.append(group);',
        'const targetEdge = event.target.closest("[data-edge-id]");',
    ):
        assert required in js
    assert '"data-edge-id": edge.id' in view
    assert 'group.addEventListener("keydown"' in view
    assert 'edge.srv.port' in view
    assert 'edge.address.observed_at' in view
    assert '.map-edge-hit' in css
    assert 'pointer-events: stroke;' in css


def test_parallel_and_convergent_paths_have_distinct_port_offsets_and_hit_targets():
    _, js, css = assets()
    view = section(js, "function renderServicesCanvas(", "function renderGraph(")
    assert 'const parallels = new Map();' in view
    assert 'parallels.get(pair).push(edge.id);' in view
    assert 'for (const ids of parallels.values()) ids.sort();' in view
    assert 'const ports = new Map();' in view
    assert 'const fromId = dnssd ? edge.source : edge.target;' in view
    assert 'const toId = dnssd ? edge.target : edge.source;' in view
    assert 'ports.get(key).push(edge.id);' in view
    assert 'const portOffset = (key, edgeId) => {' in view
    assert 'Math.min(16, 52 / (ids.length - 1))' in view
    assert 'from.y + 32 + portOffset("out:" + fromId, edge.id)' in view
    assert 'to.y + (dnssd ? serviceCardHeight(targetNode) / 2 : 32)' in view
    assert 'const hasSharedEndpoint =' in view
    assert 'ids.length > 1 || hasSharedEndpoint' in view
    assert '" services-parallel-hit"' in view
    assert '.map-edge-hit.services-parallel-hit' in css


def test_dns_sd_edge_inspector_preserves_all_three_record_chains():
    _, js, _ = assets()
    view = section(js, "function showDNSRecordDetails(", "function showInspector()")
    for required in (
        'record.source_record_key',
        'record.service_type',
        'record.instance',
        'record.observation_count',
        'record.owner_name',
        'record.target_name',
        'record.port',
        'record.address',
        'record.ttl_seconds',
        'record.observed_at',
        'record.fresh',
        'record.source',
        'showDNSRecordDetails("PTR: advertised service instance", edge.ptr, "ptr");',
        'showDNSRecordDetails("SRV: advertised target and port", edge.srv, "srv");',
        'edge.address, "address"',
        'appendDetail("Capture scope", edge.capture_scope, inspector);',
        'appendDetail("Capture interface", edge.interface, inspector);',
        'snapshot.as_of',
        'expired.push("PTR")',
        'expired.push("SRV")',
        'expired.push("A/AAAA")',
        'showUnifiedInspector();',
        'button.addEventListener("click", () => setSelectedEdge(item.id));',
    ):
        assert required in view
    assert '.innerHTML' not in view


def test_service_nodes_and_service_only_ip_support_click_through_to_edges():
    _, js, _ = assets()
    view = section(js, "function showServiceInspector()", "function showInspector()")
    assert 'node.kind === "dnssd_service"' in view
    assert 'showDNSRecordDetails("PTR: retained service advertisement", node.ptr, "ptr");' in view
    assert 'snapshot.edges.filter((item) =>' in view
    assert 'item.kind === "dnssd_advertised_endpoint"' in view
    assert 'button.addEventListener("click", () => setSelectedEdge(item.id));' in view
    assert 'No complete retained PTR → SRV → A/AAAA endpoint' in view
    assert 'No retained same-scope option-backed ARP/NDP association' in view


def test_expired_evidence_and_empty_services_are_clearly_distinguished():
    html, js, css = assets()
    assert 'id="services-legend"' in html
    assert 'TTL expired' in js
    assert 'dnssd && !edge.path_fresh ? " stale-path"' in js
    assert 'service && !node.ptr?.fresh ? " stale-ptr"' in js
    assert 'No PTR-backed advertisements in this capture' in js
    assert 'services.truncated ? " · CAP REACHED (incomplete evidence)"' in js
    assert '.map-edge.evidence-dnssd_advertised_endpoint.stale-path' in css
    assert '.map-node.dnssd_service.stale-ptr' in css
    assert '.legend-line.stale-claim' in css


def test_service_revision_drives_render_without_arp_only_graph_refresh():
    _, js, _ = assets()
    view = js[js.index("async function loadGraph()"):]
    for required in (
        'payload.unified_service_graph?.revision !== lastGraphRevision',
        'const serviceRevisionChanged = live && activeMapMode === "services"',
        'payload.unified_service_graph.revision',
        'payload.unified_address_graph.revision',
        'payload.graph_revision ?? payload.revision',
        'lastGraphRevision !== graphRevision',
        'if (redrawGraph) renderGraph();',
        'lastRenderedMapMode !== activeMapMode',
        'fetch("/api/graph", { cache: "no-store" })',
    ):
        assert required in view
    assert 'camera = {' not in view


def test_services_sidebar_and_old_ndp_inspector_remain_separate():
    html, js, _ = assets()
    assert 'id="tab-services" role="tab"' in html
    assert 'id="panel-services" class="sidebar-page"' in html
    assert 'id="tab-neighbors" role="tab"' in html
    assert 'if (activeMapMode === "services") switchMapMode("arp");' in js
    assert 'if (activeMapMode === "unified") switchMapMode("arp");' in js
    assert 'selectedNdpAddress = address.ndp_address;' in js
    assert 'selectSidebarTab("neighbors");' in js
    assert 'Cross-response joins require fresh matching DNS owner names' in js


def test_all_retained_services_and_valid_evidence_edges_render_without_display_cap():
    _, js, _ = assets()
    renderer = section(js, "function renderServicesCanvas(", "function renderGraph(")
    assert "for (const edge of snapshot.edges) {" in renderer
    assert "for (const node of snapshot.nodes) {" in renderer
    assert 'const position = locations.get(node.id);' in renderer
    assert 'viewport.append(group);' in renderer
    assert 'const service = node.kind === "dnssd_service";' in renderer
    assert 'edge.kind === "dnssd_advertised_endpoint"' in renderer
    # DOM rendering has no arbitrary slice() or max-card cap.
    assert 'snapshot.nodes.slice(' not in renderer
    assert 'snapshot.edges.slice(' not in renderer
    layout = section(js, "function layoutServiceGraph(", "function preserveManualOrder(")
    assert 'services.forEach((service) => {' in layout
    assert 'locations.set(service.id, { x: serviceColumns.services, y });' in layout
    assert 'stageHeight = Math.max(' in layout
    assert 'renderedBottom + 175' in layout
    assert 'svg.setAttribute("viewBox", "0 0 " + serviceColumns.viewWidth + " " + stageHeight);' in layout


def test_service_map_explains_offscreen_rows_and_identifies_missing_evidence():
    _, js, _ = assets()
    assert 'Reset view frames the visible evidence' in js
    assert 'Fit the currently rendered evidence into the map viewport' in js
    assert 'const bounds = viewport.getBBox();' in js
    live = js[js.index("async function loadGraph()"):]
    for name in (
        'services.omitted_mdns_advertisements',
        'services.omitted_ndp_claims',
        'services.omitted_ndp_unlinked',
        'services.arp_bindings_truncated',
    ):
        assert name in live
    assert 'CAP REACHED (incomplete evidence)' in live


def test_stage_three_adds_no_network_access_or_new_privilege():
    html, js, _ = assets()
    assert js.count('fetch("/api/graph"') == 1
    assert "WebSocket" not in js
    assert "getUserMedia" not in js
    assert ".innerHTML" not in js
    assert 'src="/app.js"' in html
    server = (Path(__file__).parents[2] / "novxis" / "web" /
              "server.py").read_text(encoding="utf-8")
    assert '"/api/graph"' in server
    assert 'ThreadingHTTPServer(("127.0.0.1", port)' in server
