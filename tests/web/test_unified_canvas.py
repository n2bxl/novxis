"""Phase 1N-L Stage 3: permanent ARP map + opt-in unified 2D graph.

The UI is intentionally static, dependency-free JS/SVG. These source-
contract tests prevent accidental changes to capture, selection, and
accessibility invariants; the M5 Safari interaction remains a separate
manual acceptance requirement.
"""

from importlib import resources
from pathlib import Path
import re

import pytest


def assets():
    root = resources.files("novxis.web.static")
    return tuple(root.joinpath(name).read_text(encoding="utf-8")
                 for name in ("index.html", "app.js", "styles.css"))


def section(script, start, end):
    return script[script.index(start):script.index(end, script.index(start))]


def test_map_mode_controls_are_accessible_and_unified_disabled_until_live_ndp():
    html, js, css = assets()
    assert 'id="map-mode-arp" type="button" aria-pressed="true"' in html
    assert 'id="map-mode-unified" type="button" aria-pressed="false"' in html
    assert 'disabled title="Requires a live ARP + mDNS + NDP capture"' in html
    assert 'role="group" aria-label="Address map view"' in html
    assert 'mapModeArp.addEventListener("click"' in js
    assert 'mapModeUnified.addEventListener("click"' in js
    assert '.map-view-switch button:disabled' in css
    assert 'mapModeUnified.disabled = !available;' in js


def test_unified_mode_requires_a_valid_local_live_graph_payload():
    _, js, _ = assets()
    view = section(js, "function updateMapModes(", 'mapModeArp.addEventListener("click"')
    for boundary in (
        'payload.mode === "live-arp"',
        "unified?.schema_version === 1",
        'unified?.origin === "passive-arp-ndp"',
        "unified.interface === payload.source?.interface",
        "Array.isArray(unified.nodes)",
        "Array.isArray(unified.edges)",
    ):
        assert boundary in view
    assert 'activeMapMode = "arp";' in view
    assert "mapSelections.arp.node" in view


def test_old_arp_nodes_claims_and_inspector_stay_independent():
    _, js, _ = assets()
    assert 'let activeMapMode = "arp";' in js
    assert 'return activeMapMode === "unified" ? graph?.unified_address_graph : graph;' in js
    assert 'const edges = activeMapMode === "unified" ? active.edges : graph.claims;' in js
    assert 'for (const node of active.nodes)' in js
    inspector = section(js, "function showInspector()", "function setSelected(")
    assert 'if (activeMapMode === "unified") {' in inspector
    assert 'showUnifiedInspector();' in inspector
    assert 'graph.nodes.find((item) => item.id === selectedId)' in inspector
    assert 'graph.claims.filter((claim) =>' in inspector


def test_ipv4_and_ipv6_get_separate_address_nodes_and_hardware_is_reused():
    _, js, css = assets()
    assert 'node.kind === "ipv4" || node.kind === "ipv6"' in js
    assert 'node.kind === "hardware"' in js
    assert re.search(
        r'activeMapMode\s*===\s*"unified"\s*\?\s*'
        r'"IPV4 / IPV6 ADDRESSES"\s*:\s*"PROTOCOL ADDRESSES"',
        js,
    )
    assert "node.kind === \"ipv6\" && node.display_address.length > 28" in js
    assert 'node.display_address.slice(0, splitAt)' in js
    assert 'node.display_address.slice(splitAt)' in js
    assert ".map-node.ipv6 rect" in css
    assert '.legend-dot.ipv6' in css


def test_edges_are_clickable_and_keyboard_selectable_without_arp_regression():
    html, js, css = assets()
    assert 'id="map"' in html
    assert 'id="viewport"' in html
    assert '"data-edge-id": claim.id' in js
    assert 'role: "button"' in js
    assert 'tabindex: "0"' in js
    assert 'class: "map-edge-hit"' in js
    assert 'setSelectedEdge(claim.id);' in js
    assert 'const targetEdge = event.target.closest("[data-edge-id]");' in js
    assert 'setSelectedEdge(gesture.edgeId);' in js
    assert 'event.key === "Enter" || event.key === " "' in js
    assert '.map-edge-hit' in css
    assert 'pointer-events: stroke;' in css
    assert 'else {\n      viewport.append(path);' in js


@pytest.mark.parametrize("kind,description", [
    ("arp_sender", "ARP IPv4 sender"),
    ("ndp_ns_source_slla", "NS source SLLA"),
    ("ndp_na_target_tlla", "NA target TLLA"),
])
def test_unified_edge_inspector_preserves_provenance_kind(kind, description):
    _, js, _ = assets()
    assert kind + ': "' + description + '"' in js


def test_inspector_exposes_original_metadata_not_claimed_device_identity():
    _, js, _ = assets()
    view = section(js, "function showUnifiedInspector()", "function showInspector()")
    for item in (
        '"Capture interface"',
        '"Capture scope"',
        '"First observed (Unix seconds)"',
        '"Last observed (Unix seconds)"',
        '"Observation count"',
        '"Aggregated source record key"',
        '"Advertised Ethernet address"',
    ):
        assert item in view
    assert "edge.source_record_key" in view
    assert "not a raw packet" in view
    assert "not verified physical-device identities" in view
    assert ".innerHTML" not in view
    assert "textContent" in view


def test_node_selection_can_open_an_individual_typed_edge():
    _, js, css = assets()
    view = section(js, "function showUnifiedInspector()", "function showInspector()")
    assert 'snapshot.edges.filter((item) =>' in view
    assert 'button.addEventListener("click", () => setSelectedEdge(item.id));' in view
    assert "className = \"claim-card unified-edge-card\";" in view
    assert ".unified-edge-card" in css
    assert "selectedEdgeId = selectedEdgeId === id ? null : id;" in js


def test_view_switch_preserves_separate_manual_arrangements_and_cameras():
    _, js, _ = assets()
    assert "const unifiedManualOrders = { protocol: null, hardware: null };" in js
    assert 'return activeMapMode === "unified" ? unifiedManualOrders : manualOrders;' in js
    assert "const mapCameras = {" in js
    assert "const mapSelections = {" in js
    assert "mapCameras[activeMapMode] = { ...camera };" in js
    assert "mapSelections[activeMapMode] = { node: selectedId, edge: selectedEdgeId };" in js
    assert "camera = { ...mapCameras[mode] };" in js
    assert "manualOrderForView()[kind] = updated;" in js
    assert "unifiedManualOrders.protocol = null;" in js
    assert "manualOrders.protocol = null;" in js


def test_live_polling_uses_per_mode_revisions_and_retains_camera():
    _, js, _ = assets()
    view = js[js.index("async function loadGraph()"):]
    assert 'const graphRevision = live' in view
    assert 'activeMapMode === "unified"' in view
    assert 'payload.unified_address_graph.revision' in view
    assert 'payload.graph_revision ?? payload.revision' in view
    assert 'lastGraphRevision !== graphRevision' in view
    assert 'lastRenderedMapMode !== activeMapMode' in view
    assert 'if (redrawGraph) renderGraph();' in view
    assert 'lastRevision !== payload.revision' in view
    assert "camera = {" not in view
    assert 'fetch("/api/graph", { cache: "no-store" })' in view


def test_dad_and_unlinked_ipv6_remain_in_separate_sidebar_view():
    _, js, _ = assets()
    ndp = section(js, "function showNDPEvidence(", "function showMDNSEvidence(")
    assert '"NS source SLLA claim"' in ndp
    assert '"NA target TLLA claim"' in ndp
    assert "DAD is tentative" in ndp
    assert "No NDP freshness TTL is inferred" in ndp
    assert 'selectedNdpAddress = null;' in ndp
    assert "renderGraph()" not in ndp


def test_existing_mdns_arp_navigation_selects_arp_map_even_when_in_unified():
    _, js, _ = assets()
    mdns = section(js, "function showMDNSEvidence(", "function clearInspector(")
    assert 'if (activeMapMode === "unified") switchMapMode("arp");' in mdns
    assert 'selectedId = address.arp_node_id;' in mdns
    assert 'selectedNdpAddress = address.ndp_address;' in mdns
    assert 'selectSidebarTab("neighbors");' in mdns


def test_no_new_network_privileges_api_routes_or_dependency_requirements():
    html, js, _ = assets()
    assert js.count('fetch("/api/graph"') == 1
    assert "getUserMedia" not in js
    assert "WebSocket" not in js
    assert ".innerHTML" not in js
    assert 'src="/app.js"' in html
    source = Path(__file__).parents[2] / "novxis" / "web" / "server.py"
    server = source.read_text(encoding="utf-8")
    assert '"127.0.0.1"' in server
    assert '"/api/graph"' in server
    assert '"/api/unified"' not in server


def test_unified_auto_arrangement_uses_mac_anchors_not_ip_lexical_ranks():
    _, js, _ = assets()
    unified = section(js, "function computeUnifiedAutoOrders(",
                      "function preserveManualOrder(")
    # A separate algorithm preserves the legacy ARP-only behavior.
    assert 'function computeAutoOrders(snapshot)' in js
    assert 'function computeUnifiedAutoOrders(snapshot)' in unified
    assert 'node.kind === "hardware"' in unified
    assert 'node.kind === "ipv4" || node.kind === "ipv6"' in unified
    assert 'a.capture_scope.localeCompare(b.capture_scope)' in unified
    assert 'a.interface.localeCompare(b.interface)' in unified
    assert 'a.address_hex.localeCompare(b.address_hex)' in unified
    assert 'const groups = new Map(' in unified
    assert 'groups.get(anchor.id).push(ip);' in unified
    assert 'else ungrouped.push(ip);' in unified


def test_unified_multiple_mac_claims_keep_all_edges_but_one_ip_node():
    _, js, _ = assets()
    view = section(js, "function computeUnifiedAutoOrders(",
                   "function preserveManualOrder(")
    assert 'const candidates = new Map(' in view
    assert 'new Set()' in view
    assert 'const anchor = hardware.find(' in view
    assert 'ip.capture_scope !== mac.capture_scope' in view
    assert 'ip.interface !== mac.interface' in view
    assert 'edge.interface !== ip.interface' in view
    assert 'edge.capture_scope !== ip.capture_scope' in view
    assert 'edge.kind === "arp_sender"' in view
    assert 'edge.kind === "ndp_ns_source_slla"' in view
    assert 'edge.kind === "ndp_na_target_tlla"' in view
    assert 'snapshot.edges' in view
    # Rendering still walks the original edges, not a projected
    # one-MAC-per-IP grouping structure.
    assert 'const edges = activeMapMode === "unified" ? active.edges : graph.claims;' in js
    assert 'for (const claim of edges)' in js


def test_unified_mac_card_center_is_mean_of_its_cluster_rows():
    _, js, _ = assets()
    view = section(js, "function layoutUnifiedGraph(", "function preserveManualOrder(")
    assert 'const automatic = computeUnifiedAutoOrders(snapshot);' in view
    assert 'const hardware = preserveManualOrder("hardware", automatic.hardware);' in view
    assert 'hardware.flatMap((mac) =>' in view
    assert 'const protocol = preserveManualOrder("protocol", defaultProtocol);' in view
    assert 'const span = Math.max(count, 1);' in view
    assert '(row + (span - 1) / 2) * ROW_STEP' in view
    assert 'addressSlots.push(row + index);' in view
    assert 'for (const ip of automatic.ungrouped) addressSlots.push(row++);' in view
    assert 'stageHeight = Math.max(620,' in view
    assert 'return locations;' in view


def test_unified_layout_does_not_change_arp_only_auto_arrangement():
    _, js, _ = assets()
    layout = section(js, "function layoutGraph()", "function renderGraph()")
    assert 'if (activeMapMode === "unified") return layoutUnifiedGraph(active);' in layout
    assert 'const automatic = computeAutoOrders(active);' in layout
    assert 'protocol: preserveManualOrder("protocol", automatic.protocol)' in layout
    assert 'hardware: preserveManualOrder("hardware", automatic.hardware)' in layout
    assert 'manualOrderForView()[kind] = updated;' in js
    assert 'manualOrders.protocol = null;' in js
    assert 'unifiedManualOrders.protocol = null;' in js
    assert 'Group IPv4 and IPv6 claims around MAC evidence anchors' in js
