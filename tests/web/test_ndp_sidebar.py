"""Stage 3 browser integration keeps IPv6 claims out of ARP graph layout."""

from importlib import resources


def assets():
    root = resources.files("novxis.web.static")
    return tuple(root.joinpath(name).read_text(encoding="utf-8")
                 for name in ("index.html", "app.js", "styles.css"))


def test_ipv6_tab_is_accessible_and_offline_disabled():
    html, js, css = assets()
    assert 'id="tab-neighbors" role="tab"' in html
    assert 'aria-controls="panel-neighbors"' in html
    assert 'id="panel-neighbors" class="sidebar-page" role="tabpanel"' in html
    assert 'aria-labelledby="tab-neighbors"' in html
    assert 'id="ndp-evidence-content"' in html
    assert 'neighbors: live && payload.ndp_evidence?.origin === "ndp-observation"' in js
    assert 'sidebarTabs[name].button.disabled = !enabled;' in js
    assert 'showNDPEvidence(live ? payload.ndp_evidence : null);' in js
    assert '.ndp-evidence[hidden] { display: none; }' in css


def test_ipv6_view_shows_provenance_and_uncertainty_without_graph_edges():
    _, js, css = assets()
    view = js[js.index("function showNDPEvidence("):
              js.index("function showMDNSEvidence(")]
    assert 'item.kind === "ns_source_slla"' in view
    assert '"NS source SLLA claim"' in view
    assert '"NA target TLLA claim"' in view
    assert '"not a target-MAC association"' in view or "not a target-MAC association" in view
    assert "DAD is tentative" in view
    assert "No NDP freshness TTL is inferred" in view
    assert "document.createElement(\"article\")" in view
    assert ".textContent =" in view
    assert ".innerHTML" not in view
    assert "renderGraph()" not in view
    assert ".ndp-evidence-item" in css


def test_aaaa_jumps_only_to_existing_scoped_ndp_evidence():
    _, js, _ = assets()
    view = js[js.index("function showMDNSEvidence("):
              js.index("function clearInspector(")]
    assert 'address.family === 6 && typeof address.ndp_address === "string"' in view
    assert 'graph?.ndp_evidence?.interface === graph?.mdns_evidence?.interface' in view
    assert 'item.address === address.ndp_address' in view
    assert 'selectedNdpAddress = address.ndp_address;' in view
    assert 'showNDPEvidence(graph.ndp_evidence);' in view
    assert 'selectSidebarTab("neighbors");' in view
    assert '"No same-interface option-backed NDP address match"' in view
    assert '"Inspect independent IPv6 neighbor evidence"' in view
    assert 'address.family === 4 ? "A " : "AAAA "' in view
    assert 'selectedId = address.arp_node_id;' in view  # old IPv4 behavior retained
    assert "document.createElement(\"line\")" not in view


def test_one_second_refresh_preserves_arp_camera_and_separate_ndp_selection():
    _, js, _ = assets()
    assert "let selectedNdpAddress = null;" in js
    assert 'if (redrawGraph) renderGraph();' in js
    assert 'lastGraphRevision !== graphRevision' in js
    assert 'showNDPEvidence(live ? payload.ndp_evidence : null);' in js
    assert "if (!available[activeSidebarTab]) activeSidebarTab = \"evidence\";" in js
    view = js[js.index("function showNDPEvidence("):
              js.index("function showMDNSEvidence(")]
    assert 'selectedNdpAddress === null' in view
    assert 'selectedNdpAddress = null;' in view


def test_live_capture_filter_and_protocol_optin_are_explicit():
    from inspect import getsource
    from novxis.cli.network_live_stream import main
    source = getsource(main)
    assert 'bpf_filter="arp or udp port 5353 or icmp6"' in source
    assert '"protocols": ["arp", "mdns", "ndp"]' in source
    assert "provider.start(" in source
    assert 'emit({"type": "completed"})' in source


def test_no_new_web_api_or_auto_device_fusion():
    _, js, _ = assets()
    assert 'fetch("/api/ndp"' not in js
    assert 'fetch("/api/graph"' in js
    view = js[js.index("function showNDPEvidence("):
              js.index("function showMDNSEvidence(")]
    assert "getUserMedia" not in view and "WebSocket" not in view
