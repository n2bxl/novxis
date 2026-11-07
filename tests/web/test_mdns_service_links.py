"""Services UI shows only same-message target evidence and scoped ARP jumps."""

from importlib import resources


def _assets():
    static = resources.files("novxis.web.static")
    return (
        static.joinpath("app.js").read_text(encoding="utf-8"),
        static.joinpath("styles.css").read_text(encoding="utf-8"),
    )


def test_services_show_independent_ptr_srv_and_a_aaaa_freshness():
    script, css = _assets()
    assert 'const targets = Array.isArray(item.targets) ? item.targets : []' in script
    assert 'target.path_fresh ? " · PTR+SRV fresh"' in script
    assert 'address.path_fresh ? " · chain fresh"' in script
    assert 'target.ttl_seconds' in script
    assert 'address.ttl' in script
    assert 'address.family === 4 ? "A " : "AAAA "' in script
    assert '.mdns-target-claim' in css
    assert '.mdns-target-address' in css


def test_exact_arp_address_link_navigates_to_existing_evidence_page():
    script, _ = _assets()
    assert 'typeof address.arp_node_id === "string"' in script
    assert 'graph.nodes.some((node) => node.id === address.arp_node_id)' in script
    assert 'selectedId = address.arp_node_id;' in script
    assert 'selectSidebarTab("evidence");' in script
    assert 'No same-interface ARP address match' in script
    assert 'No SRV target was observed alongside this PTR' in script


def test_service_relationships_are_text_only_and_no_new_capture_api():
    script, _ = _assets()
    segment = script[script.index('function showMDNSEvidence('):
                     script.index('function clearInspector(')]
    assert '.textContent =' in segment
    assert '.innerHTML' not in segment
    assert 'fetch(' not in segment
    assert 'getUserMedia' not in segment
    assert 'not a verified' in segment
    assert 'renderGraph()' in segment  # existing ARP node selection only
    assert 'document.createElement("line")' not in segment
