"""Live-only subnet evidence lens integrates without touching ARP claims."""

from importlib import resources
from ipaddress import IPv4Address

from novxis.web.graph_data import DEFAULT_FIXTURE, build_arp_graph
from novxis.web.live_state import LiveARPGraphState


def _context(interface: str) -> dict:
    return {
        "schema_version": 1,
        "origin": "local-os",
        "interface": interface,
        "status": "reported",
        "observed_at": "2026-11-02T20:00:00Z",
        "ipv4_addresses": [{
            "address": "192.0.2.34",
            "prefix_length": 24,
            "network": "192.0.2.0/24",
        }],
        "default_route": {
            "gateway": "192.0.2.1", "interface": interface,
            "scope": "os-selected-ipv4-default",
        },
    }


def _binding(ip: str, count: int = 1) -> dict:
    return {
        "type": "binding",
        "interface": "en0",
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "protocol_hex": IPv4Address(ip).packed.hex(),
        "hardware_hex": "020000000009",
        "first_seen": "100",
        "last_seen": "100" if count == 1 else "101",
        "observation_count": count,
    }


def test_live_lens_updates_from_the_same_arp_evidence_as_graph():
    state = LiveARPGraphState(context_provider=_context)
    initial = state.snapshot()
    assert "subnet_evidence" not in initial
    state.ingest({"type": "session", "interface": "en0"})
    before = state.snapshot()
    assert before["subnet_evidence"]["reported_prefix_count"] == 1
    assert before["subnet_evidence"]["observed_ipv4_address_count"] == 0
    assert before["claims"] == []
    state.ingest(_binding("192.0.2.1"))
    after = state.snapshot()
    assert after["revision"] > before["revision"]
    assert after["subnet_evidence"]["observed_ipv4_address_count"] == 1
    assert after["subnet_evidence"]["configured_prefixes"][0][
        "observed_address_count"
    ] == 1
    assert after["subnet_evidence"]["gateway_address_cross_reference"] is not None
    ids = {node["id"] for node in after["nodes"]}
    assert after["subnet_evidence"]["gateway_address_cross_reference"][
        "node_id"
    ] in ids
    assert len(after["claims"]) == 1
    assert len(after["nodes"]) == 2
    state.ingest(_binding("192.0.2.1", count=2))
    refreshed = state.snapshot()
    assert refreshed["claims"][0]["observation_count"] == 2
    assert refreshed["subnet_evidence"]["observed_ipv4_address_count"] == 1


def test_no_configured_context_keeps_arp_graph_unmodified():
    state = LiveARPGraphState()
    state.ingest({"type": "session", "interface": "en0"})
    state.ingest(_binding("192.0.2.1"))
    snapshot = state.snapshot()
    assert "host_context" not in snapshot
    assert "subnet_evidence" not in snapshot
    assert len(snapshot["nodes"]) == 2
    assert len(snapshot["claims"]) == 1


def test_offline_fixture_never_includes_current_host_prefix():
    snapshot = build_arp_graph(DEFAULT_FIXTURE)
    assert "host_context" not in snapshot
    assert "subnet_evidence" not in snapshot
    assert len(snapshot["nodes"]) == 12
    assert len(snapshot["claims"]) == 6


def test_subnet_panel_reads_lens_without_new_capture_apis():
    static = resources.files("novxis.web.static")
    html = static.joinpath("index.html").read_text(encoding="utf-8")
    script = static.joinpath("app.js").read_text(encoding="utf-8")
    css = static.joinpath("styles.css").read_text(encoding="utf-8")
    assert 'id="subnet-evidence"' in html
    assert 'id="subnet-evidence-content"' in html
    assert 'function showSubnetEvidence(lens)' in script
    assert 'lens.origin !== "derived-comparison"' in script
    assert "showSubnetEvidence(live ? payload.subnet_evidence : null)" in script
    assert 'subnetPanel.hidden = true;' in script
    assert '.subnet-evidence[hidden] { display: none; }' in css
    assert 'selectedId = item.node_id;' in script
    assert "openSubnetGroups = new Set()" in script
    assert 'details.open = openSubnetGroups.has(groupKey)' in script
    assert 'details.addEventListener("toggle"' in script
    assert '"Observed IPv4 without a reported prefix"' in script
    assert 'setSelected(item.node_id)' not in script
    assert 'graph.subnet_evidence.gateway_address_cross_reference' in script
    assert 'fetch("/api/graph"' in script
    assert 'fetch("/api/subnet"' not in script
