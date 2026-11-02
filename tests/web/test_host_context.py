"""Host context is a separate optional read-only live graph supplement."""

from novxis.web.graph_data import DEFAULT_FIXTURE, build_arp_graph
from novxis.web.live_state import LiveARPGraphState


def _context(interface):
    return {
        "schema_version": 1,
        "origin": "local-os",
        "interface": interface,
        "status": "reported",
        "ipv4_addresses": [
            {"address": "192.0.2.34", "prefix_length": 24,
             "network": "192.0.2.0/24"},
        ],
        "default_route": {
            "gateway": "198.51.100.1", "interface": "en0",
            "scope": "os-selected-ipv4-default",
        },
    }


def test_session_collects_host_context_once_without_changing_arp_evidence():
    calls = []
    def collector(interface):
        calls.append(interface)
        return _context(interface)

    state = LiveARPGraphState(context_provider=collector)
    waiting = state.snapshot()
    assert "host_context" not in waiting
    state.ingest({"type": "session", "interface": "en5"})
    snapshot = state.snapshot()
    assert snapshot["host_context"]["interface"] == "en5"
    assert snapshot["host_context"]["default_route"]["interface"] == "en0"
    assert snapshot["claims"] == []
    assert snapshot["nodes"] == []
    assert snapshot["capture_status"] == "capturing"
    assert calls == ["en5"]
    state.ingest({"type": "session", "interface": "en5"})
    assert calls == ["en5"]


def test_context_failure_does_not_terminate_live_capture():
    def fail(_interface):
        raise RuntimeError("secret network error")
    state = LiveARPGraphState(context_provider=fail)
    state.ingest({"type": "session", "interface": "en5"})
    snapshot = state.snapshot()
    assert snapshot["host_context"]["status"] == "unavailable"
    assert "secret" not in str(snapshot)
    assert snapshot["capture_status"] == "capturing"


def test_default_offline_and_in_memory_live_graphs_do_not_inherit_os_context():
    offline = build_arp_graph(DEFAULT_FIXTURE)
    default_live = LiveARPGraphState()
    default_live.ingest({"type": "session", "interface": "fixture"})
    assert "host_context" not in offline
    assert "host_context" not in default_live.snapshot()


def test_host_context_ui_remains_separate_from_svg_and_inspector():
    from importlib import resources

    static = resources.files("novxis.web.static")
    html = static.joinpath("index.html").read_text(encoding="utf-8")
    script = static.joinpath("app.js").read_text(encoding="utf-8")
    styles = static.joinpath("styles.css").read_text(encoding="utf-8")
    assert 'id="host-context"' in html
    assert 'id="host-context-content"' in html
    assert 'hostPanel.hidden = true;' in script
    assert 'context.origin !== "local-os"' in script
    assert "showHostContext(live ? payload.host_context : null)" in script
    assert 'appendDetail("Source", "Local macOS configuration (not packet evidence)"' in script
    assert ".host-context[hidden] { display: none; }" in styles


def test_live_web_cli_only_attaches_context_on_unprivileged_consumer_side():
    from inspect import getsource
    from novxis.cli import web_live, arp_live_stream

    consumer = getsource(web_live)
    producer = getsource(arp_live_stream)
    assert "context_provider=collect_host_ipv4_context" in consumer
    assert "collect_host_ipv4_context" not in producer
