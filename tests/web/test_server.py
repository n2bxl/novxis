"""Local preview serves only address-claim JSON and bundled assets."""

import json
from threading import Thread
from importlib import resources
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from novxis.cli.web_preview import build_parser
from novxis.web.server import create_server


@pytest.fixture()
def server():
    graph = {
        "schema_version": 1,
        "source": {"capture_name": "sanitized.pcap"},
        "nodes": [],
        "claims": [],
    }
    instance = create_server(graph, port=0)
    worker = Thread(target=instance.serve_forever, daemon=True)
    worker.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        worker.join(timeout=2)


def _url(instance, path):
    return f"http://127.0.0.1:{instance.server_port}{path}"


def test_graph_api_returns_read_only_json_with_local_security_headers(server):
    with urlopen(_url(server, "/api/graph")) as response:
        result = json.load(response)
        assert response.status == 200
        assert result["schema_version"] == 1
        assert response.headers["Cache-Control"] == "no-store"
        assert "default-src 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["Access-Control-Allow-Origin"] is None


@pytest.mark.parametrize("path", ["/", "/app.js", "/styles.css"])
def test_static_assets_serve_without_external_dependencies(server, path):
    with urlopen(_url(server, path)) as response:
        body = response.read()
        assert response.status == 200
        assert body
        assert b"https://cdn" not in body


def test_unlisted_routes_are_rejected(server):
    with pytest.raises(HTTPError) as exc:
        urlopen(_url(server, "/../../private.pcap"))
    assert exc.value.code == 404


def test_foreign_host_headers_are_rejected(server):
    request = Request(_url(server, "/api/graph"), headers={"Host": "attacker.invalid"})
    with pytest.raises(HTTPError) as exc:
        urlopen(request)
    assert exc.value.code == 403


def test_cli_default_uses_sanitized_fixture():
    args = build_parser().parse_args([])
    assert args.pcap.name == "arp_phase0_sanitized.pcap"
    assert args.port == 8765


def test_canvas_pan_prevents_safari_svg_text_selection():
    """Only the SVG viewport suppresses selection, not the inspector."""
    static = resources.files("novxis.web.static")
    styles = static.joinpath("styles.css").read_text(encoding="utf-8")
    script = static.joinpath("app.js").read_text(encoding="utf-8")
    assert "#map, #map *" in styles
    assert "-webkit-user-select: none" in styles
    assert "user-select: none" in styles
    assert 'svg.addEventListener("selectstart"' in script
    assert 'svg.addEventListener("dragstart"' in script
    start = script.index('svg.addEventListener("pointerdown"')
    end = script.index('svg.addEventListener("pointermove"', start)
    pan_handler = script[start:end]
    assert 'event.target.closest("[data-node-id]")' in pan_handler
    assert "event.preventDefault();" in pan_handler
    assert ".inspector" not in styles[styles.index("#map, #map *"):styles.index("#map.panning")]


def test_mouse_wheel_zoom_is_bound_to_entire_canvas_not_only_svg_shapes():
    """Safari must zoom when hovering over blank map space as well as nodes."""
    static = resources.files("novxis.web.static")
    script = static.joinpath("app.js").read_text(encoding="utf-8")
    assert 'document.querySelector(".canvas-wrap")' in script
    assert 'canvas.addEventListener("wheel"' in script
    assert 'svg.addEventListener("wheel"' not in script
    assert 'zoomAt(event.deltaY < 0' in script
    assert 'svgPoint(event)' in script
    assert '{ passive: false }' in script


def test_click_node_selects_but_dragging_node_pans():
    """Selection follows a stationary pointerup, not a click after panning."""
    static = resources.files("novxis.web.static")
    script = static.joinpath("app.js").read_text(encoding="utf-8")
    styles = static.joinpath("styles.css").read_text(encoding="utf-8")
    assert 'const PAN_THRESHOLD = 5' in script
    assert 'group.addEventListener("click"' not in script
    assert 'if (event.button !== 0 || dragging) return;' in script
    assert 'const targetNode = event.target.closest("[data-node-id]");' in script
    assert 'Math.hypot(dx, dy) < PAN_THRESHOLD' in script
    assert 'if (event.type === "pointerup" && !gesture.moved && gesture.nodeId)' in script
    assert 'setSelected(gesture.nodeId)' in script
    assert '#map.panning .map-node' in styles
