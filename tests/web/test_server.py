"""Local preview serves only address-claim JSON and bundled assets."""

import json
from threading import Thread
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
