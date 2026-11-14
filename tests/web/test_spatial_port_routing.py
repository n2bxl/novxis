"""Stage 4B.2: spatial evidence connector port ordering contracts.

These source-level contracts guard the Services SVG routing behavior without
requiring Node, a browser, capture privileges, or packet fixtures. Safari
acceptance remains necessary to assess actual Bézier path readability.
"""
from importlib import resources


def script():
    return resources.files("novxis.web.static").joinpath("app.js").read_text(
        encoding="utf-8"
    )


def ports_block():
    js = script()
    renderer = js.split("function renderServicesCanvas(", 1)[1].split(
        "function renderGraph(", 1
    )[0]
    return renderer.split("const ports = new Map();", 1)[1].split(
        "for (const edge of snapshot.edges) {\n    const sourceNode", 1
    )[0]


def test_both_card_faces_project_opposite_endpoint_vertical_centers():
    route = ports_block()
    assert "const oppositeY = new Map();" in route
    assert "const fromId = dnssd ? edge.source : edge.target;" in route
    assert "const toId = dnssd ? edge.target : edge.source;" in route
    assert "const fromPosition = locations.get(fromId);" in route
    assert "const toPosition = locations.get(toId);" in route
    assert "const targetCenter = toPosition.y +" in route
    assert "(dnssd ? serviceCardHeight(toNode) / 2 : 32)" in route
    assert "const sourceCenter = fromPosition.y + 32;" in route
    assert '["out:" + fromId, targetCenter]' in route
    assert '["in:" + toId, sourceCenter]' in route


def test_shared_ports_sort_by_remote_height_with_stable_evidence_id_ties():
    route = ports_block()
    assert "ports.get(key).push(edge.id);" in route
    assert "oppositeY.set(key + \"|\" + edge.id, remoteY);" in route
    assert "for (const [key, ids] of ports)" in route
    assert "ids.sort((a, b) =>" in route
    assert "oppositeY.get(key + \"|\" + a) - oppositeY.get(key + \"|\" + b)" in route
    assert "a.localeCompare(b)" in route
    assert "for (const ids of ports.values()) ids.sort();" not in route


def test_airplay_convergence_fixture_reverses_avoidable_crossings():
    # Three IPs converge on one service; edge IDs deliberately disagree with
    # the source IPs' physical top-to-bottom positions.
    paths = [("a-lower", 380), ("m-middle", 245), ("z-upper", 110)]
    before = sorted(paths, key=lambda item: item[0])
    after = sorted(paths, key=lambda item: (item[1], item[0]))
    assert [edge for edge, _ in before] == ["a-lower", "m-middle", "z-upper"]
    assert [edge for edge, _ in after] == ["z-upper", "m-middle", "a-lower"]
    # On a common destination card, ordering by source height avoids these
    # three inversions at the arrival ports.
    assert sum(before[i][1] > before[j][1]
               for i in range(3) for j in range(i + 1, 3)) == 3
    assert sum(after[i][1] > after[j][1]
               for i in range(3) for j in range(i + 1, 3)) == 0


def test_same_ip_multiple_services_and_parallel_claims_have_stable_ports():
    # A single IP advertising upper/lower services uses destination center
    # order at its outbound ports, not the evidence ID ordering.
    paths = [("a-lower", 410), ("z-upper", 115), ("m-middle", 240)]
    assert [edge for edge, _ in sorted(paths, key=lambda item: (item[1], item[0]))] == [
        "z-upper", "m-middle", "a-lower"
    ]
    # Identical source/destination pairs use evidence IDs as tie breakers.
    parallels = [("edge-z", 180), ("edge-a", 180), ("edge-m", 180)]
    assert [edge for edge, _ in sorted(parallels, key=lambda item: (item[1], item[0]))] == [
        "edge-a", "edge-m", "edge-z"
    ]
    route = ports_block()
    assert "Math.min(16, 52 / (ids.length - 1))" in route
    assert "ids.indexOf(edgeId)" in route


def test_routing_changes_only_ports_not_layout_or_record_metadata():
    js = script()
    route = ports_block()
    layout = js.split("function layoutServiceGraph(", 1)[1].split(
        "function preserveManualOrder(", 1
    )[0]
    for excluded in (
        "locations.set(", "reorderNode(", "manualOrderForView(",
        "serviceManualOrders", "camera =", "resetView(", "stageHeight =",
    ):
        assert excluded not in route
    assert "const services = preserveManualOrder(\"services\", automaticServices);" in layout
    assert "const center = (reference.top + reference.bottom) / 2;" in layout
    assert "serviceExtraGap" not in route
    renderer = js.split("function renderServicesCanvas(", 1)[1].split(
        "function renderGraph(", 1
    )[0]
    assert 'dnssd && !edge.path_fresh ? " stale-path" : ""' in renderer
    assert '"data-edge-id": edge.id' in renderer
    assert '"map-edge-hit"' in renderer
    assert 'setSelectedEdge(edge.id);' in renderer
