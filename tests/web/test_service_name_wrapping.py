"""Stage 3 source contracts for variable-height Services SVG cards.

Safari rendering and drag/rearrange acceptance remain required separately.
"""
from importlib import resources


def _script():
    return resources.files("novxis.web.static").joinpath("app.js").read_text(
        encoding="utf-8"
    )


def _section(source, start, end):
    return source[source.index(start):source.index(end, source.index(start))]


def test_service_name_wrapper_keeps_all_characters_without_ellipsis():
    script = _script()
    helper = _section(script, "function serviceNameLines(", "function serviceCardHeight(")
    assert "const name = String(instance);" in helper
    assert "const tokens = name.match(" in helper
    assert "Array.from(token)" in helper  # Unicode code points, not JS UTF-16 slices
    assert "line += point;" in helper
    assert "lines.push(line);" in helper
    assert "SERVICE_NAME_CHARS_PER_LINE" in helper
    assert "slice(0, limit" not in helper
    assert '"…"' not in helper


def test_service_rect_label_and_metadata_share_one_height_model():
    script = _script()
    height = _section(script, "function serviceCardHeight(", "function layoutServiceGraph(")
    renderer = _section(script, "function renderServicesCanvas(", "function renderGraph(")
    assert "72 + (serviceNameLines(node.instance).length - 1)" in height
    assert "SERVICE_NAME_LINE_HEIGHT" in height
    assert "height: service ? serviceCardHeight(node) : 64" in renderer
    assert "const nameLines = serviceNameLines(fullName);" in renderer
    assert "21 + index * SERVICE_NAME_LINE_HEIGHT" in renderer
    assert "41 + extraHeight" in renderer
    assert "59 + extraHeight" in renderer
    assert 'title.textContent = fullName + " (" + node.service_type + ")";' in renderer


def test_service_slots_expand_without_repacking_sparse_or_manual_order():
    script = _script()
    layout = _section(script, "function layoutServiceGraph(", "function preserveManualOrder(")
    assert "const services = preserveManualOrder(\"services\", automaticServices);" in layout
    assert "lastServiceSlot = Math.max(lastServiceSlot + 1, desired);" in layout
    assert "serviceSlots.push(lastServiceSlot);" in layout
    assert "const slotY = ROW_START + serviceSlots[index] * ROW_STEP;" in layout
    assert "const y = Math.max(slotY, lastServiceBottom + (index ? 12 : 0));" in layout
    assert "lastServiceBottom = y + serviceCardHeight(service);" in layout
    assert "lastServiceBottom + 175" in layout


def test_dns_sd_paths_follow_resized_card_center_without_changing_scope():
    script = _script()
    renderer = _section(script, "function renderServicesCanvas(", "function renderGraph(")
    assert "to.y + (dnssd ? serviceCardHeight(targetNode) / 2 : 32)" in renderer
    assert 'portOffset("in:" + toId, edge.id)' in renderer
    for check in (
        "edge.interface !== targetNode.interface",
        "edge.capture_scope !== targetNode.capture_scope",
        "edge.kind === \"dnssd_advertised_endpoint\"",
        '"map-edge-hit"',
        '" stale-path"',
        "setSelectedEdge(edge.id);",
    ):
        assert check in renderer


def test_manual_service_drag_targets_real_sparse_slot_centers():
    script = _script()
    layout = _section(script, "function layoutServiceGraph(", "function preserveManualOrder(")
    pointer = _section(script, 'svg.addEventListener("pointerdown"', "function endPan(")
    assert "serviceSlotCenters = services.map((service) =>" in layout
    assert "locations.get(service.id).y + serviceCardHeight(service) / 2" in layout
    assert "serviceCenters: moveNodesMode && activeMapMode === \"services\"" in pointer
    assert "serviceSlotCenters.slice() : null" in pointer
    assert "const desired = centers[dragging.fromIndex] + dy / camera.scale;" in pointer
    assert "Math.abs(centers[index] - desired)" in pointer
    assert "if (reorderNode(dragging.kind, dragging.nodeId, target)) renderGraph();" in pointer
    assert "const displacement = Math.round(dy / (ROW_STEP * camera.scale));" in pointer
    # Uniform spacing is retained only for ARP and Unified manual dragging.
    assert "if (dragging.serviceCenters?.length &&" in pointer
