"""Stage 4A static contracts for longest-column vertical centering."""
from importlib import resources


def _script():
    return resources.files("novxis.web.static").joinpath("app.js").read_text(
        encoding="utf-8"
    )


def _service_layout():
    script = _script()
    return script.split("function layoutServiceGraph(", 1)[1].split(
        "function preserveManualOrder(", 1
    )[0]


def test_centering_uses_actual_rendered_card_bounds_not_node_count():
    layout = _service_layout()
    for expected in (
        'const columns = { hardware, protocol, services };',
        'const bounds = new Map();',
        'const tops = members.map((node) => locations.get(node.id).y);',
        'const bottoms = members.map((node) => locations.get(node.id).y +',
        '(kind === "services" ? serviceCardHeight(node) : 64)',
        'const top = Math.min(...tops);',
        'const bottom = Math.max(...bottoms);',
        'bounds.set(kind, { top, bottom, height: bottom - top });',
        'item.height > longest.height ? item : longest',
    ):
        assert expected in layout


def test_shorter_columns_shift_to_longest_center_without_reordering():
    layout = _service_layout()
    assert 'const center = (reference.top + reference.bottom) / 2;' in layout
    assert 'const delta = center -' in layout
    assert '(columnBounds.top + columnBounds.bottom) / 2;' in layout
    assert 'for (const node of members) locations.get(node.id).y += delta;' in layout
    assert 'const services = preserveManualOrder("services", automaticServices);' in layout
    assert 'const y = lastServiceBottom + SERVICE_CARD_GAP;' in layout


def test_manual_drag_and_svg_stage_use_post_centering_positions():
    layout = _service_layout()
    center = layout.index('const center = (reference.top + reference.bottom) / 2;')
    drag = layout.index('serviceSlotCenters = services.map((service) =>')
    stage = layout.index('const renderedBottom = Math.max(0,')
    assert center < drag < stage
    assert 'locations.get(service.id).y + serviceCardHeight(service) / 2' in layout
    assert 'renderedBottom + 175' in layout
    assert 'svg.setAttribute("viewBox", "0 0 1080 " + stageHeight);' in layout


def test_centering_is_services_only_and_does_not_modify_evidence():
    script = _script()
    layout = _service_layout()
    assert 'edge.interface !== ip.interface' in layout
    assert 'edge.capture_scope !== ip.capture_scope' in layout
    assert 'const automatic = computeUnifiedAutoOrders(snapshot);' in layout
    assert 'firstRank(a) - firstRank(b)' in layout
    assert 'const columns = { hardware, protocol, services };' in layout
    assert 'if (activeMapMode === "services") return layoutServiceGraph(active);' in script
    unified = script.split("function layoutUnifiedGraph(", 1)[1].split(
        "const SERVICE_COLUMN_X", 1
    )[0]
    assert 'const columns = { hardware, protocol, services };' not in unified
