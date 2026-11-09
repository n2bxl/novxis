"""Stage 4B.1: viewport-responsive Services horizontal geometry contracts."""
from importlib import resources


def script():
    return resources.files("novxis.web.static").joinpath("app.js").read_text(
        encoding="utf-8"
    )


def test_horizontal_columns_follow_actual_canvas_width_with_minimum():
    js = script()
    geometry = js.split("function serviceColumnGeometry() {", 1)[1].split(
        "const SERVICE_NAME_CHARS_PER_LINE", 1
    )[0]
    assert "Math.round(canvas.clientWidth || SERVICE_MIN_VIEW_WIDTH)" in geometry
    assert "SERVICE_MIN_VIEW_WIDTH = 1080" in js
    assert "SERVICE_CARD_WIDTH = 282" in js
    assert "const services = viewWidth - SERVICE_COLUMN_LEFT - SERVICE_CARD_WIDTH;" in geometry
    assert "const protocol = Math.round((hardware + services) / 2);" in geometry


def test_service_layout_and_headers_share_dynamic_coordinates():
    js = script()
    layout = js.split("function layoutServiceGraph(", 1)[1].split(
        "function preserveManualOrder(", 1
    )[0]
    renderer = js.split("function renderServicesCanvas(", 1)[1].split(
        "function renderGraph(", 1
    )[0]
    assert "const serviceColumns = serviceColumnGeometry();" in layout
    assert "x: serviceColumns.hardware" in layout
    assert "x: serviceColumns.protocol" in layout
    assert "x: serviceColumns.services" in layout
    assert 'svg.setAttribute("viewBox", "0 0 " + serviceColumns.viewWidth + " " + stageHeight);' in layout
    assert "const serviceColumns = serviceColumnGeometry();" in renderer
    assert "addSVGText(viewport, serviceColumns.services, 59" in renderer
    assert "addSVGText(viewport, serviceColumns.protocol, 59" in renderer
    assert "addSVGText(viewport, serviceColumns.hardware, 59" in renderer


def test_resize_reflows_without_mutating_order_or_resetting_camera():
    js = script()
    resize = js.split('if (typeof ResizeObserver !== "undefined") {', 1)[1]
    assert "new ResizeObserver(() => {" in resize
    assert "Math.round(canvas.clientWidth)" in resize
    assert 'if (graph && activeMapMode === "services") renderGraph();' in resize
    assert "resetView()" not in resize
    assert "serviceManualOrders" not in resize


def test_address_modes_keep_existing_fixed_geometry():
    js = script()
    unified = js.split("function layoutUnifiedGraph(", 1)[1].split(
        "const SERVICE_CARD_WIDTH", 1
    )[0]
    assert 'svg.setAttribute("viewBox", "0 0 1080 " + stageHeight);' in unified
    assert "serviceColumnGeometry()" not in unified
    assert "function serviceNameLines(instance)" in js
    assert "serviceCardHeight(node)" in js
