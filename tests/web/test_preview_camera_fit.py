"""2D preview camera fit contracts across ARP, Unified and Services.

These are source-level guardrails; real Safari viewport acceptance remains
necessary for bounding-box geometry and gesture interactions.
"""

from importlib import resources


def _script():
    return resources.files("novxis.web.static").joinpath("app.js").read_text(
        encoding="utf-8"
    )


def test_reset_fits_rendered_content_instead_of_resetting_to_origin():
    script = _script()
    fit = script.split("function resetView() {", 1)[1].split(
        'document.getElementById("zoom-in")', 1
    )[0]
    assert "const bounds = viewport.getBBox();" in fit
    assert "const view = svg.viewBox.baseVal;" in fit
    assert "availableWidth / bounds.width" in fit
    assert "availableHeight / bounds.height" in fit
    assert "bounds.x * scale" in fit
    assert "bounds.y * scale" in fit
    assert "Number.isFinite(bounds.width)" in fit
    assert "Number.isFinite(bounds.height)" in fit
    assert "camera = { x: 0, y: 0, scale: 1 };" in fit  # empty graph fallback


def test_all_modes_share_fit_control_and_preserve_independent_cameras():
    script = _script()
    assert 'document.getElementById("fit").addEventListener("click", resetView);' in script
    assert 'mapCameras[activeMapMode] = { ...camera };' in script
    assert 'camera = { ...mapCameras[mode] };' in script
    assert 'if (activeMapMode === "services") return layoutServiceGraph(active);' in script
    assert 'if (activeMapMode === "unified") return layoutUnifiedGraph(active);' in script
    assert "const locations = layoutGraph();" in script
    assert "Reset view frames the visible evidence" in script
    assert "Reset view fits all retained rows" not in script
