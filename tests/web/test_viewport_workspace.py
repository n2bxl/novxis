"""Stage 1 viewport-constrained 2D workspace source contracts.

Static CSS/HTML checks. Browser geometry and Safari scrolling still require
owner acceptance on a narrow window, short desktop window and normal desktop.
"""
from importlib import resources
import re


def assets():
    root = resources.files("novxis.web.static")
    return (
        root.joinpath("index.html").read_text(encoding="utf-8"),
        root.joinpath("styles.css").read_text(encoding="utf-8"),
    )


def rule(css: str, selector: str) -> str:
    # Match a standalone selector, not a comma-separated combined rule.
    match = re.search(r"(?m)^\s*" + re.escape(selector) + r"\s*\{", css)
    assert match is not None, f"Missing CSS rule: {selector}"
    return css[match.start():css.index("}", match.end()) + 1]


def test_desktop_workspace_tracks_viewport_instead_of_growing_with_evidence():
    _, css = assets()
    assert "height: 100dvh;" in rule(css, ".shell")
    assert "min-height: 0;" in rule(css, ".shell")
    assert "min-height: 0;" in rule(css, ".workspace")
    assert "min-height: 660px;" not in rule(css, ".workspace")
    assert "min-height: 0;" in rule(css, ".map-panel")
    assert "min-height: 0;" in rule(css, ".canvas-wrap")
    assert "min-height: 0;" in rule(css, "#map")


def test_chrome_stays_visible_while_sidebar_scrolls_independently():
    html, css = assets()
    assert "flex: 0 0 auto;" in rule(css, ".topbar")
    assert "flex: 0 0 auto;" in rule(css, ".panel-head")
    assert "flex: 0 0 auto;" in rule(css, ".canvas-footer")
    assert "flex: 0 0 auto;" in rule(css, ".footnote")
    assert "max-height: 100%;" in rule(css, ".inspector")
    assert "overflow-y: auto;" in rule(css, ".sidebar-page")
    assert "overscroll-behavior: contain;" in rule(css, ".sidebar-page")
    for name in ("evidence", "subnet", "host", "services", "neighbors"):
        assert f'id="panel-{name}" class="sidebar-page"' in html
    assert 'class="canvas-footer"' in html
    assert 'class="footnote"' in html


def test_narrow_viewports_return_to_stack_and_page_scrolling():
    _, css = assets()
    responsive = css[css.index("@media (max-width: 900px) {"):]
    assert ".shell { height: auto; min-height: 100dvh; }" in responsive
    assert ".workspace { flex: none; grid-template-columns: 1fr;" in responsive
    assert ".canvas-wrap, #map { min-height: 360px; }" in responsive
    assert "height: min(70dvh, 700px);" in responsive
    assert "max-height: none;" in responsive


def test_zoom_maximum_uses_actual_css_viewport_and_svg_viewbox():
    js = resources.files("novxis.web.static").joinpath("app.js").read_text(
        encoding="utf-8"
    )
    maximum = js.split("function maximumZoomScale() {", 1)[1].split(
        "function zoomAt(", 1
    )[0]
    assert "const rect = svg.getBoundingClientRect();" in maximum
    assert "const view = svg.viewBox.baseVal;" in maximum
    assert "rect.width / view.width, rect.height / view.height" in maximum
    assert "return Math.max(3.5, 5 / cssPixelsPerUnit);" in maximum
    assert "3.5 * Math.max(1, stageHeight / 620)" not in maximum
    assert "Math.min(maximumZoomScale(), Math.max(0.05, camera.scale * factor))" in js
    assert 'document.getElementById("zoom-in").addEventListener("click"' in js
    assert 'canvas.addEventListener("wheel"' in js
