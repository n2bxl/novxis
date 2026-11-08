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
