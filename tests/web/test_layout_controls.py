"""2D graph layout contracts for the local NOVXIS debugger.

The browser owns presentation order. Protocol identity and ARP evidence
must remain unchanged by automatic or manual node arrangement.
"""

from importlib import resources


def _assets():
    static = resources.files("novxis.web.static")
    return (
        static.joinpath("index.html").read_text(encoding="utf-8"),
        static.joinpath("app.js").read_text(encoding="utf-8"),
        static.joinpath("styles.css").read_text(encoding="utf-8"),
    )


def test_rearrangement_is_explicit_and_can_be_reset():
    html, script, styles = _assets()
    assert 'id="move-nodes"' in html
    assert 'aria-pressed="false"' in html
    assert 'id="auto-arrange"' in html
    assert 'moveButton.addEventListener("click"' in script
    assert 'moveButton.setAttribute("aria-pressed"' in script
    assert 'manualOrders.protocol = null;' in script
    assert 'manualOrders.hardware = null;' in script
    assert '#map.move-mode .map-node' in styles


def test_auto_layout_uses_real_sender_claim_neighbors():
    _, script, _ = _assets()
    assert "function computeAutoOrders(snapshot)" in script
    assert "for (const claim of snapshot.claims)" in script
    assert "protocolRank.has(claim.source)" in script
    assert "neighbors.has(claim.target)" in script
    assert "averageRank(a) - averageRank(b)" in script
    assert "a.address_hex.localeCompare(b.address_hex)" in script
    assert "preserveManualOrder" in script
    assert "reorderNode" in script


def test_normal_drag_remains_pan_and_rearrangement_requires_opt_in():
    _, script, styles = _assets()
    assert 'let moveNodesMode = false;' in script
    assert 'mode: moveNodesMode && node ? "reorder" : "pan"' in script
    assert 'dragging.mode === "reorder"' in script
    assert "Math.round(dy / (ROW_STEP * camera.scale))" in script
    assert 'svg.classList.add("panning")' in script
    assert 'svg.classList.add("reordering")' in script
    assert '#map.reordering' in styles
    assert 'event.type === "pointerup" && !gesture.moved' in script


def test_keyboard_reorder_and_live_refresh_retains_manual_order():
    _, script, _ = _assets()
    assert 'event.shiftKey' in script
    assert 'event.key === "ArrowUp"' in script
    assert 'event.key === "ArrowDown"' in script
    assert "replacement.focus()" in script
    # Live snapshot revisions continue to update graph and inspector, but
    # presentation order is not reset on a capture update.
    polling = script[script.index("async function loadGraph()"):]
    assert "lastRevision !== payload.revision" in polling
    assert "renderGraph();" in polling
    assert "manualOrders.hardware = null" not in polling
    assert "manualOrders.protocol = null" not in polling


def test_layout_controls_do_not_add_capture_apis_or_external_dependencies():
    html, script, _ = _assets()
    assert "/api/graph" in script
    assert "http://" not in html and "https://" not in html
    assert "getUserMedia" not in script
    assert 'fetch("/api/graph"' in script
