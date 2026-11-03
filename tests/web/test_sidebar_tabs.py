"""Local 2D sidebar tabs keep the data model and navigation unchanged."""

from importlib import resources


def _assets():
    root = resources.files("novxis.web.static")
    return (
        root.joinpath("index.html").read_text(encoding="utf-8"),
        root.joinpath("app.js").read_text(encoding="utf-8"),
        root.joinpath("styles.css").read_text(encoding="utf-8"),
    )


def test_sidebar_has_three_accessible_pages_in_expected_order():
    html, _, _ = _assets()
    names = ["evidence", "subnet", "host"]
    assert 'role="tablist" aria-label="Network detail pages"' in html
    assert [html.index(f'id="tab-{n}"') for n in names] == sorted(
        html.index(f'id="tab-{n}"') for n in names
    )
    for name in names:
        assert f'id="tab-{name}" role="tab"' in html
        assert f'aria-controls="panel-{name}"' in html
        assert f'id="panel-{name}" class="sidebar-page" role="tabpanel"' in html
        assert f'aria-labelledby="tab-{name}"' in html
    assert 'id="tab-evidence" role="tab" aria-selected="true"' in html
    assert 'id="panel-subnet" class="sidebar-page" role="tabpanel"' in html
    assert 'id="panel-host" class="sidebar-page" role="tabpanel"' in html


def test_original_host_subnet_and_arp_inspector_targets_survive_tabs():
    html, script, _ = _assets()
    for original_id in (
        "host-context", "host-context-content",
        "subnet-evidence", "subnet-evidence-content",
        "inspector-title", "inspector-content",
        "map", "viewport", "move-nodes", "auto-arrange",
    ):
        assert f'id="{original_id}"' in html
    assert 'const hostPanel = document.getElementById("host-context")' in script
    assert 'const subnetPanel = document.getElementById("subnet-evidence")' in script
    assert 'const inspector = document.getElementById("inspector-content")' in script


def test_disabled_unavailable_pages_prevent_offline_context_leak():
    html, script, _ = _assets()
    assert 'tabindex="-1" type="button" disabled>Subnet' in html
    assert 'tabindex="-1" type="button" disabled>Host' in html
    assert 'const live = payload.mode === "live-arp";' in script
    assert 'subnet: live && payload.subnet_evidence?.origin === "derived-comparison"' in script
    assert 'host: live && payload.host_context?.origin === "local-os"' in script
    assert 'sidebarTabs[name].button.disabled = !enabled;' in script
    assert 'if (!available[activeSidebarTab]) activeSidebarTab = "evidence";' in script
    assert 'selectSidebarTab(activeSidebarTab);' in script


def test_tab_selection_updates_aria_and_panes_without_resetting_map():
    _, script, styles = _assets()
    assert 'let activeSidebarTab = "evidence";' in script
    assert 'tab.button.setAttribute("aria-selected", String(selected));' in script
    assert 'tab.button.tabIndex = selected ? 0 : -1;' in script
    assert 'tab.panel.hidden = !selected;' in script
    assert 'button.addEventListener("click", () => selectSidebarTab(name));' in script
    assert '.sidebar-page[hidden] { display: none; }' in styles
    selection = script[script.index("function selectSidebarTab("):
                       script.index("function updateSidebarTabs(")]
    assert 'renderGraph()' not in selection
    assert 'updateCamera()' not in selection
    assert 'selectedId =' not in selection


def test_arrow_and_home_end_keyboard_tab_navigation_is_supported():
    _, script, styles = _assets()
    assert 'button.addEventListener("keydown", (event) => {' in script
    for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
        assert f'event.key === "{key}"' in script
    assert 'selectSidebarTab(next, true);' in script
    assert '.sidebar-tabs button:focus-visible' in styles


def test_address_selection_opens_evidence_page_instead_of_losing_inspector():
    _, script, _ = _assets()
    selected = script[script.index("function setSelected("):
                      script.index("function computeAutoOrders(")]
    assert 'selectSidebarTab("evidence");' in selected
    button = script[script.index("function appendAddressButton("):
                    script.index("function appendAddressSection(")]
    assert 'selectedId = item.node_id;' in button
    assert 'showInspector();' in button
    assert 'selectSidebarTab("evidence");' in button


def test_live_refresh_preserves_tab_and_existing_subnet_group_state():
    _, script, _ = _assets()
    assert 'updateSidebarTabs(payload);' in script
    assert 'showHostContext(live ? payload.host_context : null)' in script
    assert 'showSubnetEvidence(live ? payload.subnet_evidence : null)' in script
    assert 'details.open = openSubnetGroups.has(groupKey)' in script
    assert 'lastRevision !== payload.revision' in script
    refresh = script[script.index("async function loadGraph()"):]
    assert 'activeSidebarTab = "evidence"' not in refresh
    assert 'openSubnetGroups.clear()' not in refresh
    assert 'camera = {' not in refresh


def test_tabbed_sidebar_does_not_extend_capture_surface():
    html, script, _ = _assets()
    assert 'fetch("/api/graph"' in script
    assert 'fetch("/api/subnet"' not in script
    assert "getUserMedia" not in script
    assert '<script src="/app.js" defer></script>' in html
