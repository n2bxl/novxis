"""Bounded mDNS pipe events, live TTL refresh, and ARP compatibility."""

from copy import deepcopy
from decimal import Decimal
from importlib import resources

import pytest

from novxis.web.live_state import LiveARPGraphState
from novxis.web.mdns_live import LiveMDNSState


def ad(*, ttl=120, name="Studio._demo._tcp.local"):
    return {
        "service_type": "_demo._tcp.local",
        "instance": name,
        "ttl": ttl,
    }


def msg(*, ads=None, count=None, role="response", family=4, at="100",
        interface="en0"):
    ads = [ad()] if ads is None else ads
    return {
        "type": "mdns", "interface": interface,
        "ip_version": family, "role": role,
        "observed_at": at,
        "advertisement_count": len(ads) if count is None else count,
        "advertisements": ads,
    }


def state_with_mdns(clock=lambda: 100):
    state = LiveARPGraphState(clock=clock)
    state.ingest({
        "type": "session", "interface": "en0",
        "protocols": ["arp", "mdns"],
    })
    return state


def test_only_opted_in_sessions_accept_mdns_messages():
    old = LiveARPGraphState()
    old.ingest({"type": "session", "interface": "en0"})
    with pytest.raises(ValueError):
        old.ingest(msg())
    assert "mdns_evidence" not in old.snapshot()
    enabled = state_with_mdns()
    with pytest.raises(ValueError):
        enabled.ingest(msg(interface="en5"))


def test_mdns_query_counts_do_not_create_service_instances():
    state = state_with_mdns()
    state.ingest(msg(role="query", ads=[]))
    observed = state.snapshot()["mdns_evidence"]
    assert observed["messages"] == observed["queries"] == 1
    assert observed["responses"] == observed["ptr_advertisements"] == 0
    assert observed["services"] == []
    assert observed["interface"] == "en0"


def test_ttl_expiration_advances_revision_without_packet_arrival_or_arp_redraw():
    now = [100]
    state = state_with_mdns(clock=lambda: now[0])
    state.ingest(msg())
    fresh = state.snapshot()
    assert fresh["mdns_evidence"]["fresh_instances"] == 1
    graph_rev = fresh["graph_revision"]
    revision = fresh["revision"]
    now[0] = 220
    expired = state.snapshot()
    assert expired["mdns_evidence"]["fresh_instances"] == 0
    assert not expired["mdns_evidence"]["services"][0]["fresh"]
    assert expired["revision"] > revision
    assert expired["graph_revision"] == graph_rev
    assert state.snapshot()["revision"] == expired["revision"]


def test_new_advertisement_refreshes_ttl_freshness_and_retains_count():
    now = [100]
    state = state_with_mdns(clock=lambda: now[0])
    state.ingest(msg())
    now[0] = 220
    assert state.snapshot()["mdns_evidence"]["fresh_instances"] == 0
    now[0] = 221
    state.ingest(msg(at="221"))
    service = state.snapshot()["mdns_evidence"]["services"][0]
    assert service["fresh"]
    assert service["observations"] == 2
    assert service["last_seen"] == "221"


@pytest.mark.parametrize("patch", [
    {"ip_version": 5},
    {"ip_version": True},
    {"role": "other"},
    {"interface": "en5"},
    {"observed_at": "NaN"},
    {"observed_at": "-1"},
    {"observed_at": 100},
    {"advertisement_count": True},
    {"advertisement_count": 0},
    {"advertisements": [ad(ttl=-1)]},
    {"advertisements": [ad(ttl=2**32)]},
    {"advertisements": [ad(name="\n")]},
    {"advertisements": [ad()] * 5},
])
def test_invalid_mdns_events_do_not_mutate_summary(patch):
    state = state_with_mdns()
    before = deepcopy(state.snapshot()["mdns_evidence"])
    with pytest.raises(ValueError):
        state.ingest({**msg(), **patch})
    after = state.snapshot()["mdns_evidence"]
    assert after == before


def test_capture_mdns_decode_errors_are_nonfatal_and_source_scoped():
    state = state_with_mdns()
    state.ingest({"type": "mdns_decode_error", "interface": "en0"})
    snap = state.snapshot()
    assert snap["capture_status"] == "capturing"
    assert snap["mdns_evidence"]["decode_errors"] == 1
    with pytest.raises(ValueError):
        state.ingest({"type": "mdns_decode_error", "interface": "en5"})


def test_bounded_instances_flag_missing_evidence_instead_of_inventing_full_list():
    summary = LiveMDNSState()
    for index in range(130):
        summary.observe(msg(ads=[ad(name=f"Node{index}._demo._tcp.local")]), "en0")
    result, _ = summary.snapshot(Decimal("101"))
    assert result["retained_instances"] == 128
    assert result["truncated"]
    assert result["omitted_advertisements"] >= 2


def test_omitted_advertisements_have_explicit_truncation_status():
    summary = LiveMDNSState()
    summary.observe(msg(ads=[ad()], count=3), "en0")
    result, _ = summary.snapshot(Decimal("100"))
    assert result["ptr_advertisements"] == 3
    assert result["omitted_advertisements"] == 2
    assert result["truncated"]


def test_old_arp_state_session_remains_unchanged():
    old = LiveARPGraphState(clock=lambda: 100)
    old.ingest({"type": "session", "interface": "en0"})
    result = old.snapshot()
    assert "mdns_evidence" not in result
    assert result["source"]["capture_name"] == "Live ARP"
    assert result["graph_revision"] == 0


def test_browser_adds_live_only_services_tab_without_new_network_apis():
    static = resources.files("novxis.web.static")
    html = static.joinpath("index.html").read_text(encoding="utf-8")
    script = static.joinpath("app.js").read_text(encoding="utf-8")
    css = static.joinpath("styles.css").read_text(encoding="utf-8")
    assert 'id="tab-services" role="tab"' in html
    assert 'id="panel-services" class="sidebar-page" role="tabpanel"' in html
    assert 'id="mdns-evidence-content"' in html
    assert '"evidence", "subnet", "host", "services"' in script
    assert 'services: live && payload.mdns_evidence?.origin === "mdns-observation"' in script
    assert 'showMDNSEvidence(live ? payload.mdns_evidence : null)' in script
    assert 'lastGraphRevision !== graphRevision' in script
    assert 'if (redrawGraph) renderGraph();' in script
    assert '.mdns-evidence[hidden] { display: none; }' in css
    assert 'fetch("/api/mdns"' not in script
