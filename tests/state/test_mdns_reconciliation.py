"""Synthetic cross-message DNS-SD relationship tests without network access."""

from decimal import Decimal
from ipaddress import IPv6Address

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.protocols.dns import DNSParseError
from novxis.state.mdns_reconciliation import MDNSServiceReconciliation


def _name(*labels: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode()
                    for label in labels) + b"\x00"


SERVICE = _name("_demo", "_tcp", "local")
INSTANCE = _name("Studio", "_demo", "_tcp", "local")
HOST = _name("host", "local")
OTHER = _name("other", "local")


def _rr(name: bytes, rtype: int, value: bytes, *, ttl=120):
    return (
        name + rtype.to_bytes(2, "big") + b"\x80\x01"
        + ttl.to_bytes(4, "big")
        + len(value).to_bytes(2, "big") + value
    )


def _frame(
    at: str, records: tuple[bytes, ...], *,
    interface: str = "en5", response: bool = True,
    family: int = 4,
):
    question = HOST + b"\x00\x01\x00\x01"
    payload = (
        b"\x00\x00" + (b"\x84\x00" if response else b"\x00\x00")
        + b"\x00\x01" + len(records).to_bytes(2, "big")
        + b"\x00\x00\x00\x00" + question + b"".join(records)
    )
    udp = (
        b"\x14\xe9\x14\xe9" + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00" + payload
    )
    if family == 4:
        ip = (
            b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
            + b"\x00\x01\x00\x00\xff\x11\x00\x00"
            + bytes((192, 0, 2, 26)) + bytes((224, 0, 0, 251)) + udp
        )
        ethertype = b"\x08\x00"
    else:
        ip = (
            b"\x60\x00\x00\x00" + len(udp).to_bytes(2, "big")
            + b"\x11\xff"
            + IPv6Address("fe80::26").packed + IPv6Address("ff02::fb").packed
            + udp
        )
        ethertype = b"\x86\xdd"
    data = bytes.fromhex("01005e0000fb0266778899aa") + ethertype + ip
    return CapturedFrame(
        timestamp=Decimal(at), interface=interface, data=data,
        captured_length=len(data), original_length=len(data), link_type=1,
    )


def _ptr(*, ttl=4500):
    return _rr(SERVICE, 12, INSTANCE, ttl=ttl)


def _srv(*, owner=INSTANCE, target=b"\xc0\x0c", port=4070, ttl=120):
    return _rr(
        owner, 33, b"\x00" * 4 + port.to_bytes(2, "big") + target, ttl=ttl
    )


def _txt(*, owner=INSTANCE, ttl=600):
    return _rr(owner, 16, b"\x08hello=hi", ttl=ttl)


def _addr(*, owner=HOST, ttl=120):
    return _rr(owner, 1, bytes((192, 0, 2, 25)), ttl=ttl)


def _observe(state: MDNSServiceReconciliation, at, *records,
             interface="en5", response=True, family=4):
    observed = MDNSEventPipeline().process(
        _frame(at, records, interface=interface, response=response,
               family=family)
    )
    assert observed is not None
    return state.observe_message(observed)


def _snap(state, at):
    return state.snapshots(Decimal(at))


def test_standalone_srv_txt_and_a_relate_to_previous_ptr():
    state = MDNSServiceReconciliation()
    assert _observe(state, "100", _ptr()) == 1
    assert _observe(state, "101", _srv()) == 0
    assert _observe(state, "102", _addr(), family=6) == 0
    assert _observe(state, "103", _txt()) == 0

    joined, = _snap(state, "103")
    base = joined.snapshot
    assert base.service_type.text == "_demo._tcp.local"
    assert base.observation_count == 1
    assert base.has_fresh_ptr
    assert {r.kind for r in joined.cross_message_records} == {
        "SRV", "TXT", "A",
    }
    assert base.fresh_targets[0].value.port == 4070
    assert base.fresh_addresses[0].value == "192.0.2.25"
    assert len(base.fresh_records) == 4
    assert base.fresh_targets[0].source.timestamp == Decimal("101")
    assert base.fresh_addresses[0].source.ip_version == 6
    assert len(state.state.history) == 1
    assert state.unassociated_count == 3


def test_srv_and_address_before_ptr_reconcile_if_still_fresh():
    state = MDNSServiceReconciliation()
    _observe(state, "80", _addr(ttl=50))
    _observe(state, "90", _srv(ttl=60))
    assert state.state.instance_count == 0
    _observe(state, "100", _ptr())
    joined, = _snap(state, "100")
    assert joined.snapshot.observation_count == 1
    assert len(joined.snapshot.fresh_targets) == 1
    assert len(joined.snapshot.fresh_addresses) == 1


def test_orphans_without_a_service_ptr_do_not_create_instances():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _srv())
    _observe(state, "101", _txt())
    _observe(state, "102", _addr())
    assert _snap(state, "102") == ()
    assert state.state.instance_count == 0


def test_queries_and_known_answers_are_never_imported():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr(), response=False)
    _observe(state, "101", _srv(), response=False)
    assert _snap(state, "101") == ()
    assert state.unassociated_count == 0


def test_records_from_other_interface_do_not_join():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr(), interface="en0")
    _observe(state, "101", _srv(), interface="en5")
    _observe(state, "102", _addr(), interface="en5")
    joined, = _snap(state, "102")
    assert joined.snapshot.interface == "en0"
    assert joined.snapshot.fresh_targets == ()
    assert joined.cross_message_records == ()


def test_address_requires_exact_fresh_srv_target_not_sender_or_keyword():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr())
    _observe(state, "101", _addr())
    no_srv, = _snap(state, "101")
    assert no_srv.snapshot.fresh_addresses == ()
    _observe(state, "102", _srv(target=OTHER))
    other_host, = _snap(state, "102")
    assert other_host.snapshot.fresh_targets[0].value.target.text == "other.local"
    assert other_host.snapshot.fresh_addresses == ()


def test_orphans_cannot_outlive_their_independent_ttl():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr())
    _observe(state, "101", _srv(ttl=1))
    _observe(state, "102", _addr(ttl=100))
    at102, = _snap(state, "102")
    assert at102.snapshot.has_fresh_ptr
    assert at102.snapshot.fresh_targets == ()
    assert at102.snapshot.fresh_addresses == ()
    assert at102.cross_message_records == ()


def test_expired_ptr_blocks_reconciliation_even_with_fresh_srv():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr(ttl=5))
    _observe(state, "101", _srv(ttl=200))
    at106, = _snap(state, "106")
    assert not at106.snapshot.has_fresh_ptr
    assert at106.snapshot.fresh_targets == ()
    assert at106.cross_message_records == ()


def test_newer_standalone_srv_overrides_same_semantic_key_by_timestamp():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr(), _srv(ttl=4))
    _observe(state, "102", _srv(ttl=80))
    result, = _snap(state, "105")
    targets = result.snapshot.fresh_targets
    assert len(targets) == 1
    assert targets[0].observed_at == Decimal("102")
    assert targets[0].record.wire.ttl == 80
    assert len(result.cross_message_records) == 1


def test_standalone_srv_conflicts_are_preserved_as_observation_not_resolved():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr())
    _observe(state, "101", _srv(port=4070))
    _observe(state, "102", _srv(port=5000))
    result, = _snap(state, "102")
    assert result.snapshot.has_conflicting_fresh_srv
    assert {r.value.port for r in result.snapshot.fresh_targets} == {4070, 5000}


def test_unassociated_buffer_is_bounded_and_validated():
    state = MDNSServiceReconciliation(max_unassociated=2)
    _observe(state, "100", _addr())
    _observe(state, "101", _srv())
    _observe(state, "102", _txt())
    assert state.unassociated_count == 2
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            MDNSServiceReconciliation(max_unassociated=bad)


def test_snapshot_rejects_time_before_last_message_even_without_ptr():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _srv())
    with pytest.raises(ValueError, match="precedes"):
        _snap(state, "99")


def test_unrelated_txt_owner_is_never_joined():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr())
    _observe(state, "101", _txt(owner=_name("Other", "_demo", "_tcp", "local")))
    result, = _snap(state, "101")
    assert result.snapshot.has_fresh_ptr
    assert result.cross_message_records == ()


def test_srv_rdata_with_bad_pointer_is_rejected_not_guessed():
    state = MDNSServiceReconciliation()
    packet = _frame("100", (_srv(target=b"\xc0\xff"),))
    source = MDNSEventPipeline().process(packet)
    assert source is not None
    with pytest.raises(DNSParseError):
        state.observe_message(source)


def test_later_ttl_zero_standalone_srv_withdraws_fresh_same_value():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr(), _srv(ttl=500))
    assert len(_snap(state, "101")[0].snapshot.fresh_targets) == 1
    _observe(state, "110", _srv(ttl=0))
    joined, = _snap(state, "110")
    assert joined.snapshot.has_fresh_ptr
    assert joined.snapshot.fresh_targets == ()
    latest_srv = [
        r for r in joined.snapshot.latest_records if r.kind == "SRV"
    ]
    assert len(latest_srv) == 1
    assert latest_srv[0].record.goodbye_candidate
    assert latest_srv[0].observed_at == Decimal("110")


def test_explicit_snapshot_does_not_retroactively_include_future_orphans():
    state = MDNSServiceReconciliation()
    _observe(state, "100", _ptr())
    _observe(state, "120", _srv())
    with pytest.raises(ValueError, match="precedes"):
        _snap(state, "110")


def test_malformed_later_rr_does_not_partially_commit_earlier_packet_records():
    state = MDNSServiceReconciliation()
    packet = _frame("100", (_addr(), _srv(target=b"\xc0\xff")))
    source = MDNSEventPipeline().process(packet)
    assert source is not None
    with pytest.raises(DNSParseError):
        state.observe_message(source)
    assert state.unassociated_count == 0


# Phase 1N-J: full capture helper -> sanitized pipe -> live browser state.
# Reuse this module's synthetic byte-level DNS fixtures to exercise the
# existing MDNSServiceReconciliation rather than duplicating its parser.

def _live_messages(*frames):
    from novxis.cli.network_live_stream import build_handler

    messages = []
    handler = build_handler(messages.append)
    for frame in frames:
        handler(frame)
    return messages


def _live_graph(events, now="110"):
    from novxis.web.live_state import LiveARPGraphState

    state = LiveARPGraphState(clock=lambda: float(now))
    state.ingest({
        "type": "session", "interface": "en5",
        "protocols": ["arp", "mdns"],
    })
    for event in events:
        state.ingest(event)
    return state


def test_live_reconciler_joins_standalone_srv_and_a_after_ptr():
    events = _live_messages(
        _frame("100", (_ptr(),)),
        _frame("101", (_srv(ttl=300),)),
        _frame("102", (_addr(ttl=30),), family=6),
    )
    assert sum(event["type"] == "mdns" for event in events) == 3
    updates = [e for e in events if e["type"] == "mdns_reconciliation"]
    assert len(updates) == 2
    latest = updates[-1]
    assert latest["interface"] == "en5"
    assert latest["service_type"] == "_demo._tcp.local"
    assert latest["instance"] == "Studio._demo._tcp.local"
    assert latest["ptr_observed_at"] == "100"
    assert latest["as_of"] == "102"
    (target,) = latest["targets"]
    assert target["target"] == "host.local"
    assert target["port"] == 4070
    assert target["observed_at"] == "101"
    assert target["origin"] == "cross-mdns-response"
    assert target["addresses"] == [{
        "address": "192.0.2.25", "family": 4, "ttl": 30,
        "observed_at": "102", "origin": "cross-mdns-response",
    }]
    import json
    from novxis.web.live_state import MAX_LINE
    assert all(len(json.dumps(e)) < MAX_LINE for e in events)
    assert all("payload" not in e and "txt" not in e for e in events)

    state = _live_graph(events, now="110")
    snap = state.snapshot()
    mdns = snap["mdns_evidence"]
    assert mdns["messages"] == 3
    assert mdns["responses"] == 3
    assert mdns["ptr_advertisements"] == 1
    assert mdns["retained_instances"] == 1
    (srv,) = mdns["services"][0]["targets"]
    assert srv["source"] == "cross-mdns-response"
    assert srv["observed_at"] == "101"
    assert srv["fresh"] and srv["path_fresh"]
    assert srv["addresses"][0]["source"] == "cross-mdns-response"
    assert srv["addresses"][0]["observed_at"] == "102"
    assert srv["addresses"][0]["path_fresh"]
    assert snap["nodes"] == [] and snap["claims"] == []


def test_live_reconciler_handles_orphans_before_ptr_with_same_interface():
    events = _live_messages(
        _frame("80", (_addr(ttl=90),)),
        _frame("90", (_srv(ttl=200),)),
        _frame("100", (_ptr(),)),
    )
    updates = [e for e in events if e["type"] == "mdns_reconciliation"]
    assert len(updates) == 1
    assert updates[0]["targets"][0]["observed_at"] == "90"
    assert updates[0]["targets"][0]["addresses"][0]["observed_at"] == "80"
    state = _live_graph(events, now="101")
    (target,) = state.snapshot()["mdns_evidence"]["services"][0]["targets"]
    assert target["path_fresh"]
    assert target["addresses"][0]["path_fresh"]


def test_live_reconciler_cross_interface_orphan_cannot_attach():
    events = _live_messages(
        _frame("100", (_ptr(),), interface="en5"),
        _frame("101", (_srv(),), interface="en0"),
        _frame("102", (_addr(),), interface="en0"),
    )
    assert not any(e["type"] == "mdns_reconciliation" for e in events)


def test_live_reconciler_does_not_join_standalone_query_known_answers():
    events = _live_messages(
        _frame("100", (_ptr(),)),
        _frame("101", (_srv(),), response=False),
        _frame("102", (_addr(),), response=False),
    )
    assert not any(e["type"] == "mdns_reconciliation" for e in events)


def test_live_reconciler_clears_withdrawn_srv_instead_of_leaving_stale_link():
    events = _live_messages(
        _frame("100", (_ptr(),)),
        _frame("101", (_srv(ttl=300),)),
        _frame("110", (_srv(ttl=0),)),
    )
    assert sum(e["type"] == "mdns_reconciliation" for e in events) == 1
    clears = [e for e in events if e["type"] == "mdns_reconciliation_clear"]
    assert len(clears) == 1
    state = _live_graph(events, now="110")
    service = state.snapshot()["mdns_evidence"]["services"][0]
    assert service["fresh"]
    assert service["targets"] == []


def test_live_reconciler_independent_srv_and_a_ttls_expire_without_packets():
    now = [103]
    events = _live_messages(
        _frame("100", (_ptr(),)),
        _frame("101", (_srv(ttl=120),)),
        _frame("102", (_addr(ttl=10),)),
    )
    from novxis.web.live_state import LiveARPGraphState
    state = LiveARPGraphState(clock=lambda: float(now[0]))
    state.ingest({"type": "session", "interface": "en5",
                  "protocols": ["arp", "mdns"]})
    for event in events:
        state.ingest(event)
    first = state.snapshot()
    srv = first["mdns_evidence"]["services"][0]["targets"][0]
    assert srv["path_fresh"]
    assert srv["addresses"][0]["path_fresh"]
    revision, graph_revision = first["revision"], first["graph_revision"]

    now[0] = 113
    second = state.snapshot()
    srv = second["mdns_evidence"]["services"][0]["targets"][0]
    assert srv["fresh"]
    assert not srv["addresses"][0]["fresh"]
    assert not srv["addresses"][0]["path_fresh"]
    assert second["revision"] > revision
    assert second["graph_revision"] == graph_revision

    now[0] = 222
    third = state.snapshot()
    srv = third["mdns_evidence"]["services"][0]["targets"][0]
    assert not srv["fresh"]
    assert not srv["path_fresh"]
    assert third["mdns_evidence"]["services"][0]["fresh"]


def test_reconciliation_untrusted_message_is_atomic_and_cannot_create_ptr():
    from copy import deepcopy
    from novxis.web.live_state import LiveARPGraphState

    events = _live_messages(
        _frame("100", (_ptr(),)),
        _frame("101", (_srv(),)),
    )
    update = next(e for e in events if e["type"] == "mdns_reconciliation")
    state = _live_graph(events, now="102")
    before = deepcopy(state.snapshot()["mdns_evidence"])
    bad = dict(update)
    bad["targets"] = [dict(update["targets"][0], port=True)]
    with pytest.raises(ValueError):
        state.ingest(bad)
    assert state.snapshot()["mdns_evidence"] == before

    other = LiveARPGraphState(clock=lambda: 102)
    other.ingest({"type": "session", "interface": "en5",
                  "protocols": ["arp", "mdns"]})
    assert not other._mdns.observe_reconciliation(update, "en5")
    assert not other.snapshot()["mdns_evidence"]["services"]


def test_reconciliation_rejects_wrong_interface_and_outdated_ptr_epoch():
    events = _live_messages(
        _frame("100", (_ptr(),)), _frame("101", (_srv(),)),
    )
    state = _live_graph(events, now="102")
    update = next(e for e in events if e["type"] == "mdns_reconciliation")
    with pytest.raises(ValueError):
        state.ingest({**update, "interface": "en0"})
    old = dict(update)
    old["ptr_observed_at"] = "90"
    before = state.snapshot()["revision"]
    state.ingest(old)
    assert state.snapshot()["revision"] == before


def test_ipv6_mdns_packet_with_ipv4_advertised_a_keeps_correct_transport_count():
    from novxis.web.mdns_live import LiveMDNSState
    state = LiveMDNSState()
    state.observe({
        "interface": "en5", "ip_version": 6, "role": "response",
        "observed_at": "100", "advertisement_count": 1,
        "advertisements": [{
            "service_type": "_demo._tcp.local",
            "instance": "Studio._demo._tcp.local", "ttl": 300,
            "targets": [{
                "target": "host.local", "port": 4070, "ttl": 120,
                "addresses": [{"address": "192.0.2.25", "family": 4, "ttl": 30}],
            }],
        }],
    }, "en5")
    snap, _ = state.snapshot(Decimal("100"))
    assert snap["ipv4"] == 0
    assert snap["ipv6"] == 1
