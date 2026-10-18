"""Deterministic, bounded DNS-SD state tests from synthetic Ethernet packets."""

from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from ipaddress import IPv6Address

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.presentation.mdns_state_console import format_mdns_service_snapshot
from novxis.state.mdns_services import MDNSServiceEvidenceState
from novxis.views.mdns_services import project_dnssd_advertisements


def _name(*labels: str) -> bytes:
    return b"".join(bytes((len(s),)) + s.encode("ascii") for s in labels) + b"\x00"


SERVICE = _name("_demo", "_tcp", "local")
INSTANCE = _name("Studio", "_demo", "_tcp", "local")
HOST = _name("host", "local")


def _rr(name, rtype, raw, *, ttl=120, cls=1):
    return (
        name + rtype.to_bytes(2, "big") + cls.to_bytes(2, "big")
        + ttl.to_bytes(4, "big") + len(raw).to_bytes(2, "big") + raw
    )


def _frame(
    *, at="100", interface="test0", family=4, instance=INSTANCE,
    service=SERVICE, ptr_ttl=4500, srv_ttl=120,
    txt_ttl=600, addr_ttl=120, srv_port=4070,
    srv=True, txt=True, address=True, extra_addr=False, response=True,
    include_ptr=True,
):
    # QNAME at DNS offset 12, allowing SRV target pointer compression.
    question = HOST + b"\x00\x01\x00\x01"
    answers = (
        [_rr(service, 12, instance, ttl=ptr_ttl)] if include_ptr else []
    )
    extra = []
    if srv:
        srvr = b"\x00" * 4 + srv_port.to_bytes(2, "big") + b"\xc0\x0c"
        extra.append(_rr(instance, 33, srvr, ttl=srv_ttl, cls=0x8001))
    if txt:
        extra.append(_rr(instance, 16, b"\x09CPath=/zc",
                         ttl=txt_ttl, cls=0x8001))
    if address:
        extra.append(_rr(HOST, 1, bytes((192, 0, 2, 25)),
                         ttl=addr_ttl, cls=0x8001))
    if extra_addr:
        extra.append(_rr(
            HOST, 28, IPv6Address("2001:db8::25").packed,
            ttl=addr_ttl, cls=0x8001,
        ))
    flags = 0x8400 if response else 0
    dns = (
        b"\x00\x00" + flags.to_bytes(2, "big")
        + b"\x00\x01" + len(answers).to_bytes(2, "big")
        + b"\x00\x00" + len(extra).to_bytes(2, "big")
        + question + b"".join(answers + extra)
    )
    udp = (
        b"\x14\xe9\x14\xe9" + (8 + len(dns)).to_bytes(2, "big")
        + b"\x00\x01" + dns
    )
    if family == 4:
        ip = (
            b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
            + b"\x00\x01\x00\x00\xff\x11\x00\x00"
            + bytes((192, 0, 2, 26)) + bytes((224, 0, 0, 251))
            + udp
        )
        etype = b"\x08\x00"
    else:
        ip = (
            b"\x60\x00\x00\x00" + len(udp).to_bytes(2, "big")
            + b"\x11\xff"
            + IPv6Address("fe80::26").packed + IPv6Address("ff02::fb").packed
            + udp
        )
        etype = b"\x86\xdd"
    data = bytes.fromhex("01005e0000fb0266778899aa") + etype + ip
    return CapturedFrame(
        timestamp=Decimal(at), interface=interface, data=data,
        captured_length=len(data), original_length=len(data), link_type=1
    )


def _observe(state, **kwargs):
    source = MDNSEventPipeline().process(_frame(**kwargs))
    assert source is not None
    ads = project_dnssd_advertisements(source)
    for ad in ads:
        state.observe(source, ad)
    return source, ads


def _snapshot(state, at="100"):
    return state.snapshots(Decimal(at))


def test_repeated_dual_stack_service_claims_become_one_instance():
    state = MDNSServiceEvidenceState()
    source, ads = _observe(state, at="100", family=4)
    assert len(ads) == 1
    _observe(state, at="101", family=6)
    _observe(state, at="102", family=4)
    assert state.instance_count == 1
    assert len(state.history) == 3
    snapshot, = _snapshot(state, at="102")
    assert snapshot.observation_count == 3
    assert snapshot.first_seen == Decimal("100")
    assert snapshot.last_seen == Decimal("102")
    assert snapshot.service_type.text == "_demo._tcp.local"
    assert snapshot.instance.text == "Studio._demo._tcp.local"
    assert snapshot.has_fresh_ptr
    assert len(snapshot.fresh_targets) == 1
    assert snapshot.fresh_targets[0].value.port == 4070
    assert len(snapshot.fresh_addresses) == 1
    assert snapshot.fresh_addresses[0].value == "192.0.2.25"
    assert snapshot.fresh_targets[0].source is source or (
        snapshot.fresh_targets[0].source.timestamp == Decimal("102")
    )
    assert len(snapshot.latest_records) == 4  # PTR + SRV + TXT + A
    assert "status=fresh-advertisement" in format_mdns_service_snapshot(snapshot)


def test_each_record_ttl_expires_independently_without_device_verdict():
    state = MDNSServiceEvidenceState()
    _observe(state, at="100", srv_ttl=120, addr_ttl=60, txt_ttl=600)
    s, = _snapshot(state, at="161")
    assert s.has_fresh_ptr
    assert len(s.fresh_targets) == 1
    assert s.fresh_addresses == ()
    assert "addresses=not-freshly-observed" in format_mdns_service_snapshot(s)
    s, = _snapshot(state, at="221")
    assert s.has_fresh_ptr
    assert s.fresh_targets == ()
    assert "target=not-freshly-observed" in format_mdns_service_snapshot(s)
    s, = _snapshot(state, at="4600")
    assert not s.has_fresh_ptr
    assert s.latest_records
    assert "no-fresh-ptr" in format_mdns_service_snapshot(s)
    assert "offline" not in format_mdns_service_snapshot(s)


def test_ttl_zero_goodbye_replaces_latest_ptr_not_entire_instance():
    state = MDNSServiceEvidenceState()
    _observe(state, at="100")
    _observe(state, at="110", ptr_ttl=0, srv=False, txt=False, address=False)
    s, = _snapshot(state, at="110")
    assert not s.has_fresh_ptr
    assert s.observation_count == 2
    assert s.fresh_targets  # original SRV has independent remaining TTL
    ptr = next(r for r in s.latest_records if r.kind == "PTR")
    assert ptr.record.goodbye_candidate
    assert ptr.record.wire.ttl == 0
    assert "no-current-service-claim" in format_mdns_service_snapshot(s)
    _observe(state, at="111", srv=False, txt=False, address=False)
    assert _snapshot(state, at="111")[0].has_fresh_ptr


def test_late_out_of_order_goodbye_cannot_erase_more_recent_positive_record():
    state = MDNSServiceEvidenceState()
    _observe(state, at="110")
    _observe(state, at="100", ptr_ttl=0, srv=False, txt=False, address=False)
    s, = _snapshot(state, at="110")
    assert s.observation_count == 2
    assert s.has_fresh_ptr
    assert s.first_seen == Decimal("100")
    assert s.last_seen == Decimal("110")


def test_replays_from_different_interfaces_are_not_fused():
    state = MDNSServiceEvidenceState()
    _observe(state, at="100", interface="en0")
    _observe(state, at="100", interface="en5", family=6)
    assert len(_snapshot(state)) == 2
    assert [s.interface for s in _snapshot(state)] == ["en0", "en5"]


def test_one_service_type_with_two_instances_keeps_distinct_records():
    state = MDNSServiceEvidenceState()
    _observe(state, at="100")
    _observe(state, at="101", instance=_name("Other", "_demo", "_tcp", "local"))
    assert state.instance_count == 2
    assert {s.instance.text for s in _snapshot(state, "101")} == {
        "Studio._demo._tcp.local", "Other._demo._tcp.local",
    }


def test_srv_conflict_is_retained_not_silently_resolved():
    state = MDNSServiceEvidenceState()
    _observe(state, at="100", srv_port=4070)
    _observe(state, at="110", srv_port=55000)
    s, = _snapshot(state, "110")
    assert s.has_conflicting_fresh_srv
    assert {r.value.port for r in s.fresh_targets} == {4070, 55000}
    assert "conflicting-SRV-targets=observed" in format_mdns_service_snapshot(s)


def test_different_ip_families_and_addresses_do_not_split_instances():
    state = MDNSServiceEvidenceState()
    _observe(state, at="100", family=4, extra_addr=True)
    _observe(state, at="101", family=6, extra_addr=True)
    s, = _snapshot(state, "101")
    assert s.observation_count == 2
    assert {r.value for r in s.fresh_addresses} == {
        "192.0.2.25", "2001:db8::25"
    }


def test_missing_same_message_ptr_does_not_attach_srv_or_address():
    state = MDNSServiceEvidenceState()
    _, ads = _observe(state, at="100", srv=False, txt=False, address=False)
    assert len(ads) == 1
    _, later = _observe(state, at="101", include_ptr=False)
    assert later == ()
    s, = _snapshot(state, "101")
    assert s.fresh_targets == ()
    assert len(s.latest_records) == 1


def test_queries_and_known_answers_are_not_promoted_to_service_state():
    state = MDNSServiceEvidenceState()
    _, ads = _observe(state, response=False)
    assert ads == ()
    assert state.instance_count == 0
    assert state.snapshots(Decimal("100")) == ()


def test_limits_bound_record_history_and_instance_counts():
    state = MDNSServiceEvidenceState(
        max_instances=1, max_records_per_instance=2, max_history=2,
    )
    _observe(state, at="100", extra_addr=True)
    _observe(state, at="101", extra_addr=True)
    _observe(state, at="102", instance=_name("Other", "_demo", "_tcp", "local"))
    assert state.instance_count == 1
    assert len(state.history) == 2
    s, = _snapshot(state, "102")
    assert s.instance.text == "Other._demo._tcp.local"
    assert len(s.latest_records) <= 2


@pytest.mark.parametrize("settings", [
    {"max_instances": 0}, {"max_records_per_instance": -1},
    {"max_history": True}, {"max_instances": 0.1},
])
def test_bad_caps_rejected(settings):
    with pytest.raises(ValueError):
        MDNSServiceEvidenceState(**settings)


def test_snapshot_rejects_invalid_or_previous_instant():
    state = MDNSServiceEvidenceState()
    _observe(state, at="100")
    with pytest.raises(ValueError, match="precedes"):
        _snapshot(state, "99")
    for value in (Decimal("NaN"), Decimal("Infinity")):
        with pytest.raises(ValueError, match="finite"):
            state.snapshots(value)


def test_snapshots_immutable_and_include_provenance():
    state = MDNSServiceEvidenceState()
    source, ads = _observe(state)
    snap, = _snapshot(state)
    assert snap.latest_records[0].source is source
    assert snap.latest_records[0].record is ads[0].ptr_record
    with pytest.raises(FrozenInstanceError):
        snap.observation_count = 12


def test_snapshot_display_spaces_are_readable_without_changing_raw_name():
    state = MDNSServiceEvidenceState()
    wire_instance = _name("Test Desk Mac", "_demo", "_tcp", "local")
    _observe(state, at="100", instance=wire_instance)
    snapshot, = _snapshot(state)
    assert snapshot.instance.labels[0] == b"Test Desk Mac"
    assert snapshot.instance.text == r"Test\x20Desk\x20Mac._demo._tcp.local"
    assert 'instance="Test Desk Mac._demo._tcp.local"' in (
        format_mdns_service_snapshot(snapshot)
    )
    assert snapshot.observation_count == 1
