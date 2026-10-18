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
