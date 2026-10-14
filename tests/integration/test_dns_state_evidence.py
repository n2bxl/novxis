"""Phase 1D: integration tests for scoped DNS RR evidence and TTL freshness."""

from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.dns_state import DNSStatePipeline
from novxis.state.dns import DNSRelationshipState

CLIENT = bytes((192, 0, 2, 10))
RESOLVER = bytes((198, 51, 100, 53))
OTHER_RESOLVER = bytes((203, 0, 113, 53))


def _name(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    return b"".join(
        bytes((len(part),)) + part.encode("ascii")
        for part in name.rstrip(".").split(".")
    ) + b"\x00"


def _record(
    owner: str, kind: int, ttl: int, value: str, *, rr_class: int = 1
) -> bytes:
    if kind == 1:
        payload = IPv4Address(value).packed
    elif kind == 28:
        payload = IPv6Address(value).packed
    elif kind in (5, 12):
        payload = _name(value)
    else:
        payload = value.encode("ascii")
    return (
        _name(owner)
        + kind.to_bytes(2, "big")
        + rr_class.to_bytes(2, "big")
        + ttl.to_bytes(4, "big")
        + len(payload).to_bytes(2, "big")
        + payload
    )


def _frame(
    *, response: bool, timestamp: str, txid: int = 0x1234,
    question: str = "launcher.example.test", qtype: int = 1,
    answers: tuple[bytes, ...] = (), rcode: int = 0, truncated: bool = False,
    interface: str = "en0", resolver: bytes = RESOLVER, client: bytes = CLIENT,
    client_port: int = 55555,
) -> CapturedFrame:
    flags = (
        (0x8000 if response else 0)
        | (0x0200 if truncated else 0)
        | (rcode if response else 0)
    )
    question_bytes = _name(question) + qtype.to_bytes(2, "big") + b"\x00\x01"
    dns = (
        txid.to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + b"\x00\x01"  # one question
        + len(answers).to_bytes(2, "big")
        + bytes(4)
        + question_bytes + b"".join(answers)
    )
    src_port, dst_port = (53, client_port) if response else (client_port, 53)
    udp = (
        src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big")
        + (8 + len(dns)).to_bytes(2, "big") + b"\x00\x00" + dns
    )
    ip_src, ip_dst = (resolver, client) if response else (client, resolver)
    ipv4 = (
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x01\x40\x00\x40\x11\x00\x00"
        + ip_src + ip_dst + udp
    )
    raw = bytes.fromhex("0211223344550266778899aa0800") + ipv4
    return CapturedFrame(
        timestamp=Decimal(timestamp), interface=interface,
        data=raw, captured_length=len(raw), original_length=len(raw),
        link_type=1,
    )


def _exchange(pipe: DNSStatePipeline, *, request_time="100.000",
              response_time="100.005", request_overrides=None,
              response_overrides=None):
    request_overrides = request_overrides or {}
    response_overrides = response_overrides or {}
    request = pipe.process(_frame(
        response=False, timestamp=request_time, **request_overrides
    ))
    reply = pipe.process(_frame(
        response=True, timestamp=response_time, **response_overrides
    ))
    assert request is not None and reply is not None
    return request, reply


CHAIN = (
    _record("launcher.example.test", 5, 130, "edge.example.test"),
    _record("edge.example.test", 5, 1208, "route.example.test"),
    _record("route.example.test", 5, 38, "backend.example.test"),
    _record("backend.example.test", 1, 8, "192.0.2.26"),
)


def test_cname_chain_each_record_has_its_own_ttl_and_original_provenance():
    pipe = DNSStatePipeline()
    query, reply = _exchange(
        pipe, response_overrides={"answers": CHAIN},
    )
    assert query.exchange is None and query.records == ()
    assert reply.exchange is not None
    assert len(reply.records) == 4
    assert reply.exchange.duration == Decimal("0.005")
    assert tuple(e.ttl_seconds for e in reply.records) == (130, 1208, 38, 8)
    assert tuple(e.record_type for e in reply.records) == (5, 5, 5, 1)
    assert reply.records[0].owner.text == "launcher.example.test"
    assert reply.records[-1].value == "192.0.2.26"
    assert all(e.source is reply.exchange for e in reply.records)
    assert all(
        e.record is reply.observation.message.answers[index]
        for index, e in enumerate(reply.records)
    )
    assert all(e.interface == "en0" and e.requester_ipv4 == CLIENT
               and e.resolver_ipv4 == RESOLVER for e in reply.records)
    assert pipe.state.arp_bindings == ()
    assert pipe.state.dhcpv4_acknowledgments == ()


def test_expiry_is_per_record_and_history_remains_available():
    pipe = DNSStatePipeline()
    _, reply = _exchange(pipe, response_overrides={"answers": CHAIN})
    state = pipe.state.dns_relationships
    assert len(state.fresh_records(Decimal("108"))) == 4
    assert len(state.fresh_records(Decimal("109"))) == 3
    assert len(state.fresh_records(Decimal("140"))) == 2
    assert len(state.fresh_records(Decimal("231"))) == 1
    assert len(state.fresh_records(Decimal("1310"))) == 0
    assert len(state.history) == 4
    assert len(state.latest_records) == 4
    assert reply.records[3].expires_at == Decimal("108.005")
    assert reply.records[3].is_fresh(Decimal("108.005")) is False
    assert reply.records[3].is_fresh(Decimal("99")) is False


def test_two_A_addresses_remain_separate_independent_relationships():
    pipe = DNSStatePipeline()
    answers = (
        _record("service.example.test", 1, 60, "192.0.2.1"),
        _record("service.example.test", 1, 30, "192.0.2.2"),
    )
    _exchange(
        pipe,
        request_overrides={"question": "service.example.test"},
        response_overrides={"question": "service.example.test", "answers": answers},
    )
    state = pipe.state.dns_relationships
    assert {e.value for e in state.latest_records} == {"192.0.2.1", "192.0.2.2"}
    assert {e.value for e in state.fresh_records(Decimal("131"))} == {"192.0.2.1"}


def test_AAAA_and_PTR_are_independent_typed_evidence():
    pipe = DNSStatePipeline()
    _exchange(
        pipe, response_overrides={"answers": (
            _record("launcher.example.test", 28, 40, "2001:db8::1"),
            _record("10.2.0.192.in-addr.arpa", 12, 70, "router.example.test"),
        )},
    )
    assert {(e.record_type, e.value) for e in pipe.state.dns_relationships.latest_records} == {
        (28, "2001:db8::1"), (12, "router.example.test"),
    }


@pytest.mark.parametrize("rcode,truncated", [
    (3, False),  # NXDOMAIN: not absence of a network host
    (2, False),  # SERVFAIL
    (0, True),   # truncated DNS requires separate TCP follow-up
])
def test_failed_or_truncated_response_never_creates_positive_edges(rcode, truncated):
    pipe = DNSStatePipeline()
    _, reply = _exchange(
        pipe, response_overrides={
            "rcode": rcode, "truncated": truncated, "answers": CHAIN,
        },
    )
    assert reply.exchange is not None
    assert reply.records == ()
    assert pipe.state.dns_relationships.history == ()


def test_empty_noerror_answer_is_not_a_positive_relationship():
    pipe = DNSStatePipeline()
    _, reply = _exchange(pipe)
    assert reply.exchange is not None
    assert reply.records == ()
    assert pipe.state.dns_relationships.latest_records == ()


def test_unknown_rr_types_and_non_in_class_do_not_create_edges():
    pipe = DNSStatePipeline()
    _, reply = _exchange(
        pipe, response_overrides={"answers": (
            _record("launcher.example.test", 65, 20, "opaque"),
            _record("launcher.example.test", 1, 30, "192.0.2.26", rr_class=3),
        )},
    )
    assert reply.exchange is not None
    assert reply.records == ()


def test_zero_ttl_is_retained_historically_but_never_fresh():
    pipe = DNSStatePipeline()
    _, reply = _exchange(pipe, response_overrides={
        "answers": (_record("launcher.example.test", 1, 0, "192.0.2.26"),),
    })
    assert len(reply.records) == 1
    assert reply.records[0].ttl_seconds == 0
    assert pipe.state.dns_relationships.fresh_records(Decimal("100.005")) == ()
    assert len(pipe.state.dns_relationships.history) == 1


def test_same_RR_newer_observation_updates_latest_without_deleting_history():
    pipe = DNSStatePipeline()
    answers = (_record("launcher.example.test", 1, 30, "192.0.2.26"),)
    first = _exchange(
        pipe, response_overrides={"answers": answers}
    )[1].records[0]
    second = _exchange(
        pipe, request_time="105", response_time="105.008",
        request_overrides={"txid": 55},
        response_overrides={"txid": 55, "answers": answers},
    )[1].records[0]
    state = pipe.state.dns_relationships
    assert len(state.history) == 2
    assert state.history == (first, second)
    assert state.latest_records == (second,)
    assert second.expires_at == Decimal("135.008")


def test_out_of_order_replay_does_not_replace_newer_latest_RR():
    pipe = DNSStatePipeline()
    record = (_record("launcher.example.test", 1, 30, "192.0.2.26"),)
    newer = _exchange(
        pipe, request_time="200", response_time="200.005",
        response_overrides={"answers": record},
    )[1].records[0]
    older = _exchange(
        pipe, request_time="198", response_time="198.005",
        request_overrides={"txid": 33},
        response_overrides={"txid": 33, "answers": record},
    )[1].records[0]
    assert newer.observed_at > older.observed_at
    assert pipe.state.dns_relationships.latest_records == (newer,)
    assert pipe.state.dns_relationships.history == (newer, older)


def test_scope_isolates_resolver_interface_and_requester():
    pipe = DNSStatePipeline()
    answer = (_record("launcher.example.test", 1, 30, "192.0.2.26"),)
    for idx, kwargs in enumerate((
        {},
        {"interface": "en5"},
        {"resolver": OTHER_RESOLVER},
        {"client": bytes((192, 0, 2, 99))},
    )):
        _exchange(
            pipe,
            request_time=str(100 + idx * 20),
            response_time=str(100.005 + idx * 20),
            request_overrides={"txid": idx + 1, **kwargs},
            response_overrides={"txid": idx + 1, "answers": answer, **kwargs},
        )
    assert len(pipe.state.dns_relationships.latest_records) == 4


def test_unmatched_reply_does_not_create_relationships():
    pipe = DNSStatePipeline()
    orphan = pipe.process(_frame(
        response=True, timestamp="101", answers=CHAIN,
    ))
    assert orphan is not None and orphan.exchange is None and orphan.records == ()
    assert pipe.state.dns_relationships.history == ()


def test_history_and_latest_views_are_independently_bounded():
    state = DNSRelationshipState(max_records=1, max_history=2)
    pipe = DNSStatePipeline()
    for index, value in enumerate(("192.0.2.1", "192.0.2.2", "192.0.2.3")):
        pair = _exchange(
            pipe,
            request_time=str(100 + index), response_time=str(100.005 + index),
            request_overrides={"txid": index + 1},
            response_overrides={
                "txid": index + 1,
                "answers": (_record("launcher.example.test", 1, 60, value),),
            },
        )[1].exchange
        assert pair is not None
        state.observe_exchange(pair)
    assert len(state.latest_records) == 1
    assert state.latest_records[0].value == "192.0.2.3"
    assert tuple(record.value for record in state.history) == ("192.0.2.2", "192.0.2.3")


@pytest.mark.parametrize("kwargs", [
    {"max_records": 0}, {"max_records": True}, {"max_records": 1.5},
    {"max_history": 0}, {"max_history": -1}, {"max_history": False},
])
def test_invalid_state_limits_raise(kwargs):
    with pytest.raises(ValueError, match="positive integer"):
        DNSRelationshipState(**kwargs)


def test_nonfinite_freshness_time_is_rejected():
    pipe = DNSStatePipeline()
    _, reply = _exchange(pipe, response_overrides={"answers": CHAIN})
    with pytest.raises(ValueError, match="finite"):
        pipe.state.dns_relationships.fresh_records(Decimal("NaN"))
    with pytest.raises(ValueError, match="finite"):
        reply.records[0].is_fresh(Decimal("Infinity"))


# Phase 1D-B: framework-neutral relationship snapshots and console adapter.

from novxis.views.dns_relationships import project_dns_relationships
from novxis.presentation.dns_relationship_console import (
    format_dns_relationship_snapshot,
)


def test_dns_projection_is_immutable_semantic_data_not_console_text():
    pipe = DNSStatePipeline()
    _exchange(pipe, response_overrides={"answers": CHAIN})
    snapshot = project_dns_relationships(
        pipe.state.dns_relationships, as_of=Decimal("100.500"),
    )
    assert snapshot.mode == "latest"
    assert snapshot.fresh_count == 4
    assert snapshot.expired_count == 0
    assert len(snapshot.relationships) == 4
    alias = next(row for row in snapshot.relationships
                 if row.owner == "launcher.example.test")
    assert alias.record_type == "CNAME"
    assert alias.relationship_kind == "alias"
    assert alias.target == "edge.example.test"
    assert alias.ttl_seconds == 130
    assert alias.remaining_seconds == Decimal("129.505")
    assert alias.interface == "en0"
    assert alias.resolver_ipv4 == "198.51.100.53"
    assert alias.requester_ipv4 == "192.0.2.10"
    assert alias.transaction_id == 0x1234
    assert not hasattr(alias, "rendered_label")
    from dataclasses import FrozenInstanceError
    with pytest.raises(FrozenInstanceError):
        alias.target = "changed.invalid"


def test_projection_independently_ages_each_chain_link():
    pipe = DNSStatePipeline()
    _exchange(pipe, response_overrides={"answers": CHAIN})
    snapshot = project_dns_relationships(
        pipe.state.dns_relationships, as_of=Decimal("109"),
    )
    assert snapshot.fresh_count == 3
    assert snapshot.expired_count == 1
    a = next(row for row in snapshot.relationships if row.record_type == "A")
    assert a.freshness == "expired"
    assert a.remaining_seconds == Decimal(0)
    assert {row.freshness for row in snapshot.relationships
            if row.record_type == "CNAME"} == {"fresh"}


def test_projection_retains_separate_addresses_without_choosing_host_identity():
    pipe = DNSStatePipeline()
    records = (
        _record("service.example.test", 1, 20, "192.0.2.1"),
        _record("service.example.test", 1, 20, "192.0.2.2"),
    )
    _exchange(pipe, request_overrides={"question": "service.example.test"},
              response_overrides={"question": "service.example.test", "answers": records})
    snapshot = project_dns_relationships(
        pipe.state.dns_relationships, as_of=Decimal("105"),
    )
    assert {row.target for row in snapshot.relationships} == {"192.0.2.1", "192.0.2.2"}
    assert all(row.relationship_kind == "ipv4" for row in snapshot.relationships)


def test_latest_vs_history_projection_and_time_travel_from_retained_evidence():
    pipe = DNSStatePipeline()
    record = (_record("launcher.example.test", 1, 30, "192.0.2.26"),)
    _exchange(pipe, response_overrides={"answers": record})
    _exchange(
        pipe, request_time="105", response_time="105.005",
        request_overrides={"txid": 55},
        response_overrides={"txid": 55, "answers": record},
    )
    state = pipe.state.dns_relationships
    now = project_dns_relationships(state, as_of=Decimal("110"))
    history = project_dns_relationships(
        state, as_of=Decimal("110"), mode="history",
    )
    past = project_dns_relationships(state, as_of=Decimal("103"))
    assert len(now.relationships) == 1
    assert now.relationships[0].observed_at == Decimal("105.005")
    assert len(history.relationships) == 2
    assert past.relationships[0].observed_at == Decimal("100.005")
    assert len(state.history) == 2  # Projection is a pure read.


def test_no_future_evidence_leaks_into_as_of_snapshot():
    pipe = DNSStatePipeline()
    _exchange(pipe, response_overrides={"answers": CHAIN})
    snapshot = project_dns_relationships(
        pipe.state.dns_relationships, as_of=Decimal("100"),
    )
    assert snapshot.relationships == ()
    assert snapshot.fresh_count == snapshot.expired_count == 0


def test_projection_zero_ttl_and_exact_deadline_are_expired():
    pipe = DNSStatePipeline()
    answer = (_record("launcher.example.test", 1, 0, "192.0.2.26"),)
    _exchange(pipe, response_overrides={"answers": answer})
    now = project_dns_relationships(
        pipe.state.dns_relationships, as_of=Decimal("100.005"),
    )
    assert now.relationships[0].freshness == "expired"
    assert now.relationships[0].remaining_seconds == Decimal(0)


def test_text_renderer_is_terminal_only_and_preserves_ttl_provenance():
    pipe = DNSStatePipeline()
    _exchange(pipe, response_overrides={"answers": CHAIN})
    snapshot = project_dns_relationships(
        pipe.state.dns_relationships, as_of=Decimal("109"),
    )
    text = format_dns_relationship_snapshot(snapshot)
    assert "NOVXIS DNS relationship evidence" in text
    assert "fresh=3 expired=1" in text
    assert "[EXPIRED]" in text
    assert "CNAME" in text
    assert "ttl=8s" in text
    assert "resolver=198.51.100.53" in text
    assert "dns_id=0x1234" in text
    assert "not a DNS cache" in text


@pytest.mark.parametrize("as_of", [Decimal("NaN"), Decimal("Infinity"), 100])
def test_projection_rejects_invalid_as_of(as_of):
    with pytest.raises(ValueError, match="finite Decimal"):
        project_dns_relationships(DNSRelationshipState(), as_of=as_of)


def test_projection_rejects_unknown_mode():
    with pytest.raises(ValueError, match="mode"):
        project_dns_relationships(
            DNSRelationshipState(), as_of=Decimal("100"), mode="graph",
        )
