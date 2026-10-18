"""Synthetic privacy-safe mDNS message and evidence-semantics tests."""

from ipaddress import IPv6Address

import pytest

from novxis.protocols.dns import DNSParseError, parse_dns
from novxis.protocols.mdns import (
    MDNS_IPV4_MULTICAST,
    MDNS_IPV6_MULTICAST,
    MDNS_UDP_PORT,
    parse_mdns,
)


def _name(*labels: str) -> bytes:
    return b"".join(
        bytes([len(label.encode("ascii"))]) + label.encode("ascii")
        for label in labels
    ) + b"\x00"


def _header(*, response=False, questions=0, answers=0, authority=0,
            additional=0, transaction_id=0) -> bytes:
    return (
        transaction_id.to_bytes(2, "big")
        + (0x8400 if response else 0).to_bytes(2, "big")
        + questions.to_bytes(2, "big")
        + answers.to_bytes(2, "big")
        + authority.to_bytes(2, "big")
        + additional.to_bytes(2, "big")
    )


def _question(name: bytes, kind=12, cls=1) -> bytes:
    return name + kind.to_bytes(2, "big") + cls.to_bytes(2, "big")


def _rr(name: bytes, kind: int, rdata: bytes, *, cls=1, ttl=120) -> bytes:
    return (
        name
        + kind.to_bytes(2, "big")
        + cls.to_bytes(2, "big")
        + ttl.to_bytes(4, "big")
        + len(rdata).to_bytes(2, "big")
        + rdata
    )


SERVICE = _name("_demo", "_tcp", "local")
INSTANCE = _name("Workstation", "_demo", "_tcp", "local")
HOST = _name("node", "local")


def test_mdns_port_and_multicast_addresses_are_explicit():
    assert MDNS_UDP_PORT == 5353
    assert MDNS_IPV4_MULTICAST == "224.0.0.251"
    assert MDNS_IPV6_MULTICAST == "ff02::fb"


def test_query_masks_qu_class_bit_and_preserves_raw_question():
    data = (
        _header(questions=2, transaction_id=0x1234)
        + _question(SERVICE, cls=0x8001)
        + _question(HOST, kind=1, cls=1)
    )
    msg = parse_mdns(data)
    assert not msg.is_response
    assert msg.dns.header.transaction_id == 0x1234
    assert [q.response_mode for q in msg.questions] == ["QU", "QM"]
    assert [q.question_class for q in msg.questions] == [1, 1]
    assert msg.questions[0].wire.qclass == 0x8001
    assert msg.questions[0].wire.name.text == "_demo._tcp.local"


def test_any_class_with_qu_flag_is_not_rewritten_as_in():
    msg = parse_mdns(_header(questions=1) + _question(SERVICE, cls=0x80FF))
    assert msg.questions[0].question_class == 255
    assert msg.questions[0].response_mode == "QU"
    assert msg.questions[0].wire.qclass == 0x80FF


def test_query_answer_records_are_known_answer_hints_not_advertisements():
    msg = parse_mdns(
        _header(questions=1, answers=1)
        + _question(SERVICE)
        + _rr(b"\xc0\x0c", 12, INSTANCE, cls=0x8001, ttl=75)
    )
    assert not msg.is_response
    assert len(msg.known_answers) == 1
    r = msg.known_answers[0]
    assert r.is_known_answer
    assert r.section == "answer"
    assert r.role == "known_answer"
    assert r.record_class == 1
    assert r.class_high_bit_set  # Retained anomaly on a query RR.
    assert not r.cache_flush  # Only a *response* RR can request cache flush.
    assert r.wire.rclass == 0x8001
    assert r.wire.decoded_data == "Workstation._demo._tcp.local"
    assert r.wire.ttl == 75
    assert msg.records == msg.answers


def test_response_cache_flush_masks_class_for_address_decoding():
    raw_rr = _rr(HOST, 1, b"\xc0\x00\x02\x2a", cls=0x8001)
    msg = parse_mdns(_header(response=True, answers=1) + raw_rr)
    record = msg.answers[0]
    assert msg.is_response
    assert msg.known_answers == ()
    assert record.role == "response_answer"
    assert record.cache_flush
    assert record.record_class == 1
    assert record.wire.rclass == 0x8001
    assert record.wire.decoded_data == "192.0.2.42"
    assert not record.goodbye_candidate


def test_classic_dns_decoder_does_not_mask_class_high_bit():
    raw = _header(response=True, answers=1) + _rr(
        HOST, 1, b"\xc0\x00\x02\x2a", cls=0x8001
    )
    assert parse_dns(raw).answers[0].decoded_data is None
    assert parse_mdns(raw).answers[0].wire.decoded_data == "192.0.2.42"


def test_ipv6_answer_with_cache_flush_retains_aaaa_address():
    ip = IPv6Address("2001:db8::10")
    msg = parse_mdns(
        _header(response=True, answers=1)
        + _rr(HOST, 28, ip.packed, cls=0x8001)
    )
    assert msg.answers[0].wire.decoded_data == str(ip)
    assert msg.answers[0].cache_flush


def test_response_ptr_remains_shared_record_without_cache_flush():
    msg = parse_mdns(
        _header(response=True, answers=1)
        + _rr(SERVICE, 12, INSTANCE, cls=1)
    )
    r = msg.answers[0]
    assert r.wire.decoded_data == "Workstation._demo._tcp.local"
    assert not r.cache_flush


def test_query_authority_records_are_not_promoted_to_answer_evidence():
    msg = parse_mdns(
        _header(questions=1, authority=1)
        + _question(HOST, kind=255)
        + _rr(HOST, 1, b"\xc0\x00\x02\x08", cls=0x8001)
    )
    assert msg.has_probe_authority_records
    assert msg.authorities[0].role == "query_authority"
    assert not msg.authorities[0].cache_flush
    assert not msg.authorities[0].is_known_answer
    assert msg.known_answers == ()


def test_response_additional_and_authority_are_separate_from_answer_section():
    msg = parse_mdns(
        _header(response=True, answers=1, authority=1, additional=1)
        + _rr(SERVICE, 12, INSTANCE)
        + _rr(HOST, 1, b"\xc0\x00\x02\x07", cls=0x8001)
        + _rr(HOST, 28, IPv6Address("2001:db8::2").packed, cls=0x8001)
    )
    assert [r.role for r in msg.records] == [
        "response_answer", "response_authority", "response_additional"
    ]
    assert [r.section for r in msg.records] == [
        "answer", "authority", "additional"
    ]
    assert len(msg.records) == 3


def test_goodbye_ttl_zero_is_a_candidate_only_in_responses():
    response = parse_mdns(
        _header(response=True, answers=1)
        + _rr(HOST, 1, b"\xc0\x00\x02\x07", ttl=0)
    )
    query = parse_mdns(
        _header(answers=1)
        + _rr(HOST, 1, b"\xc0\x00\x02\x07", ttl=0)
    )
    assert response.answers[0].goodbye_candidate
    assert not query.answers[0].goodbye_candidate
    assert query.answers[0].is_known_answer


def test_does_not_assume_no_question_response_is_unsolicited():
    msg = parse_mdns(
        _header(response=True, answers=1)
        + _rr(SERVICE, 12, INSTANCE)
    )
    assert msg.is_response
    assert not msg.questions
    # A response without a Question Section may still answer a prior query.
    assert not hasattr(msg, "unsolicited")
    assert not hasattr(msg, "announcer_identity")


def test_srv_and_txt_remain_raw_until_dns_sd_semantic_decoder_is_added():
    srv = b"\x00\x00\x00\x00\x0f\xe6" + HOST
    txt = b"\x09CPath=/zc"
    msg = parse_mdns(
        _header(response=True, answers=2)
        + _rr(INSTANCE, 33, srv, cls=0x8001)
        + _rr(INSTANCE, 16, txt, cls=0x8001)
    )
    assert [r.wire.rtype for r in msg.answers] == [33, 16]
    assert msg.answers[0].wire.rdata == srv
    assert msg.answers[1].wire.rdata == txt
    assert all(r.wire.decoded_data is None for r in msg.answers)


def test_unknown_record_type_and_class_keep_raw_evidence():
    msg = parse_mdns(
        _header(response=True, answers=1)
        + _rr(HOST, 65000, b"\x00\x7f", cls=0x8003)
    )
    r = msg.answers[0]
    assert r.record_class == 3
    assert r.class_high_bit_set and r.cache_flush
    assert r.wire.rdata == b"\x00\x7f"
    assert r.wire.decoded_data is None


@pytest.mark.parametrize("raw", [
    b"",
    _header(questions=1) + b"\xc0\xff",
    _header(response=True, answers=1)
    + _rr(HOST, 1, b"\x01", cls=0x8001),
    _header(response=True, answers=1)
    + _rr(HOST, 12, b"\xc0\xff", cls=0x8001),
])
def test_malformed_mdns_message_fails_closed(raw):
    with pytest.raises(DNSParseError):
        parse_mdns(raw)
