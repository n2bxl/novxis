"""Privacy-safe unit coverage of DNS wire parsing and compression boundaries."""

from ipaddress import IPv6Address

import pytest

from novxis.protocols.dns import DNSParseError, parse_dns


def _header(*, flags=0x0100, q=1, a=0, ns=0, ar=0, xid=0x1234):
    return (
        xid.to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + q.to_bytes(2, "big")
        + a.to_bytes(2, "big")
        + ns.to_bytes(2, "big")
        + ar.to_bytes(2, "big")
    )


QNAME = b"\x04node\x07example\x04test\x00"
QUESTION = QNAME + b"\x00\x01\x00\x01"
POINTER_TO_QNAME = b"\xc0\x0c"


def _rr(name: bytes, kind: int, payload: bytes, *, ttl=120, cls=1) -> bytes:
    return (
        name
        + kind.to_bytes(2, "big")
        + cls.to_bytes(2, "big")
        + ttl.to_bytes(4, "big")
        + len(payload).to_bytes(2, "big")
        + payload
    )


def test_dns_query_preserves_transaction_fields_and_question():
    message = parse_dns(_header() + QUESTION)
    assert message.header.transaction_id == 0x1234
    assert message.header.flags == 0x0100
    assert not message.header.is_response
    assert message.header.opcode == 0
    assert not message.header.truncated
    assert message.header.response_code == 0
    assert message.header.question_count == 1
    assert message.questions[0].name.labels == (b"node", b"example", b"test")
    assert message.questions[0].name.text == "node.example.test"
    assert (message.questions[0].qtype, message.questions[0].qclass) == (1, 1)
    assert not message.answers
    assert message.trailing_bytes == b""


def test_compressed_answer_and_mixed_record_types():
    ipv6 = IPv6Address("2001:db8::26").packed
    payload = (
        _header(flags=0x8180, a=3, ns=1, ar=1)
        + QUESTION
        + _rr(POINTER_TO_QNAME, 1, b"\xc0\x00\x02\x1a")
        + _rr(POINTER_TO_QNAME, 28, ipv6, ttl=60)
        # Pointer at offset 17 refers to "example.test" in the question.
        + _rr(POINTER_TO_QNAME, 5, b"\x04host\xc0\x11")
        + _rr(POINTER_TO_QNAME, 2, POINTER_TO_QNAME)
        + _rr(POINTER_TO_QNAME, 65000, b"\x00\xfe", cls=3)
        + b"\x00\x00"
    )
    message = parse_dns(payload)

    assert message.header.is_response
    assert message.header.response_code == 0
    assert [r.decoded_data for r in message.answers] == [
        "192.0.2.26", "2001:db8::26", "host.example.test"
    ]
    assert message.answers[0].ttl == 120
    assert message.answers[1].ttl == 60
    assert message.answers[0].rdata == b"\xc0\x00\x02\x1a"
    assert message.authorities[0].decoded_data == "node.example.test"
    assert message.additionals[0].rtype == 65000
    assert message.additionals[0].rdata == b"\x00\xfe"
    assert message.additionals[0].decoded_data is None
    assert message.trailing_bytes == b"\x00\x00"


def test_ptr_name_record_and_root_name():
    msg = parse_dns(
        _header(q=1, a=1)
        + b"\x00\x00\x0c\x00\x01"
        + _rr(b"\x00", 12, b"\x04node\x00")
    )
    assert msg.questions[0].name.text == "."
    assert msg.answers[0].decoded_data == "node"


def test_unknown_type_retains_uninterpreted_bytes():
    msg = parse_dns(
        _header(q=0, a=1)
        + _rr(b"\x00", 16, b"\x05hello")
    )
    assert msg.answers[0].rdata == b"\x05hello"
    assert msg.answers[0].decoded_data is None


def test_header_can_report_truncated_response_without_guessing_missing_data():
    msg = parse_dns(_header(flags=0x8203, q=0))
    assert msg.header.truncated
    assert msg.header.response_code == 3


@pytest.mark.parametrize(
    "data, message",
    [
        (b"", "header requires"),
        (b"\x00" * 11, "header requires"),
        (_header() + QNAME + b"\x00", "question fields"),
        (_header() + b"\x80", "Reserved DNS label"),
        (_header() + b"\xc0", "Truncated DNS compression pointer"),
        (_header() + b"\xc0\x0c", "not backward"),
        (_header() + b"\xc0\xff", "not backward"),
        (_header() + b"\xc0\x00", "targets the header"),
        (_header() + b"\x05abc", "Truncated DNS label"),
        (_header(a=1, q=0) + b"\x00\x00", "resource-record fields"),
        (
            _header(a=1, q=0) + b"\x00\x00\x01\x00\x01"
            + b"\x00\x00\x00\x3c\x00\x04\x7f",
            "RDLENGTH",
        ),
        (_header(q=0, a=1) + _rr(b"\x00", 1, b"\x7f"), "four octets"),
        (_header(q=0, a=1) + _rr(b"\x00", 28, b"x"), "16 octets"),
        (
            _header(q=0, a=1)
            + _rr(b"\x00", 5, b"\x04test\x00\x00"),
            "unexpected extra bytes",
        ),
        (
            _header(q=0, a=1)
            + _rr(b"\x00", 12, b"\x03ab"),
            "RDATA boundary",
        ),
        (
            _header(q=0, a=1)
            + _rr(b"\x00", 5, b"\xc0"),
            "RDATA boundary",
        ),
        (
            _header() + b"".join(b"\x3f" + b"x" * 63 for _ in range(4)) + b"\x00",
            "exceeds 255",
        ),
    ],
)
def test_invalid_or_truncated_messages_fail_closed(data, message):
    with pytest.raises(DNSParseError, match=message):
        parse_dns(data)


def test_compression_pointer_can_reference_previous_compressed_name():
    # First question supplies "example.test", second supplies "host.example.test"
    # via compression, and the final answer points to the compressed name.
    first = b"\x07example\x04test\x00\x00\x01\x00\x01"
    second = b"\x04host\xc0\x0c\x00\x01\x00\x01"
    second_name_offset = 12 + len(first)
    answer_name = (0xC000 | second_name_offset).to_bytes(2, "big")
    msg = parse_dns(
        _header(q=2, a=1)
        + first
        + second
        + _rr(answer_name, 1, b"\xc0\x00\x02\x17")
    )
    assert msg.questions[1].name.text == "host.example.test"
    assert msg.answers[0].name.text == "host.example.test"
    assert msg.answers[0].decoded_data == "192.0.2.23"


def test_wire_labels_remain_unmodified_and_are_escaped_for_display():
    msg = parse_dns(_header() + b"\x04A.\xffB\x00\x00\x01\x00\x01")
    assert msg.questions[0].name.labels == (b"A.\xffB",)
    assert msg.questions[0].name.text == r"A\x2e\xffB"
