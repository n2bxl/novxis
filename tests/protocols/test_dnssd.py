"""Synthetic SRV/TXT RDATA tests with no private service identifiers."""

from dataclasses import FrozenInstanceError
from ipaddress import IPv4Address

import pytest

from novxis.protocols.dns import (
    DNSParseError, DNSResourceRecord, parse_dns, read_dns_name_rdata,
)
from novxis.protocols.dnssd import (
    DNSSDParseError, parse_dnssd_srv, parse_dnssd_txt,
)


def _name(*parts: str) -> bytes:
    return b"".join(bytes((len(p),)) + p.encode() for p in parts) + b"\x00"


def _rr(owner: bytes, kind: int, value: bytes, cls=0x8001):
    return (owner + kind.to_bytes(2, "big") + cls.to_bytes(2, "big")
            + (120).to_bytes(4, "big") + len(value).to_bytes(2, "big") + value)


def _message_with_srv(target: bytes, priority=2, weight=5, port=4070):
    question = _name("host", "local") + b"\x00\x01\x00\x01"
    srv_data = (
        priority.to_bytes(2, "big") + weight.to_bytes(2, "big")
        + port.to_bytes(2, "big") + target
    )
    response_header = b"\x00\x00\x84\x00\x00\x01\x00\x01" + b"\x00" * 4
    return (
        response_header + question
        + _rr(_name("Office", "_demo", "_tcp", "local"), 33, srv_data)
    )


def _txt_rr(payload: bytes, cls=0x8001) -> DNSResourceRecord:
    return DNSResourceRecord(
        name=parse_dns(
            b"\x00\x00\x00\x00\x00\x01" + bytes(6)
            + _name("Office", "_demo", "_tcp", "local") + b"\x00\x10\x00\x01"
        ).questions[0].name,
        rtype=16, rclass=cls, ttl=4500,
        rdata=payload, rdata_offset=0,
    )


def test_srv_decodes_message_relative_compressed_target():
    # The first question's QNAME starts at offset 12; SRV target points to it.
    msg_bytes = _message_with_srv(b"\xc0\x0c")
    record = parse_dns(msg_bytes, interpret_mdns_class_bit=True).answers[0]
    parsed = parse_dnssd_srv(msg_bytes, record)
    assert (parsed.priority, parsed.weight, parsed.port) == (2, 5, 4070)
    assert parsed.target.text == "host.local"
    assert record.rdata.endswith(b"\xc0\x0c")


def test_srv_uncompressed_target_and_root_target_are_preserved():
    packet = _message_with_srv(_name("server", "local"), port=5000)
    rr = parse_dns(packet, interpret_mdns_class_bit=True).answers[0]
    assert parse_dnssd_srv(packet, rr).target.text == "server.local"
    root_packet = _message_with_srv(b"\x00", port=0)
    root_rr = parse_dns(root_packet, interpret_mdns_class_bit=True).answers[0]
    assert parse_dnssd_srv(root_packet, root_rr).target.text == "."


@pytest.mark.parametrize("bad", [
    b"", b"\x00" * 6, b"\x00" * 6 + b"\xc0",
    b"\x00" * 6 + b"\x03abc\x00\x01",
])
def test_srv_invalid_rdata_rejected(bad):
    packet = _message_with_srv(bad)
    rr = parse_dns(packet, interpret_mdns_class_bit=True).answers[0]
    with pytest.raises((DNSSDParseError, DNSParseError)):
        parse_dnssd_srv(packet, rr)


def test_srv_rejects_record_from_another_message():
    packet = _message_with_srv(b"\xc0\x0c")
    rr = parse_dns(packet, interpret_mdns_class_bit=True).answers[0]
    alternate = bytearray(packet)
    alternate[rr.rdata_offset + 4] = 0x13
    with pytest.raises(DNSSDParseError, match="does not match"):
        parse_dnssd_srv(bytes(alternate), rr)


def test_srv_rejects_incorrect_rrtype_or_class():
    packet = _message_with_srv(b"\xc0\x0c")
    record = parse_dns(packet, interpret_mdns_class_bit=True).answers[0]
    from dataclasses import replace
    with pytest.raises(DNSSDParseError, match="Expected SRV"):
        parse_dnssd_srv(packet, replace(record, rtype=16))
    with pytest.raises(DNSSDParseError, match="class"):
        parse_dnssd_srv(packet, replace(record, rclass=0x8003))


def test_txt_preserves_arbitrary_bytes_and_empty_values():
    strings = [b"CPath=/zc", b"enabled", b"x=", b"\xff=\x00\x80", b""]
    wire = b"".join(bytes((len(s),)) + s for s in strings)
    result = parse_dnssd_txt(_txt_rr(wire))
    assert [entry.raw for entry in result.entries] == strings
    assert [entry.key for entry in result.entries] == [
        b"CPath", b"enabled", b"x", b"\xff", b""
    ]
    assert [entry.value for entry in result.entries] == [
        b"/zc", None, b"", b"\x00\x80", None
    ]
    with pytest.raises(FrozenInstanceError):
        result.entries[0].key = b"changed"


def test_txt_empty_rdata_is_preserved_without_guessed_value():
    assert parse_dnssd_txt(_txt_rr(b"")).entries == ()


@pytest.mark.parametrize("wire", [b"\x04abc", b"\x02", b"\xffhey"])
def test_txt_malformed_length_fails_closed(wire):
    with pytest.raises(DNSSDParseError, match="extends beyond"):
        parse_dnssd_txt(_txt_rr(wire))


def test_txt_rejects_wrong_type_or_class():
    from dataclasses import replace
    rr = _txt_rr(b"\x00")
    with pytest.raises(DNSSDParseError, match="Expected TXT"):
        parse_dnssd_txt(replace(rr, rtype=33))
    with pytest.raises(DNSSDParseError, match="class"):
        parse_dnssd_txt(replace(rr, rclass=3))


def test_name_rdata_reader_rejects_extra_bytes_and_bounds():
    packet = _message_with_srv(_name("host", "local"))
    rr = parse_dns(packet, interpret_mdns_class_bit=True).answers[0]
    start = rr.rdata_offset + 6
    end = rr.rdata_offset + len(rr.rdata)
    assert read_dns_name_rdata(packet, start=start, end=end).text == "host.local"
    with pytest.raises(DNSParseError, match="extra bytes"):
        read_dns_name_rdata(packet + b"\x00", start=start, end=end + 1)
    with pytest.raises(DNSParseError, match="boundaries"):
        read_dns_name_rdata(packet, start=end, end=end)
