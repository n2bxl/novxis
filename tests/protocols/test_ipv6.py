"""Bounded IPv6 fixed-header decoding without Scapy protocol interpretation."""

from ipaddress import IPv6Address

import pytest

from novxis.protocols.ipv6 import IPv6ParseError, parse_ipv6


def _packet(
    payload=b"abcd", *, next_header=17, payload_length=None,
    version=6, traffic_class=0x5A, flow_label=0xABCDE, hop_limit=255,
    trailing=b"",
):
    first_word = (
        (version << 28) | (traffic_class << 20) | flow_label
    ).to_bytes(4, "big")
    declared = len(payload) if payload_length is None else payload_length
    return (
        first_word + declared.to_bytes(2, "big")
        + bytes((next_header, hop_limit))
        + IPv6Address("fe80::1").packed
        + IPv6Address("ff02::fb").packed
        + payload + trailing
    )


def test_parses_fixed_header_and_preserves_trailing_bytes():
    msg = parse_ipv6(_packet(trailing=b"\x00\x00"))
    assert msg.version == 6
    assert msg.traffic_class == 0x5A
    assert msg.flow_label == 0xABCDE
    assert msg.next_header == 17
    assert msg.hop_limit == 255
    assert msg.source == IPv6Address("fe80::1").packed
    assert msg.destination == IPv6Address("ff02::fb").packed
    assert msg.payload == b"abcd"
    assert msg.payload_length == 4
    assert msg.trailing_bytes == b"\x00\x00"


def test_zero_length_payload_is_not_assumed_to_be_a_jumbogram():
    msg = parse_ipv6(_packet(payload=b"abc", payload_length=0))
    assert msg.payload == b""
    assert msg.trailing_bytes == b"abc"


def test_next_header_is_preserved_not_interpreted_as_final_protocol():
    msg = parse_ipv6(_packet(next_header=44))
    assert msg.next_header == 44
    assert msg.payload == b"abcd"


@pytest.mark.parametrize("payload,error", [
    (b"", "fixed header"),
    (b"\x60" + b"\x00" * 38, "fixed header"),
    (_packet(version=4), "version"),
    (_packet(payload=b"abcd", payload_length=9), "declares"),
])
def test_invalid_ipv6_frames_fail_closed(payload,error):
    with pytest.raises(IPv6ParseError, match=error):
        parse_ipv6(payload)
