import pytest

from novxis.protocols.arp import ARPParseError, parse_arp
from novxis.protocols.ethernet import parse_ethernet


def test_parse_observed_74_byte_ethernet_arp_frame_preserves_32_trailing_zeros():
    raw = bytes.fromhex(
        "ffffffffffff"
        "5c475e67b325"
        "0806"
        "0001"
        "0800"
        "06"
        "04"
        "0001"
        "5c475e67b325"
        "c0a8041e"
        "000000000000"
        "c0a8041e"
    ) + (b"\x00" * 32)

    ethernet = parse_ethernet(raw)
    arp = parse_arp(ethernet.payload)

    assert len(raw) == 74
    assert arp.hardware_type == 1
    assert arp.protocol_type == 0x0800
    assert arp.hardware_length == 6
    assert arp.protocol_length == 4
    assert arp.opcode == 1
    assert arp.sender_hardware == bytes.fromhex("5c475e67b325")
    assert arp.sender_protocol == bytes([192, 168, 4, 30])
    assert arp.target_hardware == b"\x00" * 6
    assert arp.target_protocol == bytes([192, 168, 4, 30])
    assert arp.trailing_bytes == b"\x00" * 32


def test_parse_arp_uses_declared_hardware_and_protocol_lengths():
    data = (
        bytes.fromhex("1234abcd02030007")
        + b"AB"
        + b"one"
        + b"CD"
        + b"two"
        + b"\xaa\xbb"
    )

    arp = parse_arp(data)

    assert arp.hardware_type == 0x1234
    assert arp.protocol_type == 0xABCD
    assert arp.hardware_length == 2
    assert arp.protocol_length == 3
    assert arp.opcode == 7
    assert arp.sender_hardware == b"AB"
    assert arp.sender_protocol == b"one"
    assert arp.target_hardware == b"CD"
    assert arp.target_protocol == b"two"
    assert arp.trailing_bytes == b"\xaa\xbb"


def test_parse_arp_preserves_nonzero_trailing_bytes():
    logical = bytes.fromhex(
        "0001"
        "0800"
        "06"
        "04"
        "0002"
        "9cebe887e189"
        "c0a8044e"
        "6497147578b2"
        "c0a80401"
    )
    trailing = bytes.fromhex("deadbeef")

    arp = parse_arp(logical + trailing)

    assert arp.trailing_bytes == trailing


def test_parse_arp_rejects_incomplete_fixed_header():
    with pytest.raises(ARPParseError, match="at least 8"):
        parse_arp(b"\x00" * 7)


def test_parse_arp_rejects_bytes_shorter_than_declared_lengths():
    data = bytes.fromhex("0001080006040001") + (b"\x00" * 19)

    with pytest.raises(ARPParseError, match="requiring 28 bytes; got 27"):
        parse_arp(data)
