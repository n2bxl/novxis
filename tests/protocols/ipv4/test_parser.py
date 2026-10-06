import pytest

from novxis.protocols.ipv4 import IPv4ParseError, parse_ipv4


STANDARD_DATAGRAM = bytes.fromhex(
    "45"
    "00"
    "001c"
    "1234"
    "4000"
    "40"
    "01"
    "abcd"
    "c000020a"
    "c6336414"
    "08000000deadbeef"
)


def test_parse_ipv4_decodes_standard_header_and_payload():
    datagram = parse_ipv4(STANDARD_DATAGRAM)

    assert datagram.version == 4
    assert datagram.ihl == 5
    assert datagram.header_length == 20
    assert datagram.dscp == 0
    assert datagram.ecn == 0
    assert datagram.total_length == 28
    assert datagram.identification == 0x1234
    assert datagram.flags == 0b010
    assert datagram.fragment_offset == 0
    assert datagram.ttl == 64
    assert datagram.protocol == 1
    assert datagram.header_checksum == 0xABCD
    assert datagram.source == bytes([192, 0, 2, 10])
    assert datagram.destination == bytes([198, 51, 100, 20])
    assert datagram.options == b""
    assert datagram.payload == bytes.fromhex("08000000deadbeef")
    assert datagram.trailing_bytes == b""


def test_parse_ipv4_uses_ihl_to_preserve_options():
    data = bytes.fromhex(
        "46"
        "2f"
        "001c"
        "beef"
        "2001"
        "20"
        "11"
        "0102"
        "cb007101"
        "cb007102"
        "01010100"
        "aabbccdd"
    )

    datagram = parse_ipv4(data)

    assert datagram.ihl == 6
    assert datagram.header_length == 24
    assert datagram.dscp == 11
    assert datagram.ecn == 3
    assert datagram.flags == 0b001
    assert datagram.fragment_offset == 1
    assert datagram.ttl == 32
    assert datagram.protocol == 17
    assert datagram.options == bytes.fromhex("01010100")
    assert datagram.payload == bytes.fromhex("aabbccdd")


def test_parse_ipv4_preserves_bytes_beyond_total_length():
    datagram = parse_ipv4(STANDARD_DATAGRAM + bytes.fromhex("0000dead"))

    assert datagram.total_length == 28
    assert datagram.trailing_bytes == bytes.fromhex("0000dead")


def test_parse_ipv4_rejects_truncated_minimum_header():
    with pytest.raises(IPv4ParseError, match="at least 20 bytes"):
        parse_ipv4(b"\x45" + (b"\x00" * 18))


def test_parse_ipv4_rejects_non_ipv4_version():
    data = bytes([0x65]) + STANDARD_DATAGRAM[1:]

    with pytest.raises(IPv4ParseError, match="version 6"):
        parse_ipv4(data)


def test_parse_ipv4_rejects_ihl_smaller_than_five_words():
    data = bytes([0x44]) + STANDARD_DATAGRAM[1:]

    with pytest.raises(IPv4ParseError, match="IHL must be at least 5"):
        parse_ipv4(data)


def test_parse_ipv4_rejects_truncated_options_header():
    data = bytes([0x46]) + STANDARD_DATAGRAM[1:]

    with pytest.raises(IPv4ParseError, match="24-byte header"):
        parse_ipv4(data[:23])


def test_parse_ipv4_rejects_total_length_smaller_than_header():
    data = bytearray(STANDARD_DATAGRAM)
    data[2:4] = (19).to_bytes(2, byteorder="big")

    with pytest.raises(IPv4ParseError, match="smaller than header length 20"):
        parse_ipv4(bytes(data))


def test_parse_ipv4_rejects_truncated_declared_datagram():
    data = bytearray(STANDARD_DATAGRAM)
    data[2:4] = (40).to_bytes(2, byteorder="big")

    with pytest.raises(IPv4ParseError, match="declares 40 bytes; got 28"):
        parse_ipv4(bytes(data))
