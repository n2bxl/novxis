import pytest

from novxis.protocols.ethernet import (
    ETHERNET_HEADER_LENGTH,
    EthernetParseError,
    parse_ethernet,
)


def test_parse_ethernet_decodes_header_and_preserves_payload():
    data = bytes.fromhex(
        "ffffffffffff"
        "5c475e67b325"
        "0806"
        "01020304"
    )

    frame = parse_ethernet(data)

    assert frame.destination == bytes.fromhex("ffffffffffff")
    assert frame.source == bytes.fromhex("5c475e67b325")
    assert frame.ether_type == 0x0806
    assert frame.payload == bytes.fromhex("01020304")


def test_parse_ethernet_allows_header_without_payload():
    data = b"\x00" * ETHERNET_HEADER_LENGTH

    frame = parse_ethernet(data)

    assert frame.payload == b""


def test_parse_ethernet_rejects_truncated_header():
    with pytest.raises(EthernetParseError, match="at least 14 bytes"):
        parse_ethernet(b"\x00" * 13)
