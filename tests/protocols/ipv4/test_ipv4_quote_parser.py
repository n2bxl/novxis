import pytest

from novxis.protocols.ipv4 import IPv4QuoteParseError, parse_ipv4_quote


def _original_datagram(total_length: int = 60) -> bytes:
    return (
        bytes.fromhex("4500")
        + total_length.to_bytes(2, "big")
        + bytes.fromhex("beef40004011abcd")
        + bytes([192, 0, 2, 10])
        + bytes([198, 51, 100, 20])
        + bytes.fromhex("c000829a00281234")
        + (b"x" * max(0, total_length - 28))
    )


def test_parse_ipv4_quote_accepts_truncated_original_datagram():
    quote = parse_ipv4_quote(_original_datagram()[:28])

    assert quote.source == bytes([192, 0, 2, 10])
    assert quote.destination == bytes([198, 51, 100, 20])
    assert quote.protocol == 17
    assert quote.total_length == 60
    assert quote.available_length == 28
    assert quote.payload_prefix == bytes.fromhex("c000829a00281234")
    assert quote.trailing_bytes == b""
    assert quote.is_truncated is True


def test_parse_ipv4_quote_marks_complete_quote_not_truncated():
    data = _original_datagram(total_length=28)

    quote = parse_ipv4_quote(data)

    assert quote.available_length == 28
    assert quote.total_length == 28
    assert quote.is_truncated is False


def test_parse_ipv4_quote_preserves_bytes_beyond_declared_datagram():
    data = _original_datagram(total_length=28) + bytes.fromhex("deadbeef")

    quote = parse_ipv4_quote(data)

    assert quote.payload_prefix == bytes.fromhex("c000829a00281234")
    assert quote.trailing_bytes == bytes.fromhex("deadbeef")
    assert quote.available_length == 32


def test_parse_ipv4_quote_rejects_incomplete_header():
    with pytest.raises(IPv4QuoteParseError, match="at least 20 bytes"):
        parse_ipv4_quote(b"\x45" + (b"\x00" * 18))
