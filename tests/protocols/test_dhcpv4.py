"""Synthetic and privacy-safe tests for DHCPv4 wire decoding."""

import pytest

from novxis.protocols.dhcpv4 import (
    BOOTP_FIXED_HEADER_LENGTH,
    DHCPV4_MAGIC_COOKIE,
    DHCPv4ParseError,
    parse_dhcpv4,
)


def _option(code: int, value: bytes) -> bytes:
    return bytes((code, len(value))) + value


def _message(*, op: int = 1, options: bytes = b"\xff", xid: int = 0xB06B35DB) -> bytes:
    header = bytearray(BOOTP_FIXED_HEADER_LENGTH)
    header[0] = op
    header[1] = 1  # Ethernet hardware type.
    header[2] = 6  # 6-byte MAC address.
    header[3] = 0
    header[4:8] = xid.to_bytes(4, "big")
    header[10:12] = (0x8000).to_bytes(2, "big")
    header[28:34] = bytes.fromhex("021122334455")  # Synthetic locally administered MAC.
    header[108:112] = b"boot"
    if op == 2:
        header[16:20] = bytes((192, 0, 2, 26))
    return bytes(header) + DHCPV4_MAGIC_COOKIE + options


def test_decodes_request_header_and_requested_lease():
    options = (
        _option(53, b"\x03")
        + _option(50, bytes((192, 0, 2, 26)))
        + _option(51, (90 * 24 * 60 * 60).to_bytes(4, "big"))
        + b"\xff"
    )
    msg = parse_dhcpv4(_message(options=options))
    assert (msg.op, msg.htype, msg.hlen, msg.hops) == (1, 1, 6, 0)
    assert msg.xid == 0xB06B35DB
    assert msg.flags == 0x8000
    assert msg.chaddr == bytes.fromhex("021122334455")
    assert msg.chaddr_padding == bytes(10)
    assert msg.boot_file[:4] == b"boot"
    assert msg.ciaddr == bytes(4)
    assert msg.message_type == 3
    assert msg.option_values(50) == (bytes((192, 0, 2, 26)),)
    assert int.from_bytes(msg.option_values(51)[0], "big") == 7_776_000
    assert msg.options[0].offset == 240
    assert msg.end_seen and msg.trailing_bytes == b""


def test_decodes_ack_and_granted_lease_independently():
    options = (
        _option(53, b"\x05")
        + _option(51, (8 * 60 * 60).to_bytes(4, "big"))
        + _option(54, bytes((192, 0, 2, 1)))
        + b"\xff"
    )
    msg = parse_dhcpv4(_message(op=2, options=options))
    assert msg.op == 2
    assert msg.message_type == 5
    assert msg.yiaddr == bytes((192, 0, 2, 26))
    assert int.from_bytes(msg.option_values(51)[0], "big") == 28_800
    assert msg.option_values(54) == (bytes((192, 0, 2, 1)),)


def test_pad_end_and_trailing_bytes_are_separate_evidence():
    msg = parse_dhcpv4(_message(options=b"\x00" + _option(53, b"\x03") + b"\x00\xff\x00\x00"))
    assert msg.pad_offsets == (240, 244)
    assert msg.message_type == 3
    assert msg.end_seen
    assert msg.trailing_bytes == b"\x00\x00"
    assert msg.raw_options == b"\x00\x35\x01\x03\x00\xff\x00\x00"


def test_unknown_and_repeated_options_are_preserved_in_order():
    opts = _option(200, b"abc") + _option(200, b"def") + b"\xff"
    msg = parse_dhcpv4(_message(options=opts))
    assert msg.option_values(200) == (b"abc", b"def")
    assert [o.offset for o in msg.options] == [240, 245]
    assert msg.message_type is None


@pytest.mark.parametrize("opts", [b"", b"\x00", _option(12, b"ok")])
def test_no_end_option_is_reported_without_inventing_one(opts):
    msg = parse_dhcpv4(_message(options=opts))
    assert not msg.end_seen
    assert msg.raw_options == opts
    assert msg.trailing_bytes == b""


def test_ambiguous_or_malformed_message_type_is_not_inferred():
    for opts in (
        _option(53, b""),
        _option(53, b"\x01\x02"),
        _option(53, b"\x03") + _option(53, b"\x05"),
    ):
        assert parse_dhcpv4(_message(options=opts + b"\xff")).message_type is None


@pytest.mark.parametrize(
    "data, error",
    [
        (b"", "at least 240"),
        (b"\x00" * 239, "at least 240"),
        (_message()[:236] + b"\x00\x00\x00\x00\xff", "magic cookie"),
        (_message(options=b"\x35"), "lacks length"),
        (_message(options=b"\x35\x02\x03"), "only 1 remain"),
    ],
)
def test_rejects_truncated_or_invalid_payloads(data, error):
    with pytest.raises(DHCPv4ParseError, match=error):
        parse_dhcpv4(data)


def test_rejects_hardware_address_length_overflow():
    data = bytearray(_message())
    data[2] = 17
    with pytest.raises(DHCPv4ParseError, match="hlen=17"):
        parse_dhcpv4(bytes(data))
