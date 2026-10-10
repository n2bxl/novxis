"""DHCPv4 end-to-end evidence regression tests using synthetic network identities."""

from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events import DHCPv4MessageObserved
from novxis.pipeline import DHCPv4EventPipeline
from novxis.presentation.dhcpv4_console import format_dhcpv4_observation
from novxis.protocols.dhcpv4 import DHCPv4ParseError


def _options(kind: int, lease: int, *, ack: bool = False) -> bytes:
    if ack:
        return (
            b"\x35\x01\x05"
            + b"\x33\x04" + lease.to_bytes(4, "big")
            + b"\x36\x04\xc0\x00\x02\x01"
            + b"\xff"
        )
    return (
        b"\x35\x01" + bytes([kind])
        + b"\x32\x04\xc0\x00\x02\x1a"
        + b"\x33\x04" + lease.to_bytes(4, "big")
        + b"\xff\x00\x00"
    )


def _dhcp(*, ack: bool = False, cookie: bytes = bytes.fromhex("63825363")) -> bytes:
    header = bytearray(236)
    header[0] = 2 if ack else 1
    header[1:3] = b"\x01\x06"
    header[4:8] = bytes.fromhex("1234abcd")
    header[28:34] = bytes.fromhex("021122334455")
    if ack:
        header[16:20] = bytes((192, 0, 2, 26))
    return bytes(header) + cookie + _options(
        5 if ack else 3,
        (8 * 60 * 60) if ack else (90 * 24 * 60 * 60),
        ack=ack,
    )


def _frame(
    *,
    ack: bool = False,
    source_port: int | None = None,
    destination_port: int | None = None,
    flags_offset: int = 0x4000,
    protocol: int = 17,
    ether_type: int = 0x0800,
    dhcp_payload: bytes | None = None,
) -> CapturedFrame:
    body = _dhcp(ack=ack) if dhcp_payload is None else dhcp_payload
    sp = (67 if ack else 68) if source_port is None else source_port
    dp = (68 if ack else 67) if destination_port is None else destination_port
    udp = (
        sp.to_bytes(2, "big") + dp.to_bytes(2, "big")
        + (8 + len(body)).to_bytes(2, "big")
        + b"\x00\x00" + body
    )
    source = bytes((192, 0, 2, 1)) if ack else bytes(4)
    destination = bytes((192, 0, 2, 26)) if ack else bytes((255,) * 4)
    ip = (
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x01" + flags_offset.to_bytes(2, "big")
        + bytes((64, protocol)) + b"\x00\x00"
        + source + destination + udp
    )
    eth = (
        bytes.fromhex("ffffffffffff021122334455")
        + ether_type.to_bytes(2, "big") + ip
    )
    return CapturedFrame(
        timestamp=Decimal("1234.125") if not ack else Decimal("1234.175"),
        interface="test0",
        data=eth,
        captured_length=len(eth),
        original_length=len(eth),
        link_type=1,
    )


def test_full_stack_request_retains_original_packet_and_requested_lease():
    frame = _frame()
    observed = DHCPv4EventPipeline().process(frame)
    assert isinstance(observed, DHCPv4MessageObserved)
    assert observed.captured is frame
    assert observed.interface == "test0"
    assert observed.timestamp == Decimal("1234.125")
    assert observed.ethernet.ether_type == 0x0800
    assert observed.ipv4.source == bytes(4)
    assert observed.udp.source_port == 68
    assert observed.udp.destination_port == 67
    assert observed.message.op == 1
    assert observed.message.xid == 0x1234ABCD
    assert observed.message.message_type == 3
    assert observed.message.option_values(50) == (bytes((192, 0, 2, 26)),)
    assert observed.message.trailing_bytes == b"\x00\x00"
    rendered = format_dhcpv4_observation(observed)
    assert "DHCPREQUEST" in rendered
    assert "requested_ip=192.0.2.26" in rendered
    assert "requested_lease=90 days (7776000s)" in rendered
    assert "INIT-REBOOT" not in rendered


def test_full_stack_ack_preserves_distinct_granted_lease():
    request = DHCPv4EventPipeline().process(_frame())
    observed = DHCPv4EventPipeline().process(_frame(ack=True))
    assert request is not None and observed is not None
    assert observed.message.op == 2
    assert observed.message.xid == request.message.xid
    assert observed.message.yiaddr == bytes((192, 0, 2, 26))
    assert observed.message.message_type == 5
    assert observed.udp.source_port == 67
    rendered = format_dhcpv4_observation(observed)
    assert "DHCPACK" in rendered
    assert "yiaddr=192.0.2.26" in rendered
    assert "server_identifier=192.0.2.1" in rendered
    assert "granted_lease=8 hours (28800s)" in rendered
    assert "confirmed" not in rendered.lower()


@pytest.mark.parametrize(
    "changes",
    [
        {"source_port": 9999},
        {"destination_port": 9999},
        {"source_port": 9999, "destination_port": 68},
        {"protocol": 6},
        {"ether_type": 0x0806},
        {"flags_offset": 0x2000},
        {"flags_offset": 0x0001},
    ],
)
def test_non_dhcp_or_incomplete_network_frames_are_skipped(changes):
    assert DHCPv4EventPipeline().process(_frame(**changes)) is None


def test_relay_udp_ports_are_recognized():
    msg = DHCPv4EventPipeline().process(
        _frame(source_port=67, destination_port=67)
    )
    assert msg is not None and msg.message.message_type == 3


def test_invalid_cookie_on_dhcp_ports_is_a_decode_error():
    with pytest.raises(DHCPv4ParseError, match="magic cookie"):
        DHCPv4EventPipeline().process(
            _frame(dhcp_payload=_dhcp(cookie=b"\x00\x00\x00\x00"))
        )
