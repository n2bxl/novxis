"""Unit coverage for bounded UDP parsing and IPv4 transport filtering."""

from decimal import Decimal
from types import SimpleNamespace

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.udp import UDPEventPipeline
from novxis.protocols.udp import UDPParseError, parse_udp


def packet(source=5353, destination=9999, payload=b"hello", *, checksum=0):
    length = 8 + len(payload)
    return (
        source.to_bytes(2, "big")
        + destination.to_bytes(2, "big")
        + length.to_bytes(2, "big")
        + checksum.to_bytes(2, "big")
        + payload
    )


def test_udp_header_and_payload():
    datagram = parse_udp(packet(1234, 5678, b"abc", checksum=0xBEEF))
    assert (datagram.source_port, datagram.destination_port) == (1234, 5678)
    assert (datagram.length, datagram.payload_length) == (11, 3)
    assert (datagram.checksum, datagram.payload) == (0xBEEF, b"abc")
    assert datagram.trailing_bytes == b""


def test_empty_udp_payload_and_zero_checksum():
    datagram = parse_udp(packet(payload=b""))
    assert datagram.length == 8
    assert datagram.payload == b""
    assert datagram.checksum == 0


def test_preserves_bytes_beyond_udp_length():
    datagram = parse_udp(packet(payload=b"x") + b"\x00\x00")
    assert datagram.payload == b"x"
    assert datagram.trailing_bytes == b"\x00\x00"


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"\x00" * 7,
        b"\x00\x01\x00\x02\x00\x07\x00\x00",
        b"\x00\x01\x00\x02\x00\x0a\x00\x00x",
    ],
)
def test_rejects_truncated_or_invalid_udp(bad):
    with pytest.raises(UDPParseError):
        parse_udp(bad)


@pytest.mark.parametrize(
    "protocol,flags,offset,expected",
    [
        (17, 0, 0, True),
        (6, 0, 0, False),
        (17, 1, 0, False),
        (17, 0, 1, False),
    ],
)
def test_pipeline_rejects_non_udp_or_fragments(protocol, flags, offset, expected):
    frame = CapturedFrame(
        timestamp=Decimal("1.25"),
        interface="test0",
        data=b"",
        captured_length=0,
    )
    ip = SimpleNamespace(
        protocol=protocol, flags=flags, fragment_offset=offset,
        payload=packet(payload=b"test"),
    )
    decoded = SimpleNamespace(captured=frame, ethernet=object(), datagram=ip)
    pipeline = UDPEventPipeline()
    pipeline._ipv4 = SimpleNamespace(process=lambda incoming: decoded)
    event = pipeline.process(frame)

    assert (event is not None) is expected
    if expected:
        assert event.interface == "test0"
        assert event.timestamp == Decimal("1.25")
        assert event.datagram.payload == b"test"


def test_pipeline_ignores_non_ipv4_frame():
    pipeline = UDPEventPipeline()
    pipeline._ipv4 = SimpleNamespace(process=lambda incoming: None)
    assert pipeline.process(object()) is None
