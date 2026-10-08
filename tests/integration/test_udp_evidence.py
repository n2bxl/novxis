"""End-to-end UDP evidence tests using real Ethernet and IPv4 bytes.

No IP-layer mocks and no network privileges are required.
"""

from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events import UDPDatagramObserved
from novxis.pipeline import UDPEventPipeline
from novxis.protocols.udp import UDPParseError


LOCAL = bytes([192, 0, 2, 10])
REMOTE = bytes([198, 51, 100, 20])


def _frame(
    *,
    payload: bytes = b"NOVXIS UDP",
    source: bytes = LOCAL,
    destination: bytes = REMOTE,
    source_port: int = 51000,
    destination_port: int = 49000,
    udp_length: int | None = None,
    udp_tail: bytes = b"",
    ipv4_tail: bytes = b"",
    flags_offset: int = 0x4000,
    protocol: int = 17,
    ether_type: int = 0x0800,
) -> CapturedFrame:
    udp_length = 8 + len(payload) if udp_length is None else udp_length
    udp = (
        source_port.to_bytes(2, "big")
        + destination_port.to_bytes(2, "big")
        + udp_length.to_bytes(2, "big")
        + bytes.fromhex("beef")
        + payload
        + udp_tail
    )
    ipv4_length = 20 + len(udp)
    ipv4 = (
        bytes.fromhex("4500")
        + ipv4_length.to_bytes(2, "big")
        + bytes.fromhex("1234")
        + flags_offset.to_bytes(2, "big")
        + bytes([64, protocol])
        + bytes.fromhex("abcd")
        + source
        + destination
        + udp
    )
    ethernet = (
        bytes.fromhex("00112233445566778899aabb")
        + ether_type.to_bytes(2, "big")
        + ipv4
        + ipv4_tail
    )
    return CapturedFrame(
        timestamp=Decimal("100.125"),
        interface="en0",
        data=ethernet,
        captured_length=len(ethernet),
        original_length=len(ethernet),
        link_type=1,
    )


def test_full_ethernet_ipv4_udp_path_preserves_source_evidence():
    frame = _frame(payload=b"NOVXIS UDP")
    observation = UDPEventPipeline().process(frame)

    assert isinstance(observation, UDPDatagramObserved)
    assert observation.captured is frame
    assert observation.ethernet.ether_type == 0x0800
    assert observation.ipv4.source == LOCAL
    assert observation.ipv4.destination == REMOTE
    assert observation.ipv4.protocol == 17
    assert observation.datagram.source_port == 51000
    assert observation.datagram.destination_port == 49000
    assert observation.datagram.length == 18
    assert observation.datagram.payload_length == 10
    assert observation.datagram.payload == b"NOVXIS UDP"
    assert observation.datagram.checksum == 0xBEEF
    assert observation.datagram.trailing_bytes == b""
    assert observation.timestamp == Decimal("100.125")
    assert observation.interface == "en0"


def test_empty_payload_is_valid_end_to_end():
    observation = UDPEventPipeline().process(_frame(payload=b""))
    assert observation is not None
    assert observation.datagram.length == 8
    assert observation.datagram.payload == b""


def test_trailing_bytes_remain_at_their_correct_layer():
    observation = UDPEventPipeline().process(
        _frame(payload=b"x", udp_tail=b"\xaa\xbb", ipv4_tail=b"\x00\x00")
    )
    assert observation is not None
    assert observation.datagram.payload == b"x"
    assert observation.datagram.trailing_bytes == b"\xaa\xbb"
    assert observation.ipv4.trailing_bytes == b"\x00\x00"


def test_reverse_direction_is_another_observation_not_a_session():
    pipeline = UDPEventPipeline()
    outbound = pipeline.process(_frame())
    inbound = pipeline.process(
        _frame(
            source=REMOTE,
            destination=LOCAL,
            source_port=49000,
            destination_port=51000,
            payload=b"ACK",
        )
    )
    assert outbound is not None and inbound is not None
    assert inbound.datagram.payload == b"ACK"
    assert outbound.datagram.source_port == inbound.datagram.destination_port
    assert outbound is not inbound


@pytest.mark.parametrize("flags_offset", [0x2000, 0x0001])
def test_real_ipv4_fragments_are_skipped(flags_offset):
    assert UDPEventPipeline().process(_frame(flags_offset=flags_offset)) is None


def test_non_udp_ipv4_traffic_is_skipped():
    assert UDPEventPipeline().process(_frame(protocol=6)) is None


def test_non_ipv4_ethernet_traffic_is_skipped():
    assert UDPEventPipeline().process(_frame(ether_type=0x0806)) is None


def test_inconsistent_udp_length_is_rejected_end_to_end():
    with pytest.raises(UDPParseError, match="only 11 are present"):
        UDPEventPipeline().process(_frame(payload=b"abc", udp_length=12))
