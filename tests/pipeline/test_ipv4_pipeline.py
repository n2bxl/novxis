from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.pipeline import IPv4EvidencePipeline, UnsupportedLinkTypeError


IPV4_RAW = bytes.fromhex(
    "001122334455"
    "66778899aabb"
    "0800"
    "4500001c123440004001abcdc000020ac6336414"
    "08000000deadbeef"
)


def _frame(data: bytes, link_type: int | None = 1) -> CapturedFrame:
    return CapturedFrame(
        timestamp=Decimal("100.125"),
        interface="en5",
        data=data,
        captured_length=len(data),
        original_length=len(data),
        link_type=link_type,
    )


def test_pipeline_decodes_ethernet_ipv4_evidence():
    result = IPv4EvidencePipeline().process(_frame(IPV4_RAW))

    assert result is not None
    assert result.ethernet.ether_type == 0x0800
    assert result.datagram.source == bytes([192, 0, 2, 10])
    assert result.datagram.destination == bytes([198, 51, 100, 20])
    assert result.datagram.protocol == 1
    assert result.datagram.payload == bytes.fromhex("08000000deadbeef")


def test_pipeline_skips_non_ipv4_ethernet_frame():
    raw = bytes.fromhex(
        "ffffffffffff"
        "001122334455"
        "0806"
    ) + (b"\x00" * 28)

    assert IPv4EvidencePipeline().process(_frame(raw)) is None


def test_pipeline_rejects_known_non_ethernet_link_type():
    with pytest.raises(UnsupportedLinkTypeError, match="Ethernet link type 1"):
        IPv4EvidencePipeline().process(_frame(IPV4_RAW, link_type=127))


def test_pipeline_allows_live_frame_with_unknown_link_type():
    result = IPv4EvidencePipeline().process(_frame(IPV4_RAW, link_type=None))

    assert result is not None
    assert result.datagram.ttl == 64
