from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events import ARPReplyObserved, ARPRequestObserved
from novxis.pipeline import ARPEventPipeline, UnsupportedLinkTypeError


REQUEST_RAW = bytes.fromhex(
    "9cebe887e189"
    "6813f3e958ce"
    "0806"
    "0001"
    "0800"
    "06"
    "04"
    "0001"
    "6813f3e958ce"
    "c0a80417"
    "000000000000"
    "c0a8044e"
) + (b"\x00" * 18)

REPLY_RAW = bytes.fromhex(
    "6813f3e958ce"
    "9cebe887e189"
    "0806"
    "0001"
    "0800"
    "06"
    "04"
    "0002"
    "9cebe887e189"
    "c0a8044e"
    "6813f3e958ce"
    "c0a80417"
)


def _frame(data: bytes, timestamp: str) -> CapturedFrame:
    return CapturedFrame(
        timestamp=Decimal(timestamp),
        interface="en5",
        data=data,
        captured_length=len(data),
        original_length=len(data),
        link_type=1,
    )


def test_pipeline_processes_live_fixture_into_completed_exchange():
    pipeline = ARPEventPipeline()

    request_result = pipeline.process(_frame(REQUEST_RAW, "100.000"))
    reply_result = pipeline.process(_frame(REPLY_RAW, "100.125"))

    assert request_result is not None
    assert isinstance(request_result.observation, ARPRequestObserved)
    assert request_result.exchange is None

    assert reply_result is not None
    assert isinstance(reply_result.observation, ARPReplyObserved)
    assert reply_result.exchange is not None
    assert reply_result.exchange.duration == Decimal("0.125")
    assert pipeline.pending_requests == ()


def test_pipeline_skips_non_arp_ethernet_frame():
    frame = _frame(
        bytes.fromhex(
            "ffffffffffff"
            "001122334455"
            "0800"
            "45000014"
        ),
        "100",
    )

    assert ARPEventPipeline().process(frame) is None


def test_pipeline_rejects_known_non_ethernet_link_type():
    frame = CapturedFrame(
        timestamp=Decimal("100"),
        interface="replay",
        data=b"\x00" * 64,
        captured_length=64,
        link_type=127,
    )

    with pytest.raises(UnsupportedLinkTypeError, match="Ethernet link type 1"):
        ARPEventPipeline().process(frame)


def test_pipeline_allows_live_frame_with_unknown_link_type():
    frame = CapturedFrame(
        timestamp=Decimal("100"),
        interface="en5",
        data=REQUEST_RAW,
        captured_length=len(REQUEST_RAW),
        link_type=None,
    )

    result = ARPEventPipeline().process(frame)

    assert result is not None
    assert isinstance(result.observation, ARPRequestObserved)
