from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events import ICMPEchoReplyObserved, ICMPEchoRequestObserved
from novxis.pipeline import ICMPEventPipeline


def _frame(
    *,
    icmp_type: int,
    timestamp: str,
    source: bytes,
    destination: bytes,
    identifier: int = 0x1234,
    sequence: int = 1,
    payload: bytes = b"ping",
    protocol: int = 1,
    flags_offset: int = 0x4000,
) -> CapturedFrame:
    icmp = (
        bytes([icmp_type, 0])
        + bytes.fromhex("1111")
        + identifier.to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + payload
    )
    total_length = 20 + len(icmp)
    ipv4 = (
        bytes.fromhex("4500")
        + total_length.to_bytes(2, "big")
        + bytes.fromhex("1234")
        + flags_offset.to_bytes(2, "big")
        + bytes([64, protocol])
        + bytes.fromhex("abcd")
        + source
        + destination
        + icmp
    )
    ethernet = (
        bytes.fromhex("001122334455")
        + bytes.fromhex("66778899aabb")
        + bytes.fromhex("0800")
        + ipv4
    )
    return CapturedFrame(
        timestamp=Decimal(timestamp),
        interface="en0",
        data=ethernet,
        captured_length=len(ethernet),
        original_length=len(ethernet),
        link_type=1,
    )


def test_pipeline_correlates_live_echo_request_and_reply():
    pipeline = ICMPEventPipeline()
    local = bytes([192, 0, 2, 10])
    remote = bytes([198, 51, 100, 20])

    request_result = pipeline.process(
        _frame(
            icmp_type=8,
            timestamp="100.000",
            source=local,
            destination=remote,
        )
    )
    reply_result = pipeline.process(
        _frame(
            icmp_type=0,
            timestamp="100.025",
            source=remote,
            destination=local,
        )
    )

    assert request_result is not None
    assert isinstance(request_result.observation, ICMPEchoRequestObserved)
    assert request_result.exchange is None

    assert reply_result is not None
    assert isinstance(reply_result.observation, ICMPEchoReplyObserved)
    assert reply_result.exchange is not None
    assert reply_result.exchange.duration == Decimal("0.025")


def test_pipeline_skips_non_icmp_ipv4_datagram():
    result = ICMPEventPipeline().process(
        _frame(
            icmp_type=8,
            timestamp="100",
            source=bytes([192, 0, 2, 10]),
            destination=bytes([198, 51, 100, 20]),
            protocol=17,
        )
    )

    assert result is None


def test_pipeline_skips_first_fragment_marked_more_fragments():
    result = ICMPEventPipeline().process(
        _frame(
            icmp_type=8,
            timestamp="100",
            source=bytes([192, 0, 2, 10]),
            destination=bytes([198, 51, 100, 20]),
            flags_offset=0x2000,
        )
    )

    assert result is None


def test_pipeline_skips_noninitial_fragment():
    result = ICMPEventPipeline().process(
        _frame(
            icmp_type=8,
            timestamp="100",
            source=bytes([192, 0, 2, 10]),
            destination=bytes([198, 51, 100, 20]),
            flags_offset=0x0001,
        )
    )

    assert result is None
