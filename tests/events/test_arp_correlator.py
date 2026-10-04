from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events import (
    ARPCorrelator,
    ARPReplyObserved,
    ARPRequestObserved,
    observe_arp,
)
from novxis.protocols.arp import ARPMessage, parse_arp
from novxis.protocols.ethernet import parse_ethernet


def _observation(
    *,
    opcode: int,
    timestamp: str,
    interface: str = "en5",
    sender_hardware: bytes = b"\x11" * 6,
    sender_protocol: bytes = bytes([192, 168, 4, 10]),
    target_hardware: bytes = b"\x00" * 6,
    target_protocol: bytes = bytes([192, 168, 4, 20]),
):
    message = ARPMessage(
        hardware_type=1,
        protocol_type=0x0800,
        hardware_length=6,
        protocol_length=4,
        opcode=opcode,
        sender_hardware=sender_hardware,
        sender_protocol=sender_protocol,
        target_hardware=target_hardware,
        target_protocol=target_protocol,
        trailing_bytes=b"",
    )
    ethernet_bytes = (
        target_hardware
        + sender_hardware
        + bytes.fromhex("0806")
    )
    captured = CapturedFrame(
        timestamp=Decimal(timestamp),
        interface=interface,
        data=ethernet_bytes,
        captured_length=len(ethernet_bytes),
    )
    ethernet = parse_ethernet(ethernet_bytes)
    return observe_arp(captured, ethernet, message)


def test_live_60_byte_request_and_42_byte_reply_complete_exchange():
    request_raw = bytes.fromhex(
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
    reply_raw = bytes.fromhex(
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

    request_capture = CapturedFrame(
        timestamp=Decimal("100.000"),
        interface="en5",
        data=request_raw,
        captured_length=len(request_raw),
    )
    reply_capture = CapturedFrame(
        timestamp=Decimal("100.125"),
        interface="en5",
        data=reply_raw,
        captured_length=len(reply_raw),
    )

    request_ethernet = parse_ethernet(request_raw)
    reply_ethernet = parse_ethernet(reply_raw)

    request = observe_arp(
        request_capture,
        request_ethernet,
        parse_arp(request_ethernet.payload),
    )
    reply = observe_arp(
        reply_capture,
        reply_ethernet,
        parse_arp(reply_ethernet.payload),
    )

    assert isinstance(request, ARPRequestObserved)
    assert isinstance(reply, ARPReplyObserved)

    correlator = ARPCorrelator()
    assert correlator.observe(request) is None

    exchange = correlator.observe(reply)

    assert exchange is not None
    assert exchange.request is request
    assert exchange.reply is reply
    assert exchange.duration == Decimal("0.125")
    assert correlator.pending_requests == ()


def test_unmatched_reply_does_not_create_exchange():
    correlator = ARPCorrelator()
    reply = _observation(
        opcode=2,
        timestamp="101",
        sender_hardware=b"\x22" * 6,
        sender_protocol=bytes([192, 168, 4, 20]),
        target_hardware=b"\x11" * 6,
        target_protocol=bytes([192, 168, 4, 10]),
    )

    assert correlator.observe(reply) is None
    assert correlator.pending_requests == ()


def test_reply_with_wrong_target_hardware_does_not_match():
    correlator = ARPCorrelator()
    request = _observation(opcode=1, timestamp="100")
    reply = _observation(
        opcode=2,
        timestamp="101",
        sender_hardware=b"\x22" * 6,
        sender_protocol=bytes([192, 168, 4, 20]),
        target_hardware=b"\x33" * 6,
        target_protocol=bytes([192, 168, 4, 10]),
    )

    correlator.observe(request)

    assert correlator.observe(reply) is None
    assert correlator.pending_requests == (request,)


def test_reply_on_different_interface_does_not_match():
    correlator = ARPCorrelator()
    request = _observation(opcode=1, timestamp="100", interface="en5")
    reply = _observation(
        opcode=2,
        timestamp="101",
        interface="en0",
        sender_hardware=b"\x22" * 6,
        sender_protocol=bytes([192, 168, 4, 20]),
        target_hardware=b"\x11" * 6,
        target_protocol=bytes([192, 168, 4, 10]),
    )

    correlator.observe(request)

    assert correlator.observe(reply) is None


def test_reply_outside_correlation_window_does_not_match_and_expires_request():
    correlator = ARPCorrelator(max_age=Decimal("2"))
    request = _observation(opcode=1, timestamp="100")
    reply = _observation(
        opcode=2,
        timestamp="103",
        sender_hardware=b"\x22" * 6,
        sender_protocol=bytes([192, 168, 4, 20]),
        target_hardware=b"\x11" * 6,
        target_protocol=bytes([192, 168, 4, 10]),
    )

    correlator.observe(request)

    assert correlator.observe(reply) is None
    assert correlator.pending_requests == ()


def test_most_recent_matching_request_is_used_first():
    correlator = ARPCorrelator()
    older = _observation(opcode=1, timestamp="100")
    newer = _observation(opcode=1, timestamp="101")
    reply = _observation(
        opcode=2,
        timestamp="101.5",
        sender_hardware=b"\x22" * 6,
        sender_protocol=bytes([192, 168, 4, 20]),
        target_hardware=b"\x11" * 6,
        target_protocol=bytes([192, 168, 4, 10]),
    )

    correlator.observe(older)
    correlator.observe(newer)
    exchange = correlator.observe(reply)

    assert exchange is not None
    assert exchange.request is newer
    assert correlator.pending_requests == (older,)


def test_generic_observation_does_not_enter_pending_requests():
    correlator = ARPCorrelator()
    unknown = _observation(opcode=99, timestamp="100")

    assert correlator.observe(unknown) is None
    assert correlator.pending_requests == ()


def test_invalid_correlation_window_is_rejected():
    with pytest.raises(ValueError, match="greater than zero"):
        ARPCorrelator(max_age=Decimal("0"))
