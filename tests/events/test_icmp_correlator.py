from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events import ICMPEchoCorrelator, observe_icmp
from novxis.protocols.ethernet import EthernetFrame
from novxis.protocols.icmp import ICMPMessage
from novxis.protocols.ipv4 import IPv4Datagram


def _observation(
    *,
    type_value: int,
    timestamp: str,
    interface: str = "en0",
    source: bytes = bytes([192, 0, 2, 10]),
    destination: bytes = bytes([198, 51, 100, 20]),
    identifier: int = 0x1234,
    sequence: int = 1,
    payload: bytes = b"echo-data",
):
    rest = identifier.to_bytes(2, "big") + sequence.to_bytes(2, "big")
    message = ICMPMessage(
        type=type_value,
        code=0,
        checksum=0,
        rest_of_header=rest,
        payload=payload,
    )
    ipv4 = IPv4Datagram(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=28 + len(payload),
        identification=1,
        flags=2,
        fragment_offset=0,
        ttl=64,
        protocol=1,
        header_checksum=0,
        source=source,
        destination=destination,
        options=b"",
        payload=b"",
        trailing_bytes=b"",
    )
    ethernet = EthernetFrame(
        destination=b"\x02" * 6,
        source=b"\x01" * 6,
        ether_type=0x0800,
        payload=b"",
    )
    captured = CapturedFrame(
        timestamp=Decimal(timestamp),
        interface=interface,
        data=b"",
        captured_length=0,
    )
    return observe_icmp(captured, ethernet, ipv4, message)


def _reply(**overrides):
    defaults = {
        "type_value": 0,
        "timestamp": "100.125",
        "source": bytes([198, 51, 100, 20]),
        "destination": bytes([192, 0, 2, 10]),
    }
    defaults.update(overrides)
    return _observation(**defaults)


def test_matching_echo_reply_completes_exchange_and_measures_rtt():
    correlator = ICMPEchoCorrelator()
    request = _observation(type_value=8, timestamp="100.000")
    reply = _reply()

    assert correlator.observe(request) is None
    exchange = correlator.observe(reply)

    assert exchange is not None
    assert exchange.request is request
    assert exchange.reply is reply
    assert exchange.duration == Decimal("0.125")
    assert correlator.pending_requests == ()


def test_reply_on_different_interface_does_not_match():
    correlator = ICMPEchoCorrelator()
    request = _observation(type_value=8, timestamp="100")

    correlator.observe(request)

    assert correlator.observe(_reply(interface="en5")) is None
    assert correlator.pending_requests == (request,)


def test_reply_without_reversed_addresses_does_not_match():
    correlator = ICMPEchoCorrelator()
    request = _observation(type_value=8, timestamp="100")

    correlator.observe(request)

    assert correlator.observe(_reply(
        source=bytes([198, 51, 100, 20]),
        destination=bytes([203, 0, 113, 5]),
    )) is None


def test_reply_with_different_sequence_does_not_match():
    correlator = ICMPEchoCorrelator()
    request = _observation(type_value=8, timestamp="100")

    correlator.observe(request)

    assert correlator.observe(_reply(sequence=2)) is None


def test_reply_with_different_payload_does_not_match():
    correlator = ICMPEchoCorrelator()
    request = _observation(type_value=8, timestamp="100")

    correlator.observe(request)

    assert correlator.observe(_reply(payload=b"different")) is None


def test_reply_outside_window_expires_request():
    correlator = ICMPEchoCorrelator(max_age=Decimal("1"))
    request = _observation(type_value=8, timestamp="100")
    late_reply = _reply(timestamp="102")

    correlator.observe(request)

    assert correlator.observe(late_reply) is None
    assert correlator.pending_requests == ()


def test_invalid_correlation_window_is_rejected():
    with pytest.raises(ValueError, match="greater than zero"):
        ICMPEchoCorrelator(max_age=Decimal("0"))
