from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events import (
    ICMPEchoReplyObserved,
    ICMPEchoRequestObserved,
    ICMPMessageObserved,
    observe_icmp,
)
from novxis.protocols.ethernet import EthernetFrame
from novxis.protocols.icmp import ICMPMessage
from novxis.protocols.ipv4 import IPv4Datagram


def _captured() -> CapturedFrame:
    return CapturedFrame(
        timestamp=Decimal("100.25"),
        interface="en0",
        data=b"raw",
        captured_length=3,
    )


def _ethernet() -> EthernetFrame:
    return EthernetFrame(
        destination=b"\x02" * 6,
        source=b"\x01" * 6,
        ether_type=0x0800,
        payload=b"ip",
    )


def _ipv4() -> IPv4Datagram:
    return IPv4Datagram(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=32,
        identification=1,
        flags=2,
        fragment_offset=0,
        ttl=64,
        protocol=1,
        header_checksum=0,
        source=bytes([192, 0, 2, 10]),
        destination=bytes([198, 51, 100, 20]),
        options=b"",
        payload=b"icmp",
        trailing_bytes=b"",
    )


def _message(type_value: int, code: int = 0) -> ICMPMessage:
    return ICMPMessage(
        type=type_value,
        code=code,
        checksum=0x1234,
        rest_of_header=bytes.fromhex("abcd0001"),
        payload=b"payload",
    )


def test_echo_request_becomes_request_observation():
    event = observe_icmp(_captured(), _ethernet(), _ipv4(), _message(8))

    assert isinstance(event, ICMPEchoRequestObserved)
    assert event.timestamp == Decimal("100.25")
    assert event.interface == "en0"


def test_echo_reply_becomes_reply_observation():
    event = observe_icmp(_captured(), _ethernet(), _ipv4(), _message(0))

    assert isinstance(event, ICMPEchoReplyObserved)


def test_echo_type_with_nonzero_code_remains_generic():
    event = observe_icmp(_captured(), _ethernet(), _ipv4(), _message(8, code=1))

    assert type(event) is ICMPMessageObserved


def test_non_echo_type_remains_generic():
    event = observe_icmp(_captured(), _ethernet(), _ipv4(), _message(3, code=1))

    assert type(event) is ICMPMessageObserved
