from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events import (
    ARPMessageObserved,
    ARPReplyObserved,
    ARPRequestObserved,
    observe_arp,
)
from novxis.protocols.arp import ARPMessage
from novxis.protocols.ethernet import EthernetFrame


def _captured() -> CapturedFrame:
    return CapturedFrame(
        timestamp=Decimal("100.25"),
        interface="en5",
        data=b"raw",
        captured_length=3,
    )


def _ethernet() -> EthernetFrame:
    return EthernetFrame(
        destination=b"\xff" * 6,
        source=b"\x01" * 6,
        ether_type=0x0806,
        payload=b"arp",
    )


def _message(opcode: int) -> ARPMessage:
    return ARPMessage(
        hardware_type=1,
        protocol_type=0x0800,
        hardware_length=6,
        protocol_length=4,
        opcode=opcode,
        sender_hardware=b"\x01" * 6,
        sender_protocol=bytes([192, 168, 4, 10]),
        target_hardware=b"\x00" * 6,
        target_protocol=bytes([192, 168, 4, 20]),
        trailing_bytes=b"\x00" * 18,
    )


def test_request_opcode_becomes_request_observation():
    event = observe_arp(_captured(), _ethernet(), _message(1))

    assert isinstance(event, ARPRequestObserved)
    assert event.timestamp == Decimal("100.25")
    assert event.interface == "en5"
    assert event.captured.data == b"raw"


def test_reply_opcode_becomes_reply_observation():
    event = observe_arp(_captured(), _ethernet(), _message(2))

    assert isinstance(event, ARPReplyObserved)


def test_unknown_opcode_remains_generic_observation():
    event = observe_arp(_captured(), _ethernet(), _message(99))

    assert type(event) is ARPMessageObserved
    assert event.message.opcode == 99
