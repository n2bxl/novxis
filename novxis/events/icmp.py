"""Normalized ICMPv4 observations and completed Echo exchanges."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.protocols.ethernet import EthernetFrame
from novxis.protocols.icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, ICMPMessage
from novxis.protocols.ipv4 import IPv4Datagram


@dataclass(frozen=True, slots=True)
class ICMPMessageObserved:
    """An ICMPv4 message observed with its original layered evidence attached."""

    captured: CapturedFrame
    ethernet: EthernetFrame
    ipv4: IPv4Datagram
    message: ICMPMessage

    @property
    def timestamp(self) -> Decimal:
        return self.captured.timestamp

    @property
    def interface(self) -> str:
        return self.captured.interface


@dataclass(frozen=True, slots=True)
class ICMPEchoRequestObserved(ICMPMessageObserved):
    """An ICMP Echo Request with the standard zero code."""


@dataclass(frozen=True, slots=True)
class ICMPEchoReplyObserved(ICMPMessageObserved):
    """An ICMP Echo Reply with the standard zero code."""


@dataclass(frozen=True, slots=True)
class ICMPEchoExchangeCompleted:
    """A request and reply correlated strongly enough to form one Echo exchange."""

    request: ICMPEchoRequestObserved
    reply: ICMPEchoReplyObserved

    @property
    def duration(self) -> Decimal:
        return self.reply.timestamp - self.request.timestamp


def observe_icmp(
    captured: CapturedFrame,
    ethernet: EthernetFrame,
    ipv4: IPv4Datagram,
    message: ICMPMessage,
) -> ICMPMessageObserved:
    """Normalize ICMPv4 evidence, classifying only standard Echo type/code pairs."""
    event_type: type[ICMPMessageObserved]

    if message.type == ICMP_ECHO_REQUEST and message.code == 0:
        event_type = ICMPEchoRequestObserved
    elif message.type == ICMP_ECHO_REPLY and message.code == 0:
        event_type = ICMPEchoReplyObserved
    else:
        event_type = ICMPMessageObserved

    return event_type(
        captured=captured,
        ethernet=ethernet,
        ipv4=ipv4,
        message=message,
    )
