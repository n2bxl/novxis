"""Normalized ICMPv4 observations and completed Echo exchanges."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.protocols.ethernet import EthernetFrame
from novxis.protocols.icmp import (
    ICMP_DESTINATION_UNREACHABLE,
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    ICMP_TIME_EXCEEDED,
    ICMPMessage,
)
from novxis.protocols.ipv4 import IPv4Datagram, IPv4DatagramQuote


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
class ICMPErrorObserved(ICMPMessageObserved):
    """An ICMP error carrying a successfully decoded quote of the triggering IPv4."""

    quoted_ipv4: IPv4DatagramQuote


@dataclass(frozen=True, slots=True)
class ICMPDestinationUnreachableObserved(ICMPErrorObserved):
    """A Destination Unreachable observation with quoted IPv4 evidence."""


@dataclass(frozen=True, slots=True)
class ICMPTimeExceededObserved(ICMPErrorObserved):
    """A Time Exceeded observation with quoted IPv4 evidence."""


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
    *,
    quoted_ipv4: IPv4DatagramQuote | None = None,
) -> ICMPMessageObserved:
    """Normalize ICMP evidence without inventing semantics unsupported by evidence."""
    event_type: type[ICMPMessageObserved]

    if message.type == ICMP_ECHO_REQUEST and message.code == 0:
        event_type = ICMPEchoRequestObserved
    elif message.type == ICMP_ECHO_REPLY and message.code == 0:
        event_type = ICMPEchoReplyObserved
    elif (
        message.type == ICMP_DESTINATION_UNREACHABLE
        and quoted_ipv4 is not None
    ):
        return ICMPDestinationUnreachableObserved(
            captured=captured,
            ethernet=ethernet,
            ipv4=ipv4,
            message=message,
            quoted_ipv4=quoted_ipv4,
        )
    elif message.type == ICMP_TIME_EXCEEDED and quoted_ipv4 is not None:
        return ICMPTimeExceededObserved(
            captured=captured,
            ethernet=ethernet,
            ipv4=ipv4,
            message=message,
            quoted_ipv4=quoted_ipv4,
        )
    else:
        event_type = ICMPMessageObserved

    return event_type(
        captured=captured,
        ethernet=ethernet,
        ipv4=ipv4,
        message=message,
    )
