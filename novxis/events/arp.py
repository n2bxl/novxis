"""Normalized ARP observations and completed exchanges."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.protocols.arp import ARPMessage
from novxis.protocols.ethernet import EthernetFrame


@dataclass(frozen=True, slots=True)
class ARPMessageObserved:
    """An ARP message observed with its original packet evidence attached."""

    captured: CapturedFrame
    ethernet: EthernetFrame
    message: ARPMessage

    @property
    def timestamp(self) -> Decimal:
        return self.captured.timestamp

    @property
    def interface(self) -> str:
        return self.captured.interface


@dataclass(frozen=True, slots=True)
class ARPRequestObserved(ARPMessageObserved):
    """An ARP message whose opcode explicitly identifies it as a request."""


@dataclass(frozen=True, slots=True)
class ARPReplyObserved(ARPMessageObserved):
    """An ARP message whose opcode explicitly identifies it as a reply."""


@dataclass(frozen=True, slots=True)
class ARPExchangeCompleted:
    """A request and reply correlated strongly enough to form one exchange."""

    request: ARPRequestObserved
    reply: ARPReplyObserved

    @property
    def duration(self) -> Decimal:
        return self.reply.timestamp - self.request.timestamp


def observe_arp(
    captured: CapturedFrame,
    ethernet: EthernetFrame,
    message: ARPMessage,
) -> ARPMessageObserved:
    """Normalize decoded ARP evidence without adding behavioral classification."""
    event_type: type[ARPMessageObserved]

    if message.opcode == 1:
        event_type = ARPRequestObserved
    elif message.opcode == 2:
        event_type = ARPReplyObserved
    else:
        event_type = ARPMessageObserved

    return event_type(
        captured=captured,
        ethernet=ethernet,
        message=message,
    )
