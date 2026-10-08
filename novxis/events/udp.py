"""Normalized UDP observation retaining all captured packet evidence."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.protocols.ethernet import EthernetFrame
from novxis.protocols.ipv4 import IPv4Datagram
from novxis.protocols.udp import UDPDatagram


@dataclass(frozen=True, slots=True)
class UDPDatagramObserved:
    captured: CapturedFrame
    ethernet: EthernetFrame
    ipv4: IPv4Datagram
    datagram: UDPDatagram

    @property
    def timestamp(self) -> Decimal:
        return self.captured.timestamp

    @property
    def interface(self) -> str:
        return self.captured.interface


def observe_udp(
    captured: CapturedFrame,
    ethernet: EthernetFrame,
    ipv4: IPv4Datagram,
    datagram: UDPDatagram,
) -> UDPDatagramObserved:
    """Describe observed transport evidence without assuming a UDP session."""
    return UDPDatagramObserved(captured, ethernet, ipv4, datagram)
