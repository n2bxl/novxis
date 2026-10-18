"""Normalized mDNS observation preserving its captured frame and IP evidence."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.protocols.ethernet import EthernetFrame
from novxis.protocols.ipv4 import IPv4Datagram
from novxis.protocols.ipv6 import IPv6Datagram
from novxis.protocols.mdns import MDNSMessage
from novxis.protocols.udp import UDPDatagram


@dataclass(frozen=True, slots=True)
class MDNSMessageObserved:
    """A decoded mDNS packet, not a verified advertisement or device identity."""

    captured: CapturedFrame
    ethernet: EthernetFrame
    ip: IPv4Datagram | IPv6Datagram
    udp: UDPDatagram
    message: MDNSMessage

    @property
    def timestamp(self) -> Decimal:
        return self.captured.timestamp

    @property
    def interface(self) -> str:
        return self.captured.interface

    @property
    def ip_version(self) -> int:
        return self.ip.version
