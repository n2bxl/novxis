"""Normalized DNS message observations retaining packet-level provenance."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events.udp import UDPDatagramObserved
from novxis.protocols.dns import DNSMessage
from novxis.protocols.ethernet import EthernetFrame
from novxis.protocols.ipv4 import IPv4Datagram
from novxis.protocols.udp import UDPDatagram


@dataclass(frozen=True, slots=True)
class DNSMessageObserved:
    """A decoded DNS message, not a validated resolution or host identity."""

    udp_observation: UDPDatagramObserved
    message: DNSMessage

    @property
    def captured(self) -> CapturedFrame:
        return self.udp_observation.captured

    @property
    def ethernet(self) -> EthernetFrame:
        return self.udp_observation.ethernet

    @property
    def ipv4(self) -> IPv4Datagram:
        return self.udp_observation.ipv4

    @property
    def udp(self) -> UDPDatagram:
        return self.udp_observation.datagram

    @property
    def timestamp(self) -> Decimal:
        return self.udp_observation.timestamp

    @property
    def interface(self) -> str:
        return self.udp_observation.interface


def observe_dns(
    udp_observation: UDPDatagramObserved, message: DNSMessage
) -> DNSMessageObserved:
    """Wrap DNS bytes without asserting matching, trust, or cache state."""
    return DNSMessageObserved(udp_observation=udp_observation, message=message)
