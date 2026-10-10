"""Normalized DHCPv4 observation; no lease or client state is inferred."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events.udp import UDPDatagramObserved
from novxis.protocols.dhcpv4 import DHCPv4Message
from novxis.protocols.ethernet import EthernetFrame
from novxis.protocols.ipv4 import IPv4Datagram
from novxis.protocols.udp import UDPDatagram


@dataclass(frozen=True, slots=True)
class DHCPv4MessageObserved:
    """A single DHCP message with its original Ethernet/IPv4/UDP evidence."""

    udp_observation: UDPDatagramObserved
    message: DHCPv4Message

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


def observe_dhcpv4(
    udp_observation: UDPDatagramObserved, message: DHCPv4Message
) -> DHCPv4MessageObserved:
    """Wrap raw DHCPv4 evidence without asserting a completed exchange."""
    return DHCPv4MessageObserved(udp_observation, message)
