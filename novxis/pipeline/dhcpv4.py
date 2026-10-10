"""DHCPv4 observations on the existing bounded UDP evidence path."""

from novxis.capture.frame import CapturedFrame
from novxis.events.dhcpv4 import DHCPv4MessageObserved, observe_dhcpv4
from novxis.pipeline.udp import UDPEventPipeline
from novxis.protocols.dhcpv4 import parse_dhcpv4

DHCPV4_CLIENT_PORT = 68
DHCPV4_SERVER_PORT = 67
DHCPV4_PORTS = frozenset({DHCPV4_SERVER_PORT, DHCPV4_CLIENT_PORT})


class DHCPv4EventPipeline:
    """Produce one observation per complete DHCPv4 payload.

    Reuse the UDP pipeline for Ethernet, IPv4, fragmentation and UDP-length
    handling. Both UDP ports must be DHCPv4 ports, allowing server-to-server
    relay traffic on 67/67 without decoding unrelated traffic sent to port 67.
    """

    def __init__(self) -> None:
        self._udp = UDPEventPipeline()

    def process(self, frame: CapturedFrame) -> DHCPv4MessageObserved | None:
        udp_observation = self._udp.process(frame)
        if udp_observation is None:
            return None

        udp = udp_observation.datagram
        if (
            udp.source_port not in DHCPV4_PORTS
            or udp.destination_port not in DHCPV4_PORTS
        ):
            return None

        message = parse_dhcpv4(udp.payload)
        return observe_dhcpv4(udp_observation, message)
