"""Classic DNS observation path built on the bounded IPv4/UDP pipeline."""

from novxis.capture.frame import CapturedFrame
from novxis.events.dns import DNSMessageObserved, observe_dns
from novxis.pipeline.udp import UDPEventPipeline
from novxis.protocols.dns import parse_dns

DNS_UDP_PORT = 53


class DNSEventPipeline:
    """Decode UDP port-53 candidate messages, retaining transport evidence.

    The UDP pipeline already skips fragmented IPv4 packets and ignores other
    protocols and link types. Port number alone does not prove that content is
    DNS; malformed candidate payloads raise DNSParseError for the caller.
    mDNS/5353 and DNS-over-TCP are intentionally separate future paths.
    """

    def __init__(self) -> None:
        self._udp = UDPEventPipeline()

    def process(self, frame: CapturedFrame) -> DNSMessageObserved | None:
        udp_observation = self._udp.process(frame)
        if udp_observation is None:
            return None

        udp = udp_observation.datagram
        if DNS_UDP_PORT not in (udp.source_port, udp.destination_port):
            return None

        message = parse_dns(udp.payload)
        return observe_dns(udp_observation, message)
