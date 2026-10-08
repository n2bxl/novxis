"""Shared Ethernet/IPv4/UDP evidence and observation pipeline."""

from novxis.capture.frame import CapturedFrame
from novxis.events.udp import UDPDatagramObserved, observe_udp
from novxis.pipeline.ipv4 import IPv4EvidencePipeline
from novxis.protocols.udp import parse_udp

IP_PROTOCOL_UDP = 17
IPV4_FLAG_MORE_FRAGMENTS = 0b001


class UDPEventPipeline:
    """Decode UDP only when the complete IPv4 payload is present unfragmented."""

    def __init__(self) -> None:
        self._ipv4 = IPv4EvidencePipeline()

    def process(self, frame: CapturedFrame) -> UDPDatagramObserved | None:
        ipv4_result = self._ipv4.process(frame)
        if ipv4_result is None:
            return None

        datagram = ipv4_result.datagram
        if datagram.protocol != IP_PROTOCOL_UDP:
            return None
        # Fragment zero may contain the UDP header but not the full datagram.
        # Do not attempt to interpret any fragments before reassembly exists.
        if datagram.fragment_offset != 0 or datagram.flags & IPV4_FLAG_MORE_FRAGMENTS:
            return None

        udp = parse_udp(datagram.payload)
        return observe_udp(
            ipv4_result.captured, ipv4_result.ethernet, datagram, udp
        )
