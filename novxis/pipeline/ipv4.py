"""Shared Ethernet/IPv4 evidence processing pipeline."""

from dataclasses import dataclass

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.link import validate_ethernet_link_type
from novxis.protocols.ethernet import (
    ETHERTYPE_IPV4,
    EthernetFrame,
    parse_ethernet,
)
from novxis.protocols.ipv4 import IPv4Datagram, parse_ipv4


@dataclass(frozen=True, slots=True)
class IPv4ProcessingResult:
    """Captured evidence decoded through Ethernet and IPv4."""

    captured: CapturedFrame
    ethernet: EthernetFrame
    datagram: IPv4Datagram


class IPv4EvidencePipeline:
    """Decode IPv4 evidence without interpreting its upper-layer payload."""

    def process(self, frame: CapturedFrame) -> IPv4ProcessingResult | None:
        """Decode one Ethernet/IPv4 frame or ignore a different EtherType."""
        validate_ethernet_link_type(frame.link_type)
        ethernet = parse_ethernet(frame.data)

        if ethernet.ether_type != ETHERTYPE_IPV4:
            return None

        datagram = parse_ipv4(ethernet.payload)

        return IPv4ProcessingResult(
            captured=frame,
            ethernet=ethernet,
            datagram=datagram,
        )
