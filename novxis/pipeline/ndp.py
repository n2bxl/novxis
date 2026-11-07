"""Passive Ethernet -> IPv6 -> ICMPv6 NS/NA pipeline (no state mutation)."""

from dataclasses import dataclass

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.link import validate_ethernet_link_type
from novxis.protocols.ethernet import (
    ETHERTYPE_IPV6, EthernetFrame, parse_ethernet,
)
from novxis.protocols.ipv6 import IPv6Datagram, parse_ipv6
from novxis.protocols.icmpv6_nd import (
    ICMPV6_NEXT_HEADER, NeighborSolicitation, NeighborAdvertisement,
    parse_neighbor_discovery,
)


@dataclass(frozen=True, slots=True)
class NeighborDiscoveryObserved:
    """One validated wire message, retaining original capture provenance."""

    captured: CapturedFrame
    ethernet: EthernetFrame
    ipv6: IPv6Datagram
    message: NeighborSolicitation | NeighborAdvertisement


class NeighborDiscoveryPipeline:
    """Decode only direct IPv6 Next Header=58 NS/NA without probes/caches.

    IPv6 extension chains/fragments and other ICMPv6 message types are
    explicitly unsupported in Stage 1; no payload is guessed as ICMPv6.
    """

    def process(self, frame: CapturedFrame) -> NeighborDiscoveryObserved | None:
        validate_ethernet_link_type(frame.link_type)
        ethernet = parse_ethernet(frame.data)
        if ethernet.ether_type != ETHERTYPE_IPV6:
            return None
        ipv6 = parse_ipv6(ethernet.payload)
        if ipv6.next_header != ICMPV6_NEXT_HEADER:
            return None
        message = parse_neighbor_discovery(
            ipv6.payload, source=ipv6.source,
            destination=ipv6.destination, hop_limit=ipv6.hop_limit,
        )
        if message is None:
            return None
        return NeighborDiscoveryObserved(
            captured=frame, ethernet=ethernet, ipv6=ipv6, message=message,
        )
