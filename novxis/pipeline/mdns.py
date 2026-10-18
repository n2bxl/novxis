"""Passive Ethernet/IPv4-or-IPv6/UDP/5353 mDNS observation pipeline."""

from novxis.capture.frame import CapturedFrame
from novxis.events.mdns import MDNSMessageObserved
from novxis.pipeline.link import validate_ethernet_link_type
from novxis.protocols.ethernet import (
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, EthernetFrame, parse_ethernet,
)
from novxis.protocols.ipv4 import parse_ipv4
from novxis.protocols.ipv6 import parse_ipv6, IPV6_NEXT_HEADER_UDP
from novxis.protocols.mdns import MDNS_UDP_PORT, parse_mdns
from novxis.protocols.udp import parse_udp

IP_PROTOCOL_UDP = 17
IPV4_MORE_FRAGMENTS = 0b001


class MDNSEventPipeline:
    """Decode unfragmented UDP/5353 from supported IPv4 and IPv6 fixed headers.

    The pipeline never sends queries or correlates mDNS responses. Non-UDP
    traffic and unsupported IPv6 extension-header chains are ignored rather
    than having their payload misinterpreted as UDP. Ethernet II only.
    """

    def process(self, frame: CapturedFrame) -> MDNSMessageObserved | None:
        validate_ethernet_link_type(frame.link_type)
        ethernet: EthernetFrame = parse_ethernet(frame.data)

        if ethernet.ether_type == ETHERTYPE_IPV4:
            ip = parse_ipv4(ethernet.payload)
            if ip.protocol != IP_PROTOCOL_UDP:
                return None
            if ip.fragment_offset != 0 or ip.flags & IPV4_MORE_FRAGMENTS:
                return None
        elif ethernet.ether_type == ETHERTYPE_IPV6:
            ip = parse_ipv6(ethernet.payload)
            # No extension-header traversal or reassembly in Phase 1M-B.
            if ip.next_header != IPV6_NEXT_HEADER_UDP:
                return None
        else:
            return None

        udp = parse_udp(ip.payload)
        if MDNS_UDP_PORT not in (udp.source_port, udp.destination_port):
            return None

        return MDNSMessageObserved(
            captured=frame,
            ethernet=ethernet,
            ip=ip,
            udp=udp,
            message=parse_mdns(udp.payload),
        )
