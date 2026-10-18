"""Bounded IPv6 fixed-header decoder (RFC 8200), independent of Scapy.

This initial slice does not process extension-header chains, fragments, or
jumbograms. Callers must not treat next_header as the final transport protocol
when it designates an extension header.
"""

from dataclasses import dataclass

IPV6_HEADER_LENGTH = 40
IPV6_NEXT_HEADER_UDP = 17


class IPv6ParseError(ValueError):
    """Raised when the IPv6 fixed header or declared payload is malformed."""


@dataclass(frozen=True, slots=True)
class IPv6Datagram:
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    source: bytes
    destination: bytes
    payload: bytes
    trailing_bytes: bytes


def parse_ipv6(data: bytes) -> IPv6Datagram:
    """Decode the IPv6 fixed header and its declared payload length.

    This does not follow IPv6 extension headers or validate transport checksums.
    A declared zero payload length is not interpreted as a jumbogram.
    """
    if len(data) < IPV6_HEADER_LENGTH:
        raise IPv6ParseError(
            f"IPv6 fixed header requires {IPV6_HEADER_LENGTH} bytes; got {len(data)}."
        )
    version = data[0] >> 4
    if version != 6:
        raise IPv6ParseError(f"Expected IPv6 version 6; got version {version}.")

    declared_length = int.from_bytes(data[4:6], "big")
    end = IPV6_HEADER_LENGTH + declared_length
    if end > len(data):
        raise IPv6ParseError(
            f"IPv6 payload declares {declared_length} bytes, "
            f"but only {len(data) - IPV6_HEADER_LENGTH} are present."
        )

    first_word = int.from_bytes(data[:4], "big")
    return IPv6Datagram(
        version=version,
        traffic_class=(first_word >> 20) & 0xFF,
        flow_label=first_word & 0xFFFFF,
        payload_length=declared_length,
        next_header=data[6],
        hop_limit=data[7],
        source=data[8:24],
        destination=data[24:40],
        payload=data[40:end],
        trailing_bytes=data[end:],
    )
