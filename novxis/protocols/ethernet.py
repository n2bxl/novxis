"""Minimal Ethernet II evidence decoding for NOVXIS."""

from dataclasses import dataclass

ETHERNET_HEADER_LENGTH = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806


class EthernetParseError(ValueError):
    """Raised when raw bytes cannot contain a complete Ethernet II header."""


@dataclass(frozen=True, slots=True)
class EthernetFrame:
    """Decoded Ethernet II header plus its untouched payload bytes."""

    destination: bytes
    source: bytes
    ether_type: int
    payload: bytes


def parse_ethernet(data: bytes) -> EthernetFrame:
    """Decode an Ethernet II header without interpreting its payload."""
    if len(data) < ETHERNET_HEADER_LENGTH:
        raise EthernetParseError(
            "Ethernet II frame requires at least "
            f"{ETHERNET_HEADER_LENGTH} bytes; got {len(data)}."
        )

    return EthernetFrame(
        destination=data[0:6],
        source=data[6:12],
        ether_type=int.from_bytes(data[12:14], byteorder="big"),
        payload=data[14:],
    )
