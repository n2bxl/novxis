"""Minimal ICMPv4 evidence decoder."""

from novxis.protocols.icmp.message import ICMPMessage

ICMP_MIN_HEADER_LENGTH = 8


class ICMPParseError(ValueError):
    """Raised when bytes cannot contain a complete ICMPv4 base message."""


def parse_icmp(data: bytes) -> ICMPMessage:
    """Decode the common eight-byte ICMPv4 message prefix and preserve payload."""
    if len(data) < ICMP_MIN_HEADER_LENGTH:
        raise ICMPParseError(
            "ICMPv4 message requires at least "
            f"{ICMP_MIN_HEADER_LENGTH} bytes; got {len(data)}."
        )

    return ICMPMessage(
        type=data[0],
        code=data[1],
        checksum=int.from_bytes(data[2:4], byteorder="big"),
        rest_of_header=data[4:8],
        payload=data[8:],
    )
