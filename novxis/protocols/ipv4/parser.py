"""Length-aware IPv4 evidence decoder."""

from novxis.protocols.ipv4.datagram import IPv4Datagram

IPV4_MIN_HEADER_LENGTH = 20


class IPv4ParseError(ValueError):
    """Raised when bytes cannot contain the IPv4 datagram they declare."""


def parse_ipv4(data: bytes) -> IPv4Datagram:
    """Decode one IPv4 datagram while preserving bytes beyond total length."""
    if len(data) < IPV4_MIN_HEADER_LENGTH:
        raise IPv4ParseError(
            "IPv4 datagram requires at least "
            f"{IPV4_MIN_HEADER_LENGTH} bytes; got {len(data)}."
        )

    version = data[0] >> 4
    ihl = data[0] & 0x0F

    if version != 4:
        raise IPv4ParseError(f"Expected IPv4 version 4; got version {version}.")

    if ihl < 5:
        raise IPv4ParseError(f"IPv4 IHL must be at least 5 words; got {ihl}.")

    header_length = ihl * 4

    if len(data) < header_length:
        raise IPv4ParseError(
            f"IPv4 IHL={ihl} requires a {header_length}-byte header; "
            f"got {len(data)} bytes."
        )

    dscp_ecn = data[1]
    total_length = int.from_bytes(data[2:4], byteorder="big")

    if total_length < header_length:
        raise IPv4ParseError(
            f"IPv4 total length {total_length} is smaller than "
            f"header length {header_length}."
        )

    if len(data) < total_length:
        raise IPv4ParseError(
            f"IPv4 total length declares {total_length} bytes; got {len(data)}."
        )

    flags_and_offset = int.from_bytes(data[6:8], byteorder="big")

    return IPv4Datagram(
        version=version,
        ihl=ihl,
        dscp=dscp_ecn >> 2,
        ecn=dscp_ecn & 0x03,
        total_length=total_length,
        identification=int.from_bytes(data[4:6], byteorder="big"),
        flags=(flags_and_offset >> 13) & 0x07,
        fragment_offset=flags_and_offset & 0x1FFF,
        ttl=data[8],
        protocol=data[9],
        header_checksum=int.from_bytes(data[10:12], byteorder="big"),
        source=data[12:16],
        destination=data[16:20],
        options=data[20:header_length],
        payload=data[header_length:total_length],
        trailing_bytes=data[total_length:],
    )
