"""Length-aware decoder for IPv4 datagrams quoted inside ICMP errors."""

from novxis.protocols.ipv4.quote import IPv4DatagramQuote

IPV4_MIN_HEADER_LENGTH = 20


class IPv4QuoteParseError(ValueError):
    """Raised when quoted bytes cannot contain a complete IPv4 header."""


def parse_ipv4_quote(data: bytes) -> IPv4DatagramQuote:
    """Decode an IPv4 header while allowing the original payload to be truncated."""
    if len(data) < IPV4_MIN_HEADER_LENGTH:
        raise IPv4QuoteParseError(
            "Quoted IPv4 evidence requires at least "
            f"{IPV4_MIN_HEADER_LENGTH} bytes; got {len(data)}."
        )

    version = data[0] >> 4
    ihl = data[0] & 0x0F

    if version != 4:
        raise IPv4QuoteParseError(
            f"Expected quoted IPv4 version 4; got version {version}."
        )

    if ihl < 5:
        raise IPv4QuoteParseError(
            f"Quoted IPv4 IHL must be at least 5 words; got {ihl}."
        )

    header_length = ihl * 4

    if len(data) < header_length:
        raise IPv4QuoteParseError(
            f"Quoted IPv4 IHL={ihl} requires a {header_length}-byte header; "
            f"got {len(data)} bytes."
        )

    total_length = int.from_bytes(data[2:4], byteorder="big")

    if total_length < header_length:
        raise IPv4QuoteParseError(
            f"Quoted IPv4 total length {total_length} is smaller than "
            f"header length {header_length}."
        )

    flags_and_offset = int.from_bytes(data[6:8], byteorder="big")
    logical_end = min(len(data), total_length)

    return IPv4DatagramQuote(
        version=version,
        ihl=ihl,
        dscp=data[1] >> 2,
        ecn=data[1] & 0x03,
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
        payload_prefix=data[header_length:logical_end],
        trailing_bytes=data[total_length:] if len(data) > total_length else b"",
        available_length=len(data),
    )
