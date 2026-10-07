"""UDP datagram evidence decoding (RFC 768), independent of capture providers."""

from dataclasses import dataclass

UDP_HEADER_LENGTH = 8


class UDPParseError(ValueError):
    """Raised when UDP bytes are incomplete or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class UDPDatagram:
    """Decoded UDP header, bounded payload, and preserved trailing evidence."""

    source_port: int
    destination_port: int
    length: int
    checksum: int
    payload: bytes
    trailing_bytes: bytes

    @property
    def payload_length(self) -> int:
        return len(self.payload)


def parse_udp(data: bytes) -> UDPDatagram:
    """Decode a complete UDP datagram without inferring its application protocol.

    UDP length includes the eight-byte header. Bytes beyond that length are
    preserved as evidence, not silently included in the UDP payload.
    Checksum is reported as carried; verification requires the IP pseudoheader.
    """
    if len(data) < UDP_HEADER_LENGTH:
        raise UDPParseError(
            f"UDP header requires {UDP_HEADER_LENGTH} bytes; got {len(data)}."
        )

    source_port = int.from_bytes(data[0:2], "big")
    destination_port = int.from_bytes(data[2:4], "big")
    length = int.from_bytes(data[4:6], "big")
    checksum = int.from_bytes(data[6:8], "big")

    if length < UDP_HEADER_LENGTH:
        raise UDPParseError(
            f"UDP length must be at least {UDP_HEADER_LENGTH}; got {length}."
        )
    if length > len(data):
        raise UDPParseError(
            f"UDP declares {length} bytes but only {len(data)} are present."
        )

    return UDPDatagram(
        source_port=source_port,
        destination_port=destination_port,
        length=length,
        checksum=checksum,
        payload=data[UDP_HEADER_LENGTH:length],
        trailing_bytes=data[length:],
    )
