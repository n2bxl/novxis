"""Evidence model for a decoded IPv4 datagram."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IPv4Datagram:
    """Decoded IPv4 fields exactly as represented by the datagram."""

    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source: bytes
    destination: bytes
    options: bytes
    payload: bytes
    trailing_bytes: bytes

    @property
    def header_length(self) -> int:
        """Return the IPv4 header length in bytes."""
        return self.ihl * 4
