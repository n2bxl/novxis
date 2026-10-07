"""Evidence model for an IPv4 datagram quoted inside another protocol."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IPv4DatagramQuote:
    """Decoded IPv4 header plus only the quoted bytes that were available."""

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
    payload_prefix: bytes
    trailing_bytes: bytes
    available_length: int

    @property
    def header_length(self) -> int:
        """Return the original IPv4 header length in bytes."""
        return self.ihl * 4

    @property
    def is_truncated(self) -> bool:
        """Whether the quote ends before the original datagram's declared length."""
        return self.available_length < self.total_length
