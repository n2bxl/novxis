"""Evidence model for a decoded ICMPv4 message."""

from dataclasses import dataclass

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8


@dataclass(frozen=True, slots=True)
class ICMPMessage:
    """Decoded ICMPv4 fields exactly as represented by the message."""

    type: int
    code: int
    checksum: int
    rest_of_header: bytes
    payload: bytes

    @property
    def echo_identifier(self) -> int | None:
        """Return the Echo identifier when the message type uses Echo format."""
        if self.type not in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST):
            return None
        return int.from_bytes(self.rest_of_header[0:2], byteorder="big")

    @property
    def echo_sequence(self) -> int | None:
        """Return the Echo sequence number when the message type uses Echo format."""
        if self.type not in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST):
            return None
        return int.from_bytes(self.rest_of_header[2:4], byteorder="big")
