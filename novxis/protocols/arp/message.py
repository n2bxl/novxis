"""Evidence model for a decoded ARP message."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ARPMessage:
    """Decoded ARP fields exactly as represented by the message."""

    hardware_type: int
    protocol_type: int
    hardware_length: int
    protocol_length: int
    opcode: int
    sender_hardware: bytes
    sender_protocol: bytes
    target_hardware: bytes
    target_protocol: bytes
    trailing_bytes: bytes
