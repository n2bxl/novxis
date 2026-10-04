"""Length-aware ARP evidence decoder."""

from novxis.protocols.arp.message import ARPMessage

ARP_FIXED_HEADER_LENGTH = 8


class ARPParseError(ValueError):
    """Raised when bytes are insufficient for the ARP lengths they declare."""


def parse_arp(data: bytes) -> ARPMessage:
    """Decode ARP fields while preserving any bytes after the logical message."""
    if len(data) < ARP_FIXED_HEADER_LENGTH:
        raise ARPParseError(
            "ARP message requires at least "
            f"{ARP_FIXED_HEADER_LENGTH} fixed-header bytes; got {len(data)}."
        )

    hardware_type = int.from_bytes(data[0:2], byteorder="big")
    protocol_type = int.from_bytes(data[2:4], byteorder="big")
    hardware_length = data[4]
    protocol_length = data[5]
    opcode = int.from_bytes(data[6:8], byteorder="big")

    address_bytes = 2 * hardware_length + 2 * protocol_length
    logical_length = ARP_FIXED_HEADER_LENGTH + address_bytes

    if len(data) < logical_length:
        raise ARPParseError(
            "ARP message declares "
            f"HLEN={hardware_length} and PLEN={protocol_length}, requiring "
            f"{logical_length} bytes; got {len(data)}."
        )

    cursor = ARP_FIXED_HEADER_LENGTH

    sender_hardware = data[cursor : cursor + hardware_length]
    cursor += hardware_length

    sender_protocol = data[cursor : cursor + protocol_length]
    cursor += protocol_length

    target_hardware = data[cursor : cursor + hardware_length]
    cursor += hardware_length

    target_protocol = data[cursor : cursor + protocol_length]
    cursor += protocol_length

    return ARPMessage(
        hardware_type=hardware_type,
        protocol_type=protocol_type,
        hardware_length=hardware_length,
        protocol_length=protocol_length,
        opcode=opcode,
        sender_hardware=sender_hardware,
        sender_protocol=sender_protocol,
        target_hardware=target_hardware,
        target_protocol=target_protocol,
        trailing_bytes=data[cursor:],
    )
