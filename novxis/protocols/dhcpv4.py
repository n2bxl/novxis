"""Bounded DHCPv4/BOOTP payload decoding, independent of capture providers.

This is a wire decoder, not a DHCP lease state machine. DHCP options are
preserved in their original order and option-overload semantics are deferred.
"""

from dataclasses import dataclass

BOOTP_FIXED_HEADER_LENGTH = 236
DHCPV4_MAGIC_COOKIE = bytes.fromhex("63825363")
DHCPV4_MIN_LENGTH = BOOTP_FIXED_HEADER_LENGTH + len(DHCPV4_MAGIC_COOKIE)
DHCPV4_OPTION_PAD = 0
DHCPV4_OPTION_END = 255
DHCPV4_OPTION_MESSAGE_TYPE = 53


class DHCPv4ParseError(ValueError):
    """Raised when the DHCPv4 payload is too short or structurally malformed."""


@dataclass(frozen=True, slots=True)
class DHCPv4Option:
    """One complete TLV option as observed in the main DHCP options field."""

    code: int
    value: bytes
    offset: int  # Offset from the beginning of the DHCP UDP payload.


@dataclass(frozen=True, slots=True)
class DHCPv4Message:
    """BOOTP fields and the ordered DHCP options, without inferred lease state."""

    op: int
    htype: int
    hlen: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: bytes
    yiaddr: bytes
    siaddr: bytes
    giaddr: bytes
    chaddr: bytes
    chaddr_padding: bytes
    sname: bytes
    boot_file: bytes
    options: tuple[DHCPv4Option, ...]
    raw_options: bytes
    pad_offsets: tuple[int, ...]
    end_seen: bool
    trailing_bytes: bytes

    def option_values(self, code: int) -> tuple[bytes, ...]:
        """Return all values for an option code, preserving duplicates."""
        return tuple(option.value for option in self.options if option.code == code)

    @property
    def message_type(self) -> int | None:
        """Return unambiguous option-53 type, or None if absent/malformed."""
        values = self.option_values(DHCPV4_OPTION_MESSAGE_TYPE)
        if len(values) != 1 or len(values[0]) != 1:
            return None
        return values[0][0]


def parse_dhcpv4(data: bytes) -> DHCPv4Message:
    """Decode the bounded BOOTP prefix and the main DHCP options field.

    The DHCP magic cookie is required. Options are parsed as code/length/value,
    except one-byte PAD (0) and END (255) codes. Unknown and repeated options
    remain intact. Any bytes after END remain trailing evidence; no option
    overload decoding, client state inference, or IP reachability claim occurs.
    """
    if len(data) < DHCPV4_MIN_LENGTH:
        raise DHCPv4ParseError(
            f"DHCPv4 requires at least {DHCPV4_MIN_LENGTH} bytes; got {len(data)}."
        )
    if data[BOOTP_FIXED_HEADER_LENGTH:DHCPV4_MIN_LENGTH] != DHCPV4_MAGIC_COOKIE:
        raise DHCPv4ParseError("DHCPv4 magic cookie is missing or invalid.")

    hardware_length = data[2]
    if hardware_length > 16:
        raise DHCPv4ParseError(
            f"BOOTP hardware address length exceeds the 16-byte chaddr field: "
            f"hlen={hardware_length}."
        )

    options: list[DHCPv4Option] = []
    pad_offsets: list[int] = []
    cursor = DHCPV4_MIN_LENGTH
    end_seen = False
    while cursor < len(data):
        offset = cursor
        code = data[cursor]
        cursor += 1
        if code == DHCPV4_OPTION_PAD:
            pad_offsets.append(offset)
            continue
        if code == DHCPV4_OPTION_END:
            end_seen = True
            break
        if cursor >= len(data):
            raise DHCPv4ParseError(f"DHCP option {code} at offset {offset} lacks length.")
        length = data[cursor]
        cursor += 1
        if cursor + length > len(data):
            raise DHCPv4ParseError(
                f"DHCP option {code} at offset {offset} declares {length} "
                f"bytes but only {len(data) - cursor} remain."
            )
        options.append(DHCPv4Option(code, data[cursor:cursor + length], offset))
        cursor += length

    return DHCPv4Message(
        op=data[0],
        htype=data[1],
        hlen=hardware_length,
        hops=data[3],
        xid=int.from_bytes(data[4:8], "big"),
        secs=int.from_bytes(data[8:10], "big"),
        flags=int.from_bytes(data[10:12], "big"),
        ciaddr=data[12:16],
        yiaddr=data[16:20],
        siaddr=data[20:24],
        giaddr=data[24:28],
        chaddr=data[28:28 + hardware_length],
        chaddr_padding=data[28 + hardware_length:44],
        sname=data[44:108],
        boot_file=data[108:236],
        options=tuple(options),
        raw_options=data[DHCPV4_MIN_LENGTH:],
        pad_offsets=tuple(pad_offsets),
        end_seen=end_seen,
        trailing_bytes=data[cursor:] if end_seen else b"",
    )
