"""Passive ICMPv6 Neighbor Solicitation/Advertisement wire decoder.

Stage 1 only: RFC 4861 packet validity and original typed evidence.
No neighbor cache, endpoint identity, SLAAC, active probes, or network map.
Only direct IPv6 Next Header 58 is supported by the packet pipeline;
extension headers and IPv6 fragmentation are intentionally deferred.
"""

from dataclasses import dataclass
from ipaddress import IPv6Address

ICMPV6_NEXT_HEADER = 58
NEIGHBOR_SOLICITATION = 135
NEIGHBOR_ADVERTISEMENT = 136
SOURCE_LINK_LAYER_ADDRESS = 1
TARGET_LINK_LAYER_ADDRESS = 2
ND_MESSAGE_MIN_LENGTH = 24
IPV6_UNSPECIFIED = bytes(16)


class NeighborDiscoveryParseError(ValueError):
    """Invalid ICMPv6 Neighbor Discovery packet evidence."""


@dataclass(frozen=True, slots=True)
class NeighborDiscoveryOption:
    """Length-prefixed option from the exact wire data, including unknown types."""

    option_type: int
    length_units: int
    data: bytes

    @property
    def ethernet_address(self) -> bytes | None:
        """Only the six address octets of an exactly eight-byte option.

        The caller must additionally check option_type and which ND message
        contains the option. Never interpret an arbitrary option as an MAC.
        """
        return self.data if self.length_units == 1 and len(self.data) == 6 else None


@dataclass(frozen=True, slots=True)
class NeighborSolicitation:
    source: bytes
    destination: bytes
    target: bytes
    checksum: int
    reserved: int
    options: tuple[NeighborDiscoveryOption, ...]
    source_link_layer: bytes | None
    is_dad_probe: bool
    type: int = NEIGHBOR_SOLICITATION


@dataclass(frozen=True, slots=True)
class NeighborAdvertisement:
    source: bytes
    destination: bytes
    target: bytes
    checksum: int
    flags_raw: int
    router: bool
    solicited: bool
    override: bool
    options: tuple[NeighborDiscoveryOption, ...]
    target_link_layer: bytes | None
    type: int = NEIGHBOR_ADVERTISEMENT


def _ones_complement_sum(data: bytes) -> int:
    """Fold 16-bit words including odd trailing-byte padding."""
    if len(data) & 1:
        data += b"\x00"
    total = sum(
        int.from_bytes(data[index:index + 2], "big")
        for index in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def icmpv6_checksum_valid(
    message: bytes, *, source: bytes, destination: bytes
) -> bool:
    """RFC 4443 checksum with IPv6 pseudoheader Next Header=58."""
    if len(source) != 16 or len(destination) != 16:
        raise NeighborDiscoveryParseError("IPv6 addresses must be 16 octets")
    pseudoheader = (
        source + destination + len(message).to_bytes(4, "big")
        + bytes(3) + bytes((ICMPV6_NEXT_HEADER,))
    )
    return _ones_complement_sum(pseudoheader + message) == 0xFFFF


def _read_options(data: bytes) -> tuple[NeighborDiscoveryOption, ...]:
    result: list[NeighborDiscoveryOption] = []
    position = 0
    while position < len(data):
        if position + 2 > len(data):
            raise NeighborDiscoveryParseError("truncated ND option header")
        kind, length = data[position:position + 2]
        if length == 0:
            raise NeighborDiscoveryParseError("zero-length ND option")
        end = position + length * 8
        if end > len(data):
            raise NeighborDiscoveryParseError("ND option overruns ICMPv6 message")
        result.append(NeighborDiscoveryOption(
            option_type=kind,
            length_units=length,
            data=data[position + 2:end],
        ))
        position = end
    return tuple(result)


def _first_ethernet_option(
    options: tuple[NeighborDiscoveryOption, ...], kind: int
) -> bytes | None:
    for item in options:
        if item.option_type == kind:
            # Preserve non-Ethernet-sized options but make no MAC claim.
            return item.ethernet_address
    return None


def _solicited_node_multicast(target: bytes) -> bytes:
    """ff02::1:ffXX:XXXX for the final 24 bits of the target IPv6."""
    return bytes.fromhex("ff0200000000000000000001ff") + target[-3:]


def parse_neighbor_discovery(
    message: bytes, *, source: bytes, destination: bytes, hop_limit: int
) -> NeighborSolicitation | NeighborAdvertisement | None:
    """Decode RFC 4861 types 135/136, or return None for other ICMPv6.

    Received packet validity is enforced before returning an observation:
    IPv6 hop-limit=255, code=0, IPv6 pseudoheader checksum, nonmulticast
    target, nonzero well-bounded option lengths, and DAD/NA conditions.
    Unknown options and reserved flag bits are retained, not reinterpreted.

    A DAD Neighbor Solicitation has source :: and a *tentative* target.
    Its target is not an observed IPv6-to-MAC sender association.
    """
    if not isinstance(message, bytes):
        raise NeighborDiscoveryParseError("ICMPv6 packet must be bytes")
    if not message or message[0] not in (
        NEIGHBOR_SOLICITATION, NEIGHBOR_ADVERTISEMENT
    ):
        return None
    if len(source) != 16 or len(destination) != 16:
        raise NeighborDiscoveryParseError("IPv6 addresses must be 16 octets")
    if hop_limit != 255:
        raise NeighborDiscoveryParseError("Neighbor Discovery hop limit must be 255")
    if len(message) < ND_MESSAGE_MIN_LENGTH:
        raise NeighborDiscoveryParseError("truncated Neighbor Discovery message")
    if message[1] != 0:
        raise NeighborDiscoveryParseError("Neighbor Discovery code must be zero")
    if not icmpv6_checksum_valid(message, source=source, destination=destination):
        raise NeighborDiscoveryParseError("invalid ICMPv6 pseudoheader checksum")

    target = message[8:24]
    if IPv6Address(target).is_multicast:
        raise NeighborDiscoveryParseError("ND target must not be multicast")
    options = _read_options(message[24:])
    word = int.from_bytes(message[4:8], "big")
    checksum = int.from_bytes(message[2:4], "big")

    if message[0] == NEIGHBOR_SOLICITATION:
        is_dad_probe = source == IPV6_UNSPECIFIED
        if is_dad_probe:
            if destination != _solicited_node_multicast(target):
                raise NeighborDiscoveryParseError(
                    "DAD source :: requires matching solicited-node multicast"
                )
            if any(o.option_type == SOURCE_LINK_LAYER_ADDRESS for o in options):
                raise NeighborDiscoveryParseError(
                    "DAD must not include source link-layer address option"
                )
        return NeighborSolicitation(
            source=source, destination=destination,
            target=target, checksum=checksum, reserved=word,
            options=options,
            source_link_layer=_first_ethernet_option(
                options, SOURCE_LINK_LAYER_ADDRESS
            ),
            is_dad_probe=is_dad_probe,
        )

    router = bool(word & 0x80000000)
    solicited = bool(word & 0x40000000)
    override = bool(word & 0x20000000)
    if solicited and IPv6Address(destination).is_multicast:
        raise NeighborDiscoveryParseError(
            "solicited Neighbor Advertisement must not target multicast"
        )
    return NeighborAdvertisement(
        source=source, destination=destination, target=target,
        checksum=checksum, flags_raw=word,
        router=router, solicited=solicited, override=override,
        options=options,
        target_link_layer=_first_ethernet_option(
            options, TARGET_LINK_LAYER_ADDRESS
        ),
    )
