"""RFC 4861 NS/NA wire validation with fully checksummed synthetic messages."""

from ipaddress import IPv6Address

import pytest

from novxis.protocols.icmpv6_nd import (
    NeighborAdvertisement, NeighborDiscoveryParseError,
    NeighborSolicitation, icmpv6_checksum_valid, parse_neighbor_discovery,
)

SRC = IPv6Address("fe80::10").packed
DST = IPv6Address("fe80::20").packed
TARGET = IPv6Address("2001:db8::1234").packed
MAC = bytes.fromhex("0266778899aa")
SLLA = b"\x01\x01" + MAC
TLLA = b"\x02\x01" + MAC
DAD_DST = IPv6Address("ff02::1:ff00:1234").packed
ALL_NODES = IPv6Address("ff02::1").packed
UNSPECIFIED = bytes(16)


def checksum(source: bytes, destination: bytes, data: bytes) -> int:
    """Independent test fixture encoder, including pseudoheader and folding."""
    header = (
        source + destination + len(data).to_bytes(4, "big")
        + b"\x00\x00\x00\x3a"
    )
    raw = header + data
    if len(raw) % 2:
        raw += b"\x00"
    words = [int.from_bytes(raw[i:i + 2], "big")
             for i in range(0, len(raw), 2)]
    total = sum(words)
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(kind=135, *, source=SRC, destination=DST, target=TARGET,
           flags=0, options=b"", code=0):
    raw = (
        bytes((kind, code)) + b"\x00\x00"
        + flags.to_bytes(4, "big") + target + options
    )
    value = checksum(source, destination, raw)
    return raw[:2] + value.to_bytes(2, "big") + raw[4:]


def decode(kind=135, *, hop_limit=255, source=SRC, destination=DST,
           target=TARGET, flags=0, options=b"", code=0):
    wire = packet(kind, source=source, destination=destination,
                  target=target, flags=flags, options=options, code=code)
    return parse_neighbor_discovery(
        wire, source=source, destination=destination, hop_limit=hop_limit,
    )


def test_neighbor_solicitation_preserves_target_source_lladdr_and_provenance():
    result = decode(options=SLLA)
    assert isinstance(result, NeighborSolicitation)
    assert result.type == 135
    assert result.source == SRC and result.destination == DST
    assert result.target == TARGET
    assert result.source_link_layer == MAC
    assert result.options[0].option_type == 1
    assert result.options[0].length_units == 1
    assert not result.is_dad_probe
    assert icmpv6_checksum_valid(
        packet(options=SLLA), source=SRC, destination=DST,
    )


def test_neighbor_advertisement_flags_and_target_link_layer_are_distinct():
    result = decode(136, options=TLLA, flags=0xE0000000)
    assert isinstance(result, NeighborAdvertisement)
    assert result.type == 136
    assert result.router and result.solicited and result.override
    assert result.flags_raw == 0xE0000000
    assert result.target_link_layer == MAC
    assert result.options[0].option_type == 2


def test_dad_source_unspecified_is_tentative_without_mac_claim():
    result = decode(
        source=UNSPECIFIED, destination=DAD_DST, options=b"",
    )
    assert isinstance(result, NeighborSolicitation)
    assert result.is_dad_probe
    assert result.target == TARGET
    assert result.source_link_layer is None


def test_reserved_bits_are_preserved_but_not_interpreted():
    ns = decode(flags=0x0000008F)
    assert ns.reserved == 0x8F
    na = decode(136, flags=0x0000001F)
    assert na.flags_raw == 0x1F
    assert not na.router and not na.solicited and not na.override


def test_unknown_option_is_kept_without_becoming_a_mac():
    unknown = b"\xfa\x01" + b"\xff" * 6
    result = decode(options=unknown)
    assert result.options[0].option_type == 250
    assert result.options[0].data == b"\xff" * 6
    assert result.source_link_layer is None


def test_wrong_kind_link_layer_option_does_not_create_sender_claim():
    result = decode(options=TLLA)
    assert result.source_link_layer is None
    result = decode(136, options=SLLA)
    assert result.target_link_layer is None


def test_multiple_valid_options_are_parsed_without_guessing_device_identity():
    unknown = b"\xfd\x01" + b"\x00" * 6
    result = decode(options=unknown + SLLA)
    assert len(result.options) == 2
    assert result.options[1].ethernet_address == MAC
    assert result.source_link_layer == MAC


def test_non_ethernet_option_length_remains_opaque():
    raw = b"\x01\x02" + b"\x10" * 14
    result = decode(options=raw)
    assert len(result.options) == 1
    assert result.options[0].length_units == 2
    assert result.options[0].ethernet_address is None
    assert result.source_link_layer is None


def test_unsupported_icmpv6_types_are_ignored_before_nd_validation():
    for kind in (128, 129, 133, 134, 137):
        assert decode(kind, hop_limit=20) is None
    assert parse_neighbor_discovery(
        b"", source=SRC, destination=DST, hop_limit=255,
    ) is None


@pytest.mark.parametrize("length", [0, 1, 3, 7, 23])
def test_truncated_neighbor_discovery_is_rejected(length):
    raw = packet()
    with pytest.raises(NeighborDiscoveryParseError, match="truncated"):
        parse_neighbor_discovery(
            raw[:length], source=SRC, destination=DST, hop_limit=255,
        )


@pytest.mark.parametrize("kind", [135, 136])
def test_hop_limit_below_255_is_rejected(kind):
    with pytest.raises(NeighborDiscoveryParseError, match="hop limit"):
        decode(kind, hop_limit=254)


@pytest.mark.parametrize("kind", [135, 136])
def test_nonzero_code_is_rejected(kind):
    with pytest.raises(NeighborDiscoveryParseError, match="code"):
        decode(kind, code=1)


@pytest.mark.parametrize("kind", [135, 136])
def test_corrupted_checksum_is_rejected(kind):
    raw = bytearray(packet(kind))
    raw[-1] ^= 1
    with pytest.raises(NeighborDiscoveryParseError, match="checksum"):
        parse_neighbor_discovery(
            bytes(raw), source=SRC, destination=DST, hop_limit=255,
        )


def test_checksum_rejects_changed_pseudoheader_even_with_same_body():
    raw = packet()
    assert not icmpv6_checksum_valid(
        raw, source=SRC, destination=ALL_NODES,
    )


@pytest.mark.parametrize("kind", [135, 136])
def test_multicast_target_is_not_a_valid_nd_target(kind):
    with pytest.raises(NeighborDiscoveryParseError, match="target"):
        decode(kind, target=ALL_NODES)


@pytest.mark.parametrize("kind", [135, 136])
def test_zero_length_option_rejected(kind):
    with pytest.raises(NeighborDiscoveryParseError, match="zero-length"):
        decode(kind, options=b"\x01\x00" + b"\x00" * 6)


@pytest.mark.parametrize("option", [
    b"\x01",
    b"\x01\x01",
    b"\x02\x02" + b"\x00" * 6,
])
def test_truncated_or_overrun_option_rejected(option):
    with pytest.raises(NeighborDiscoveryParseError, match="option"):
        decode(options=option)


def test_dad_requires_correct_solicited_node_multicast_destination():
    with pytest.raises(
        NeighborDiscoveryParseError, match="solicited-node"
    ):
        decode(source=UNSPECIFIED, destination=ALL_NODES)


def test_dad_must_not_include_slla_even_when_checksum_is_valid():
    with pytest.raises(NeighborDiscoveryParseError, match="DAD"):
        decode(source=UNSPECIFIED, destination=DAD_DST, options=SLLA)


def test_solicited_na_must_not_go_to_multicast():
    with pytest.raises(NeighborDiscoveryParseError, match="multicast"):
        decode(136, destination=ALL_NODES, flags=0x40000000)


def test_unsolicited_na_may_be_multicast_without_solicited_flag():
    result = decode(136, destination=ALL_NODES, flags=0x20000000, options=TLLA)
    assert not result.solicited
    assert result.override
    assert result.target_link_layer == MAC


def test_na_can_omit_tlla_without_inventing_a_link_layer_address():
    result = decode(136)
    assert result.target_link_layer is None


@pytest.mark.parametrize("source,destination", [
    (b"\x00", DST), (SRC, b"\x00"), (SRC[:-1], DST),
])
def test_invalid_pseudoheader_address_lengths_are_rejected(source, destination):
    with pytest.raises(NeighborDiscoveryParseError, match="16 octets"):
        parse_neighbor_discovery(
            packet(), source=source, destination=destination, hop_limit=255,
        )
