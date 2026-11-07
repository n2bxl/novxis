"""End-to-end Ethernet II -> IPv6 -> ICMPv6 NS/NA without host identity."""

from decimal import Decimal
from ipaddress import IPv6Address

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.ndp import NeighborDiscoveryPipeline
from novxis.pipeline.link import UnsupportedLinkTypeError
from novxis.protocols.icmpv6_nd import (
    NeighborAdvertisement, NeighborDiscoveryParseError, NeighborSolicitation,
)
from novxis.protocols.ipv6 import IPv6ParseError

SRC = IPv6Address("fe80::10").packed
DEST = IPv6Address("fe80::20").packed
TARGET = IPv6Address("2001:db8::10").packed
ETHERNET_SRC = bytes.fromhex("020000000010")
SLLA = b"\x01\x01" + bytes.fromhex("020000000099")
TLLA = b"\x02\x01" + bytes.fromhex("020000000088")


def _checksum(src, dst, payload):
    pseudo = src + dst + len(payload).to_bytes(4, "big") + b"\x00\x00\x00\x3a"
    data = pseudo + payload
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i:i + 2], "big")
                for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_frame(*, kind=135, options=SLLA, next_header=58, hop_limit=255,
               ethertype=0x86DD, source=SRC, destination=DEST, target=TARGET,
               flags=0, extra=b"", link_type=1, corrupt=False):
    icmp = (
        bytes((kind, 0)) + b"\x00\x00"
        + flags.to_bytes(4, "big") + target + options
    )
    icmp = icmp[:2] + _checksum(source, destination, icmp).to_bytes(2, "big") + icmp[4:]
    if corrupt:
        icmp = icmp[:-1] + bytes((icmp[-1] ^ 0xFF,))
    header = (
        b"\x60\x00\x00\x00" + len(icmp).to_bytes(2, "big")
        + bytes((next_header, hop_limit)) + source + destination
    )
    ethernet = (
        bytes.fromhex("333300000001") + ETHERNET_SRC
        + ethertype.to_bytes(2, "big")
    )
    data = ethernet + header + icmp + extra
    return CapturedFrame(
        timestamp=Decimal("101.125"), interface="fixture-en5",
        data=data, captured_length=len(data), original_length=len(data),
        link_type=link_type,
    )


def test_ns_pipeline_retains_frame_and_separate_link_layer_sources():
    frame = make_frame()
    observed = NeighborDiscoveryPipeline().process(frame)
    assert observed is not None
    assert observed.captured is frame
    assert observed.ethernet.source == ETHERNET_SRC
    assert observed.ipv6.source == SRC
    assert observed.ipv6.destination == DEST
    assert isinstance(observed.message, NeighborSolicitation)
    assert observed.message.target == TARGET
    # Never assume the Ethernet sender equals the source LLA option.
    assert observed.message.source_link_layer != observed.ethernet.source
    assert observed.message.source_link_layer == SLLA[2:]


def test_na_pipeline_retains_flags_and_tlla():
    result = NeighborDiscoveryPipeline().process(
        make_frame(kind=136, options=TLLA, flags=0x60000000)
    )
    assert result is not None
    assert isinstance(result.message, NeighborAdvertisement)
    assert result.message.solicited and result.message.override
    assert not result.message.router
    assert result.message.target_link_layer == TLLA[2:]


def test_dad_probe_is_tentative_not_a_sender_binding():
    unspecified = bytes(16)
    solicited = IPv6Address("ff02::1:ff00:10").packed
    result = NeighborDiscoveryPipeline().process(
        make_frame(source=unspecified, destination=solicited, options=b"")
    )
    assert isinstance(result.message, NeighborSolicitation)
    assert result.message.is_dad_probe
    assert result.message.source_link_layer is None


@pytest.mark.parametrize("next_header", [0, 6, 17, 43, 44, 60])
def test_not_direct_icmpv6_is_skipped_without_guessing(next_header):
    assert NeighborDiscoveryPipeline().process(
        make_frame(next_header=next_header)
    ) is None


def test_unrelated_ethernet_ethertype_is_skipped():
    assert NeighborDiscoveryPipeline().process(
        make_frame(ethertype=0x0800)
    ) is None


@pytest.mark.parametrize("kind", [128, 129, 133, 134, 137])
def test_non_ns_na_icmpv6_types_are_skipped(kind):
    assert NeighborDiscoveryPipeline().process(make_frame(kind=kind)) is None


def test_invalid_hop_limit_rejected_in_pipeline():
    with pytest.raises(NeighborDiscoveryParseError, match="hop limit"):
        NeighborDiscoveryPipeline().process(make_frame(hop_limit=64))


def test_invalid_checksum_rejected_in_pipeline():
    with pytest.raises(NeighborDiscoveryParseError, match="checksum"):
        NeighborDiscoveryPipeline().process(make_frame(corrupt=True))


def test_declared_ipv6_payload_bounds_ignore_ethernet_padding():
    observed = NeighborDiscoveryPipeline().process(
        make_frame(extra=b"\xde\xad\xbe\xef")
    )
    assert isinstance(observed.message, NeighborSolicitation)
    assert observed.ipv6.trailing_bytes == b"\xde\xad\xbe\xef"
    assert observed.message.source_link_layer == SLLA[2:]


def test_ipv6_truncation_rejected_before_icmpv6_decode():
    f = make_frame()
    short = CapturedFrame(
        timestamp=f.timestamp, interface=f.interface, data=f.data[:47],
        captured_length=47, link_type=1,
    )
    with pytest.raises(IPv6ParseError):
        NeighborDiscoveryPipeline().process(short)


def test_unsupported_link_type_rejected_in_pipeline():
    with pytest.raises(UnsupportedLinkTypeError):
        NeighborDiscoveryPipeline().process(make_frame(link_type=101))


def test_unknown_link_type_can_be_accepted_for_live_ethernet_frames():
    result = NeighborDiscoveryPipeline().process(
        make_frame(link_type=None)
    )
    assert result is not None


def test_packet_noncanonical_option_does_not_infer_mac():
    option = b"\x01\x02" + b"\x03" * 14
    result = NeighborDiscoveryPipeline().process(make_frame(options=option))
    assert result.message.source_link_layer is None
    assert result.message.options[0].data == b"\x03" * 14
