"""Synthetic IPv4/IPv6 Ethernet→UDP→mDNS evidence integration tests."""

from decimal import Decimal
from ipaddress import IPv6Address

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events.mdns import MDNSMessageObserved
from novxis.pipeline.link import UnsupportedLinkTypeError
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.presentation.mdns_console import format_mdns_observation
from novxis.protocols.dns import DNSParseError
from novxis.protocols.ipv6 import IPv6ParseError

SERVICE = b"\x05_demo\x04_tcp\x05local\x00"
INSTANCE = b"\x04Node\x05_demo\x04_tcp\x05local\x00"
SRC_V4 = bytes((192, 0, 2, 10))
DST_V4 = bytes((224, 0, 0, 251))
SRC_V6 = IPv6Address("fe80::10").packed
DST_V6 = IPv6Address("ff02::fb").packed


def _dns(*, response=False, bad=False, class_value=0x8001):
    if bad:
        return b"bad"
    if not response:
        return (
            b"\x00\x00\x00\x00\x00\x01" + b"\x00" * 6
            + SERVICE + b"\x00\x0c" + class_value.to_bytes(2, "big")
        )
    answer = (
        SERVICE + b"\x00\x0c\x00\x01"
        + (120).to_bytes(4, "big")
        + len(INSTANCE).to_bytes(2, "big")
        + INSTANCE
    )
    return b"\x00\x00\x84\x00\x00\x00\x00\x01" + b"\x00" * 4 + answer


def _frame(
    *, family=4, response=False, bad=False, sport=5353,
    dport=5353, next_header=17, ipv4_offset=0,
    link_type=1, ether_type=None, payload_override=None,
    v6_length_override=None,
):
    dns = _dns(response=response, bad=bad)
    payload = dns if payload_override is None else payload_override
    udp = (
        sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x01" + payload
    )
    if family == 4:
        raw_ip = (
            b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
            + b"\x00\x01" + ipv4_offset.to_bytes(2, "big")
            + bytes((255, next_header)) + b"\x00\x00"
            + SRC_V4 + DST_V4 + udp
        )
        etype = 0x0800
    else:
        declared = len(udp) if v6_length_override is None else v6_length_override
        raw_ip = (
            b"\x60\x00\x00\x00"
            + declared.to_bytes(2, "big")
            + bytes((next_header, 255))
            + SRC_V6 + DST_V6 + udp
        )
        etype = 0x86DD
    ethernet = (
        bytes.fromhex("01005e0000fb0266778899aa")
        + (etype if ether_type is None else ether_type).to_bytes(2, "big")
        + raw_ip
    )
    return CapturedFrame(
        timestamp=Decimal("1792341600.125"),
        interface="fixture0",
        data=ethernet, captured_length=len(ethernet),
        original_length=len(ethernet), link_type=link_type,
    )


@pytest.mark.parametrize("family", [4, 6])
def test_query_keeps_full_frame_and_qu_question(family):
    frame = _frame(family=family)
    observed = MDNSEventPipeline().process(frame)
    assert isinstance(observed, MDNSMessageObserved)
    assert observed.captured is frame
    assert observed.ip_version == family
    assert observed.interface == "fixture0"
    assert observed.timestamp == frame.timestamp
    assert observed.udp.source_port == 5353
    assert observed.message.questions[0].response_mode == "QU"
    assert observed.message.questions[0].wire.name.text == "_demo._tcp.local"
    assert not observed.message.is_response
    text = format_mdns_observation(observed)
    assert "MDNSMessageObserved" in text
    assert f"ipv{family}" in text
    assert "QU" in text
    assert "device identity" not in text


@pytest.mark.parametrize("family", [4, 6])
def test_response_retains_ptr_advertisement_without_resolving_host(family):
    observed = MDNSEventPipeline().process(_frame(family=family, response=True))
    assert observed is not None
    assert observed.message.is_response
    assert observed.message.answers[0].wire.rtype == 12
    assert observed.message.answers[0].wire.decoded_data == "Node._demo._tcp.local"
    assert observed.message.answers[0].wire.ttl == 120
    assert observed.message.known_answers == ()
    assert "response_answer" in format_mdns_observation(observed)
    if family == 6:
        assert str(IPv6Address(observed.ip.source)) == "fe80::10"
        assert str(IPv6Address(observed.ip.destination)) == "ff02::fb"
        assert observed.ip.hop_limit == 255


@pytest.mark.parametrize("changes", [
    {"sport": 12345, "dport": 54321},
    {"next_header": 6},
    {"ether_type": 0x0806},
])
def test_irrelevant_ipv4_frames_are_skipped(changes):
    assert MDNSEventPipeline().process(_frame(**changes)) is None


@pytest.mark.parametrize("ipv4_offset", [0x2000, 0x0001])
def test_ipv4_fragments_are_skipped(ipv4_offset):
    assert MDNSEventPipeline().process(_frame(ipv4_offset=ipv4_offset)) is None


@pytest.mark.parametrize("next_header", [0, 43, 44, 60, 6])
def test_ipv6_extension_headers_or_non_udp_are_not_misdecoded(next_header):
    assert MDNSEventPipeline().process(
        _frame(family=6, next_header=next_header)
    ) is None


def test_rejects_wrong_link_type_before_parsing():
    with pytest.raises(UnsupportedLinkTypeError):
        MDNSEventPipeline().process(_frame(link_type=101))


@pytest.mark.parametrize("family", [4, 6])
def test_invalid_mdns_payload_is_reported(family):
    with pytest.raises(DNSParseError):
        MDNSEventPipeline().process(_frame(family=family, bad=True))


def test_truncated_ipv6_payload_is_reported():
    with pytest.raises(IPv6ParseError):
        MDNSEventPipeline().process(
            _frame(family=6, v6_length_override=0xFF)
        )


def test_ip_only_nongated_packet_does_not_produce_mdns_observation():
    assert MDNSEventPipeline().process(
        _frame(family=6, sport=12345, dport=23456)
    ) is None
