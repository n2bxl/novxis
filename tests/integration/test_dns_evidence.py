"""End-to-end DNS-over-UDP evidence tests with synthetic, nonprivate bytes."""

from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events.dns import DNSMessageObserved
from novxis.pipeline.dns import DNSEventPipeline
from novxis.presentation.dns_console import format_dns_observation
from novxis.protocols.dns import DNSParseError

QNAME = b"\x04node\x07example\x04test\x00"
QUESTION = QNAME + b"\x00\x01\x00\x01"
CLIENT_IP = bytes((192, 0, 2, 30))
SERVER_IP = bytes((192, 0, 2, 53))


def _dns(*, response: bool = False, malformed: bool = False) -> bytes:
    if malformed:
        return b"bad"
    flags = 0x8180 if response else 0x0100
    header = (
        b"\xab\xcd" + flags.to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + int(response).to_bytes(2, "big")
        + bytes(4)
    )
    if not response:
        return header + QUESTION
    answer = (
        b"\xc0\x0c\x00\x01\x00\x01"
        + (120).to_bytes(4, "big")
        + b"\x00\x04\xc0\x00\x02\x1a"
    )
    return header + QUESTION + answer


def _frame(
    *, response: bool = False, source_port: int | None = None,
    destination_port: int | None = None, protocol: int = 17,
    ether_type: int = 0x0800, flags_offset: int = 0x4000,
    malformed: bool = False, link_type: int = 1,
) -> CapturedFrame:
    payload = _dns(response=response, malformed=malformed)
    sp = (53 if response else 53000) if source_port is None else source_port
    dp = (53000 if response else 53) if destination_port is None else destination_port
    udp = (
        sp.to_bytes(2, "big") + dp.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00" + payload
    )
    source = SERVER_IP if response else CLIENT_IP
    destination = CLIENT_IP if response else SERVER_IP
    ipv4 = (
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x01" + flags_offset.to_bytes(2, "big")
        + bytes((64, protocol)) + b"\x00\x00"
        + source + destination + udp
    )
    ethernet = (
        bytes.fromhex("0211223344550266778899aa")
        + ether_type.to_bytes(2, "big") + ipv4
    )
    return CapturedFrame(
        timestamp=Decimal("1760200800.125") if not response else Decimal("1760200800.175"),
        interface="fixture0",
        data=ethernet, captured_length=len(ethernet),
        original_length=len(ethernet), link_type=link_type,
    )


def test_full_stack_query_retains_original_packet_and_message():
    frame = _frame()
    observation = DNSEventPipeline().process(frame)
    assert isinstance(observation, DNSMessageObserved)
    assert observation.captured is frame
    assert observation.udp_observation.captured is frame
    assert observation.interface == "fixture0"
    assert observation.timestamp == Decimal("1760200800.125")
    assert observation.ethernet.ether_type == 0x0800
    assert observation.ipv4.source == CLIENT_IP
    assert observation.udp.source_port == 53000
    assert observation.udp.destination_port == 53
    assert observation.message.header.transaction_id == 0xABCD
    assert not observation.message.header.is_response
    assert observation.message.questions[0].name.text == "node.example.test"
    rendered = format_dns_observation(observation)
    assert "DNSMessageObserved" in rendered
    assert "query" in rendered
    assert "id=0xabcd" in rendered
    assert "q=node.example.test/A/class1" in rendered
    assert "resolved" not in rendered.lower()
    assert "completed" not in rendered.lower()


def test_full_stack_response_reports_raw_answer_and_ttl_without_host_claim():
    observation = DNSEventPipeline().process(_frame(response=True))
    assert isinstance(observation, DNSMessageObserved)
    assert observation.ipv4.source == SERVER_IP
    assert observation.udp.source_port == 53
    assert observation.message.header.is_response
    answer = observation.message.answers[0]
    assert answer.name.text == "node.example.test"
    assert answer.rdata == bytes((192, 0, 2, 26))
    assert answer.decoded_data == "192.0.2.26"
    assert answer.ttl == 120
    rendered = format_dns_observation(observation)
    assert "response" in rendered
    assert "192.0.2.53:53" in rendered
    assert "answer=node.example.test/A/class1=192.0.2.26(ttl=120s)" in rendered
    assert "host identity" not in rendered.lower()


@pytest.mark.parametrize(
    "changes",
    [
        {"source_port": 5353, "destination_port": 5353},  # mDNS separate
        {"source_port": 5353, "destination_port": 9999},
        {"source_port": 5353, "destination_port": 5354},
        {"source_port": 53000, "destination_port": 9999},
        {"protocol": 6},             # DNS-over-TCP not implemented
        {"ether_type": 0x0806},      # ARP
        {"flags_offset": 0x2000},    # first IPv4 fragment
        {"flags_offset": 0x0001},    # later IPv4 fragment
    ],
)
def test_non_dns_or_fragmented_network_traffic_is_not_decoded(changes):
    assert DNSEventPipeline().process(_frame(**changes)) is None


def test_same_source_and_destination_dns_port_is_supported():
    observation = DNSEventPipeline().process(
        _frame(source_port=53, destination_port=53)
    )
    assert observation is not None
    assert observation.udp.source_port == 53
    assert observation.udp.destination_port == 53


def test_malformed_port_53_payload_is_reported_not_silently_ignored():
    with pytest.raises(DNSParseError, match="header requires"):
        DNSEventPipeline().process(_frame(malformed=True))


def test_port_53_is_not_sufficient_to_prove_valid_dns():
    with pytest.raises(DNSParseError):
        DNSEventPipeline().process(_frame(response=True, malformed=True))


def test_pipeline_remains_stateless_and_does_not_correlate_exchanges():
    pipeline = DNSEventPipeline()
    request = pipeline.process(_frame())
    reply = pipeline.process(_frame(response=True))
    assert isinstance(request, DNSMessageObserved)
    assert isinstance(reply, DNSMessageObserved)
    assert request.message.header.transaction_id == reply.message.header.transaction_id
    assert not hasattr(pipeline, "completed_exchanges")
