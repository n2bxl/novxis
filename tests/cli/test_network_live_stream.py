"""Synthetic wire-level ARP/mDNS combined feed, without external traffic."""

import io
import json
from decimal import Decimal
from ipaddress import IPv6Address

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.capture.pcap_replay import PcapReplayProvider
from novxis.cli.network_live_stream import (
    MAX_ADS_PER_MESSAGE, build_handler, mdns_message,
)
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.views.mdns_services import project_dnssd_advertisements
from novxis.web.graph_data import DEFAULT_FIXTURE, build_arp_graph
from novxis.web.live_state import LiveARPGraphState, MAX_LINE, consume_stream

SERVICE = b"\x05_demo\x04_tcp\x05local\x00"
INSTANCE = b"\x04Node\x05_demo\x04_tcp\x05local\x00"


def frame(*, family=4, response=True, at="100", ttl=120, broken=False):
    if response:
        answer = (
            SERVICE + b"\x00\x0c\x00\x01" +
            ttl.to_bytes(4, "big") + len(INSTANCE).to_bytes(2, "big") + INSTANCE
        )
        dns = b"\x00\x00\x84\x00\x00\x00\x00\x01" + bytes(4) + answer
    else:
        # One question and an answer-section known-answer PTR; neither is a
        # service advertisement since this packet is a query.
        answer = (
            SERVICE + b"\x00\x0c\x00\x01" +
            ttl.to_bytes(4, "big") + len(INSTANCE).to_bytes(2, "big") + INSTANCE
        )
        question = SERVICE + b"\x00\x0c\x00\x01"
        dns = b"\x00\x00\x00\x00\x00\x01\x00\x01" + bytes(4) + question + answer
    if broken:
        dns = b"\x00"
    udp = (
        b"\x14\xe9\x14\xe9" +
        (8 + len(dns)).to_bytes(2, "big") + b"\x00\x01" + dns
    )
    if family == 4:
        ip = (
            b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big") +
            b"\x00\x00\x00\x00\xff\x11\x00\x00" +
            bytes((192, 0, 2, 10, 224, 0, 0, 251)) + udp
        )
        etype = b"\x08\x00"
    else:
        ip = (
            b"\x60\x00\x00\x00" + len(udp).to_bytes(2, "big") +
            b"\x11\xff" +
            IPv6Address("fe80::10").packed +
            IPv6Address("ff02::fb").packed + udp
        )
        etype = b"\x86\xdd"
    data = bytes.fromhex("01005e0000fb0266778899aa") + etype + ip
    return CapturedFrame(
        timestamp=Decimal(at), interface="fixture", data=data,
        captured_length=len(data), original_length=len(data), link_type=1,
    )


def produce(*frames):
    emitted = []
    handler = build_handler(emitted.append)
    for item in frames:
        handler(item)
    return emitted


@pytest.mark.parametrize("family", [4, 6])
def test_real_pipeline_sends_only_bounded_mdns_response_metadata(family):
    emitted = produce(frame(family=family, response=True))
    assert len(emitted) == 1
    msg = emitted[0]
    assert msg["type"] == "mdns"
    assert msg["role"] == "response"
    assert msg["ip_version"] == family
    assert msg["advertisement_count"] == 1
    assert msg["advertisements"] == [{
        "service_type": "_demo._tcp.local",
        "instance": "Node._demo._tcp.local",
        "ttl": 120,
    }]
    assert "payload" not in msg and "txt" not in msg
    assert len(json.dumps(msg)) < MAX_LINE


def test_query_with_known_answer_is_not_treated_as_advertisement():
    emitted = produce(frame(response=False))
    assert len(emitted) == 1
    assert emitted[0]["role"] == "query"
    assert emitted[0]["advertisement_count"] == 0
    assert emitted[0]["advertisements"] == []


def test_malformed_mdns_candidate_does_not_abort_other_observations():
    messages = produce(frame(broken=True), frame(response=True))
    assert messages[0] == {
        "type": "mdns_decode_error", "interface": "fixture",
    }
    assert messages[1]["role"] == "response"


def test_arp_sanitized_fixture_has_identical_graph_using_combined_handler():
    emitted = []
    handler = build_handler(emitted.append)
    frames = PcapReplayProvider().replay(
        DEFAULT_FIXTURE, handler, interface_label="fixture",
    )
    assert frames == 8
    assert all(msg["type"] == "binding" for msg in emitted)
    live = LiveARPGraphState(clock=lambda: 100)
    wire = [
        {"type": "session", "interface": "fixture",
         "protocols": ["arp", "mdns"]},
        *emitted, {"type": "completed"},
    ]
    consume_stream(io.StringIO("".join(json.dumps(x) + "\n" for x in wire)), live)
    result = live.snapshot()
    expected = build_arp_graph(DEFAULT_FIXTURE, interface_label="fixture")
    assert result["nodes"] == expected["nodes"]
    assert result["claims"] == expected["claims"]
    assert result["capture_status"] == "ended"
    assert result["mdns_evidence"]["messages"] == 0


def test_mixed_synthetic_mdns_stream_and_arp_state_are_independent():
    emitted = produce(frame(family=4, response=False), frame(family=6, response=True))
    state = LiveARPGraphState(clock=lambda: 110)
    wire = [
        {"type": "session", "interface": "fixture",
         "protocols": ["arp", "mdns"]},
        *emitted, {"type": "completed"},
    ]
    consume_stream(io.StringIO("".join(json.dumps(x) + "\n" for x in wire)), state)
    result = state.snapshot()
    mdns = result["mdns_evidence"]
    assert mdns["messages"] == 2
    assert mdns["queries"] == 1
    assert mdns["responses"] == 1
    assert mdns["ipv4"] == 1 and mdns["ipv6"] == 1
    assert mdns["ptr_advertisements"] == 1
    assert mdns["fresh_instances"] == 1
    assert len(mdns["services"]) == 1
    assert result["nodes"] == [] and result["claims"] == []


def test_zero_ttl_ptr_is_never_reported_fresh():
    emitted = produce(frame(response=True, ttl=0))
    state = LiveARPGraphState(clock=lambda: 100)
    state.ingest({"type": "session", "interface": "fixture",
                  "protocols": ["arp", "mdns"]})
    for event in emitted:
        state.ingest(event)
    assert state.snapshot()["mdns_evidence"]["fresh_instances"] == 0


def test_message_normalizer_never_returns_query_side_ads():
    observation = MDNSEventPipeline().process(frame(response=False))
    assert observation is not None
    ads = project_dnssd_advertisements(observation)
    assert ads == ()
    msg = mdns_message(observation, ads)
    assert msg["role"] == "query"
    assert msg["advertisements"] == []
    assert MAX_ADS_PER_MESSAGE <= 6
