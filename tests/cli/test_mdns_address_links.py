"""Same-response PTR -> SRV -> A/AAAA live evidence, without identity inference."""

from copy import deepcopy
from decimal import Decimal
from ipaddress import IPv6Address
import json

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.cli.network_live_stream import build_handler, mdns_message
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.views.mdns_services import project_dnssd_advertisements
from novxis.views.mdns_arp_crossref import cross_reference_mdns_arp
from novxis.web.live_state import LiveARPGraphState, MAX_LINE
from novxis.web.mdns_live import LiveMDNSState

SERVICE = b"\x05_demo\x04_tcp\x05local\x00"
INSTANCE = b"\x04Node\x05_demo\x04_tcp\x05local\x00"
HOST = b"\x04host\x05local\x00"
IP4 = "192.0.2.25"
IP6 = "2001:db8::25"


def _rr(name, kind, data, *, ttl):
    return (
        name + kind.to_bytes(2, "big") + b"\x00\x01"
        + ttl.to_bytes(4, "big")
        + len(data).to_bytes(2, "big") + data
    )


def _frame(*, with_srv=True, with_addresses=True, ttl=300):
    # The DNS question starts at byte 12 and anchors the SRV target's
    # legal backwards compression pointer (0xc00c -> "host.local").
    question = HOST + b"\x00\x01\x00\x01"
    answers = [_rr(SERVICE, 12, INSTANCE, ttl=ttl)]
    extra = []
    if with_srv:
        extra.append(_rr(
            INSTANCE, 33, bytes(4) + (4070).to_bytes(2, "big")
            + b"\xc0\x0c", ttl=120,
        ))
        if with_addresses:
            extra.append(_rr(HOST, 1, bytes((192, 0, 2, 25)), ttl=30))
            extra.append(_rr(
                HOST, 28, IPv6Address(IP6).packed, ttl=60,
            ))
    dns = (
        b"\x00\x00\x84\x00\x00\x01"
        + len(answers).to_bytes(2, "big")
        + b"\x00\x00" + len(extra).to_bytes(2, "big")
        + question + b"".join(answers + extra)
    )
    udp = (
        b"\x14\xe9\x14\xe9" + (len(dns) + 8).to_bytes(2, "big")
        + b"\x00\x01" + dns
    )
    ipv4 = (
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x01\x00\x00\xff\x11\x00\x00"
        + bytes((192, 0, 2, 26, 224, 0, 0, 251)) + udp
    )
    packet = bytes.fromhex("01005e0000fb0266778899aa0800") + ipv4
    return CapturedFrame(
        timestamp=Decimal("100"), interface="en0", data=packet,
        captured_length=len(packet), original_length=len(packet), link_type=1,
    )


def _message(**options):
    observed = MDNSEventPipeline().process(_frame(**options))
    assert observed is not None
    ads = project_dnssd_advertisements(observed)
    assert len(ads) == 1
    return mdns_message(observed, ads)


def _state(now=lambda: 100):
    state = LiveARPGraphState(clock=now)
    state.ingest({
        "type": "session", "interface": "en0",
        "protocols": ["arp", "mdns"],
    })
    return state


def test_real_wire_pipeline_projects_srvs_and_both_address_families():
    events = []
    build_handler(events.append)(_frame())
    assert len(events) == 1
    event = events[0]
    assert event["role"] == "response"
    assert event["advertisement_count"] == 1
    assert not event["relationships_omitted"]
    (service,) = event["advertisements"]
    assert service["instance"] == "Node._demo._tcp.local"
    assert service["ttl"] == 300
    assert service["targets"] == [{
        "target": "host.local", "port": 4070, "ttl": 120,
        "addresses": [
            {"family": 4, "address": IP4, "ttl": 30},
            {"family": 6, "address": IP6, "ttl": 60},
        ],
    }]
    assert len(json.dumps(event)) < MAX_LINE
    assert "payload" not in json.dumps(event)
    assert "txt" not in json.dumps(event).lower()


def test_same_response_missing_srv_never_invents_target():
    event = _message(with_srv=False)
    assert event["advertisements"][0]["targets"] == []


def test_srv_without_same_response_addresses_is_accurately_unresolved():
    event = _message(with_addresses=False)
    assert event["advertisements"][0]["targets"][0]["addresses"] == []


def test_independent_ptr_srv_and_address_ttls_update_without_packets():
    now = [100]
    state = _state(lambda: now[0])
    state.ingest(_message())
    first = state.snapshot()
    service = first["mdns_evidence"]["services"][0]
    target = service["targets"][0]
    assert service["fresh"]
    assert target["fresh"] and target["path_fresh"]
    assert all(rr["fresh"] and rr["path_fresh"] for rr in target["addresses"])
    revision = first["revision"]
    graph_revision = first["graph_revision"]
    now[0] = 131
    next_snap = state.snapshot()
    target = next_snap["mdns_evidence"]["services"][0]["targets"][0]
    assert target["fresh"]
    assert not target["addresses"][0]["fresh"]
    assert not target["addresses"][0]["path_fresh"]
    assert target["addresses"][1]["fresh"]
    assert next_snap["revision"] > revision
    assert next_snap["graph_revision"] == graph_revision
    now[0] = 221
    expired = state.snapshot()["mdns_evidence"]["services"][0]
    assert expired["fresh"]
    assert not expired["targets"][0]["fresh"]
    assert not expired["targets"][0]["path_fresh"]
    assert all(not rr["path_fresh"] for rr in expired["targets"][0]["addresses"])


def test_exact_interface_arp_match_is_navigation_not_graph_edge():
    state = _state()
    state.ingest(_message())
    state.ingest({
        "type": "binding", "interface": "en0",
        "hardware_type": 1, "protocol_type": 0x0800,
        "protocol_hex": "c0000219", "hardware_hex": "020000000019",
        "first_seen": "100", "last_seen": "100", "observation_count": 1,
    })
    snap = state.snapshot()
    target = snap["mdns_evidence"]["services"][0]["targets"][0]
    ipv4, ipv6 = target["addresses"]
    assert "arp_node_id" in ipv4
    assert ipv4["arp_node_id"] in {node["id"] for node in snap["nodes"]}
    assert ipv4["arp_cross_reference"] == "independent_same_interface_ipv4_address"
    assert "arp_node_id" not in ipv6
    assert len(snap["claims"]) == 1
    assert all(claim["kind"] == "arp_sender" for claim in snap["claims"])


def test_other_interface_or_different_ipv4_address_never_links():
    snapshot = {
        "interface": "en0",
        "services": [{
            "targets": [{
                "addresses": [{"family": 4, "address": IP4}],
            }],
        }],
    }
    other_interface = [{
        "id": "foreign", "kind": "protocol", "interface": "en5",
        "hardware_type": 1, "protocol_type": 0x0800,
        "address_hex": "c0000219",
    }]
    assert "arp_node_id" not in (
        cross_reference_mdns_arp(snapshot, other_interface)
        ["services"][0]["targets"][0]["addresses"][0]
    )
    other_address = [{**other_interface[0], "interface": "en0",
                      "address_hex": "c000021a"}]
    assert "arp_node_id" not in (
        cross_reference_mdns_arp(snapshot, other_address)
        ["services"][0]["targets"][0]["addresses"][0]
    )


@pytest.mark.parametrize("bad", [
    {"target": "host.local\n"},
    {"port": True},
    {"port": 65536},
    {"ttl": -1},
    {"addresses": [{"address": IP4, "family": 6, "ttl": 30}]},
    {"addresses": [{"address": "192.0.2.999", "family": 4, "ttl": 30}]},
    {"addresses": [{"address": IP4, "family": 4, "ttl": True}]},
    {"addresses": [{"address": IP4, "family": 4, "ttl": 30}] * 4},
])
def test_untrusted_target_fields_are_atomic(bad):
    state = LiveMDNSState()
    valid = _message()
    broken = deepcopy(valid)
    broken["advertisements"][0]["targets"][0].update(bad)
    before, _ = state.snapshot(Decimal("100"))
    with pytest.raises(ValueError):
        state.observe(broken, "en0")
    after, _ = state.snapshot(Decimal("100"))
    assert after == before


def test_query_with_known_answer_still_does_not_claim_srv_or_address():
    # Existing query fixtures exercise mDNS known-answer sections.
    from novxis.web.mdns_live import LiveMDNSState
    summary = LiveMDNSState()
    message = _message()
    message["role"] = "query"
    with pytest.raises(ValueError):
        summary.observe(message, "en0")


def test_latest_ptr_response_without_srv_clears_prior_target_claims():
    summary = LiveMDNSState()
    full = _message()
    summary.observe(full, "en0")
    next_event = _message(with_srv=False)
    next_event["observed_at"] = "101"
    summary.observe(next_event, "en0")
    snap, _ = summary.snapshot(Decimal("101"))
    assert snap["services"][0]["observations"] == 2
    assert snap["services"][0]["targets"] == []
