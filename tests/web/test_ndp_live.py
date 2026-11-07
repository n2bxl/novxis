"""Live NDP pipe, strict receiver, and exact-scope AAAA evidence navigation."""

from copy import deepcopy
from decimal import Decimal
from ipaddress import IPv6Address
import json

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.cli.network_live_stream import build_handler
from novxis.web.live_state import LiveARPGraphState, MAX_LINE
from novxis.web.ndp_live import LiveNDPState
from novxis.views.mdns_ndp_crossref import cross_reference_mdns_ndp

SOURCE = "fe80::10"
TARGET = "2001:db8::20"
MAC = "020000000010"


def _checksum(src, dst, payload):
    pseudo = src + dst + len(payload).to_bytes(4, "big") + b"\x00\x00\x00\x3a"
    raw = pseudo + payload
    if len(raw) & 1:
        raw += b"\x00"
    total = sum(int.from_bytes(raw[i:i+2], "big")
                for i in range(0, len(raw), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def wire_frame(*, kind=136, option=True, timestamp="100", interface="en0"):
    source, destination = (
        IPv6Address(SOURCE).packed, IPv6Address("fe80::30").packed
    )
    target = IPv6Address(TARGET).packed
    options = (bytes((2 if kind == 136 else 1, 1))
               + bytes.fromhex(MAC)) if option else b""
    payload = bytes((kind, 0)) + bytes(2) + bytes(4) + target + options
    check = _checksum(source, destination, payload)
    payload = payload[:2] + check.to_bytes(2, "big") + payload[4:]
    ip = (bytes.fromhex("60000000") + len(payload).to_bytes(2, "big")
          + bytes((58, 255)) + source + destination + payload)
    packet = bytes.fromhex("3333000000010200000000cc86dd") + ip
    return CapturedFrame(
        timestamp=Decimal(timestamp), interface=interface,
        data=packet, captured_length=len(packet), original_length=len(packet),
        link_type=1,
    )


def event(*, kind="na", claim=True, source=SOURCE, target=TARGET,
          iface="en0", at="100", mac=MAC):
    return {
        "type": "ndp", "interface": iface, "observed_at": at,
        "message_type": kind, "source_ipv6": source, "target_ipv6": target,
        "frame_source_hex": "0200000000cc",
        "claim_kind": (
            "ns_source_slla" if kind == "ns" else "na_target_tlla"
        ) if claim else None,
        "claim_ipv6": (
            source if kind == "ns" else target
        ) if claim else None,
        "claim_mac_hex": mac if claim else None,
        "unlinked_reason": None if claim else (
            "ns_missing_slla" if kind == "ns" else "na_missing_tlla"
        ),
        "dad": False,
    }


def state(*, ndp=True):
    obj = LiveARPGraphState(clock=lambda: 101)
    obj.ingest({
        "type": "session", "interface": "en0",
        "protocols": ["arp", "mdns", "ndp"] if ndp else ["arp", "mdns"],
    })
    return obj


def service(*, address=TARGET, interface="en0"):
    return {
        "type": "mdns", "interface": interface, "ip_version": 6,
        "role": "response", "observed_at": "100",
        "advertisement_count": 1,
        "advertisements": [{
            "service_type": "_demo._tcp.local",
            "instance": "Demo._demo._tcp.local", "ttl": 300,
            "targets": [{
                "target": "host.local", "port": 4000, "ttl": 100,
                "addresses": [{"address": address, "family": 6, "ttl": 70}],
            }],
        }],
    }


def _aaaa(snapshot):
    return snapshot["mdns_evidence"]["services"][0]["targets"][0]["addresses"][0]


def test_capture_helper_exports_single_bounded_ndp_metadata_not_packet():
    out = []
    helper = build_handler(out.append)
    helper(wire_frame())
    assert len(out) == 1
    message = out[0]
    assert message == event()
    assert len(json.dumps(message)) < MAX_LINE
    assert not any(key in message for key in ("payload", "options", "data"))
    assert message["frame_source_hex"] != message["claim_mac_hex"]


def test_capture_helper_retains_unlinked_na_without_fabricating_target_mac():
    out = []
    build_handler(out.append)(wire_frame(option=False))
    assert len(out) == 1
    item = out[0]
    assert item["claim_ipv6"] is None
    assert item["claim_mac_hex"] is None
    assert item["unlinked_reason"] == "na_missing_tlla"


def test_live_aaaa_address_matches_independent_option_backed_na():
    obj = state()
    obj.ingest(service())
    assert "ndp_address" not in _aaaa(obj.snapshot())
    graph_rev = obj.snapshot()["graph_revision"]
    obj.ingest(event())
    snap = obj.snapshot()
    assert _aaaa(snap)["ndp_address"] == TARGET
    assert _aaaa(snap)["ndp_mac_variant_count"] == 1
    assert snap["ndp_evidence"]["claims"][0]["kind"] == "na_target_tlla"
    assert snap["graph_revision"] == graph_rev
    assert not snap["nodes"] and not snap["claims"]


def test_ns_slla_associates_source_not_neighbor_solicitation_target():
    obj = state()
    obj.ingest(service(address=TARGET))
    obj.ingest(event(kind="ns"))
    assert "ndp_address" not in _aaaa(obj.snapshot())
    assert obj.snapshot()["ndp_evidence"]["claims"][0]["address"] == SOURCE

    obj.ingest(service(address=SOURCE))
    assert _aaaa(obj.snapshot())["ndp_address"] == SOURCE


def test_na_without_tlla_and_dad_do_not_create_ipv6_navigation():
    obj = state()
    obj.ingest(service())
    obj.ingest(event(claim=False))
    dad = event(
        kind="ns", claim=False, source="::", target=TARGET,
    )
    dad["unlinked_reason"] = "dad_tentative"
    dad["dad"] = True
    obj.ingest(dad)
    snap = obj.snapshot()
    assert "ndp_address" not in _aaaa(snap)
    assert snap["ndp_evidence"]["dad"] == 1
    assert snap["ndp_evidence"]["retained_unlinked"] == 2
    assert snap["ndp_evidence"]["retained_claims"] == 0


def test_same_ipv6_claim_from_other_interface_does_not_cross_reference():
    mdns = {
        "interface": "en0",
        "services": [{
            "targets": [{"addresses": [{"family": 6, "address": TARGET}]}]
        }],
    }
    ndp = {
        "interface": "en5",
        "claims": [{"interface": "en5", "kind": "na_target_tlla",
                    "address": TARGET, "mac": MAC}],
    }
    output = cross_reference_mdns_ndp(mdns, ndp)
    assert output is mdns
    assert "ndp_address" not in output["services"][0]["targets"][0]["addresses"][0]


def test_different_llas_stay_separate_and_ambiguity_is_visible():
    obj = state()
    obj.ingest(service())
    obj.ingest(event())
    obj.ingest(event(at="101", mac="020000000011"))
    snap = obj.snapshot()
    assert snap["ndp_evidence"]["multiple_lla_addresses"] == 1
    assert len(snap["ndp_evidence"]["claims"]) == 2
    assert _aaaa(snap)["ndp_mac_variant_count"] == 2


def test_old_sessions_offline_and_arp_graph_remain_unmodified():
    legacy = state(ndp=False)
    with pytest.raises(ValueError, match="authorized capture"):
        legacy.ingest(event())
    assert "ndp_evidence" not in legacy.snapshot()
    assert legacy.snapshot()["source"]["capture_name"] == "Live ARP + mDNS"
    assert legacy.snapshot()["graph_revision"] == 0
    old = LiveARPGraphState()
    old.ingest({"type": "session", "interface": "en0"})
    assert "ndp_evidence" not in old.snapshot()


@pytest.mark.parametrize("patch", [
    {"interface": "en5"},
    {"observed_at": "NaN"},
    {"observed_at": -1},
    {"observed_at": "1e999"},
    {"source_ipv6": "fe80::0010"},
    {"claim_ipv6": SOURCE},
    {"claim_kind": "ns_source_slla"},
    {"claim_kind": []},
    {"claim_mac_hex": "000000000000"},
    {"claim_mac_hex": "01005e000001"},
    {"claim_mac_hex": "xx0000000010"},
    {"frame_source_hex": "gg0000000000"},
    {"unlinked_reason": "na_missing_tlla"},
    {"dad": True},
])
def test_untrusted_ndp_validation_is_atomic(patch):
    obj = state()
    before = deepcopy(obj.snapshot()["ndp_evidence"])
    with pytest.raises((ValueError, TypeError)):
        obj.ingest({**event(), **patch})
    assert obj.snapshot()["ndp_evidence"] == before


def test_nonstrict_crossref_never_fuses_ipv4_or_invents_graph_nodes():
    obj = state()
    obj.ingest(service(address=TARGET))
    obj.ingest(event())
    snap = obj.snapshot()
    assert not snap["nodes"] and not snap["claims"]
    assert _aaaa(snap)["ndp_cross_reference"] == (
        "independent_same_interface_ipv6_option_claim"
    )
    assert len(snap["ndp_evidence"]["claims"]) == 1


def test_independent_ndp_cap_and_decode_error_reporting():
    n = LiveNDPState(max_claims=1, max_unlinked=1)
    n.observe(event(), "en0")
    n.observe(event(mac="020000000011", at="101"), "en0")
    n.observe(event(claim=False, at="102"), "en0")
    n.observe(event(claim=False, target="2001:db8::21", at="103"), "en0")
    n.decode_error()
    snap = n.snapshot("en0")
    assert snap["messages"] == 4
    assert snap["omitted_claims"] == 1
    assert snap["omitted_unlinked"] == 1
    assert snap["truncated"] and snap["decode_errors"] == 1


def test_repeated_and_out_of_order_records_preserve_seen_bounds():
    n = LiveNDPState()
    n.observe(event(at="102"), "en0")
    n.observe(event(at="100"), "en0")
    snap = n.snapshot("en0")
    (claim,) = snap["claims"]
    assert claim["first_seen"] == "100"
    assert claim["last_seen"] == "102"
    assert claim["observations"] == 2
