"""Phase 1N-L Stage 2: sanitized pipe -> read-only unified graph adapter.

All addresses are synthetic documentation fixtures. Neither an NDJSON
frame sender nor a DNS-SD advertisement becomes an IP-to-MAC edge.
"""

from copy import deepcopy
from decimal import Decimal
from ipaddress import IPv6Address
import io
import json
from threading import Thread
from urllib.request import urlopen

import pytest

from novxis.web.live_state import LiveARPGraphState, consume_stream
from novxis.web.server import create_server
from novxis.web.unified_live import project_live_unified_address_graph


def state(*, protocols=("arp", "mdns", "ndp"), max_bindings=256):
    obj = LiveARPGraphState(max_bindings=max_bindings, clock=lambda: 105)
    obj.ingest({
        "type": "session", "interface": "en0",
        "protocols": list(protocols),
    })
    return obj


def binding(*, address="c0000219", mac="020000000025",
            at="100", count=1, hardware_type=1, protocol_type=0x0800):
    return {
        "type": "binding", "interface": "en0",
        "hardware_type": hardware_type, "protocol_type": protocol_type,
        "protocol_hex": address, "hardware_hex": mac,
        "first_seen": at, "last_seen": at,
        "observation_count": count,
    }


def ndp(*, kind="na", source="fe80::10", target="2001:db8::25",
        mac="020000000025", at="101", claim=True):
    claimed_address = source if kind == "ns" else target
    return {
        "type": "ndp", "interface": "en0",
        "observed_at": at, "message_type": kind,
        "source_ipv6": source, "target_ipv6": target,
        "frame_source_hex": "0200000000cc",
        "claim_kind": (
            "ns_source_slla" if kind == "ns" else "na_target_tlla"
        ) if claim else None,
        "claim_ipv6": claimed_address if claim else None,
        "claim_mac_hex": mac if claim else None,
        "unlinked_reason": None if claim else (
            "ns_missing_slla" if kind == "ns" else "na_missing_tlla"
        ),
        "dad": False,
    }


def unified(obj):
    return obj.snapshot()["unified_address_graph"]


def test_live_opt_in_exposes_empty_bounded_unified_graph_but_no_new_old_graph_edges():
    obj = state()
    snap = obj.snapshot()
    graph = snap["unified_address_graph"]
    assert graph["schema_version"] == 1
    assert graph["origin"] == "passive-arp-ndp"
    assert graph["interface"] == "en0"
    assert len(graph["capture_scope"]) == 32
    assert graph["revision"] == 0
    assert graph["nodes"] == [] and graph["edges"] == []
    assert snap["nodes"] == [] and snap["claims"] == []
    assert snap["graph_revision"] == 0
    assert not graph["truncated"]


def test_ipv4_and_ipv6_claims_reuse_scoped_hardware_address_with_independent_edges():
    obj = state()
    obj.ingest(binding())
    obj.ingest(ndp())
    snap = obj.snapshot()
    graph = snap["unified_address_graph"]
    assert graph["revision"] == 2
    assert snap["graph_revision"] == 1
    assert snap["revision"] == 3
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    nodes = {n["id"]: n for n in graph["nodes"]}
    edges = {e["kind"]: e for e in graph["edges"]}
    assert set(edges) == {"arp_sender", "ndp_na_target_tlla"}
    assert edges["arp_sender"]["target"] == edges["ndp_na_target_tlla"]["target"]
    assert edges["arp_sender"]["source"] != edges["ndp_na_target_tlla"]["source"]
    assert nodes[edges["arp_sender"]["source"]]["display_address"] == "192.0.2.25"
    assert nodes[edges["ndp_na_target_tlla"]["source"]]["display_address"] == "2001:db8::25"
    assert nodes[edges["arp_sender"]["target"]]["display_address"] == "02:00:00:00:00:25"
    assert {n["capture_scope"] for n in graph["nodes"]} == {graph["capture_scope"]}
    assert {e["capture_scope"] for e in graph["edges"]} == {graph["capture_scope"]}
    assert len(snap["nodes"]) == 2 and len(snap["claims"]) == 1
    assert snap["ndp_evidence"]["retained_claims"] == 1


def test_ns_associates_source_only_and_na_associates_target_only():
    obj = state()
    obj.ingest(ndp(kind="ns"))
    obj.ingest(ndp(kind="na", at="103"))
    graph = unified(obj)
    assert len(graph["edges"]) == 2
    edges = {e["kind"]: e for e in graph["edges"]}
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert nodes[edges["ndp_ns_source_slla"]["source"]]["display_address"] == "fe80::10"
    assert nodes[edges["ndp_na_target_tlla"]["source"]]["display_address"] == "2001:db8::25"
    assert edges["ndp_ns_source_slla"]["target"] == edges["ndp_na_target_tlla"]["target"]
    assert all(n["address_hex"] != "0200000000cc" for n in graph["nodes"])


def test_same_address_same_mac_ns_and_na_stay_separate_typed_edges():
    obj = state()
    obj.ingest(ndp(kind="ns", source="2001:db8::25"))
    obj.ingest(ndp(kind="na"))
    graph = unified(obj)
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 2
    assert len({e["source"] for e in graph["edges"]}) == 1
    assert len({e["id"] for e in graph["edges"]}) == 2


def test_two_ipv6_addresses_can_share_one_hardware_address_without_fusing_ip_nodes():
    obj = state()
    obj.ingest(binding())
    obj.ingest(ndp(target="2001:db8::25"))
    obj.ingest(ndp(target="2001:db8::26", at="102"))
    graph = unified(obj)
    assert len(graph["nodes"]) == 4
    assert len(graph["edges"]) == 3
    assert len({e["target"] for e in graph["edges"]}) == 1
    assert len({e["source"] for e in graph["edges"]}) == 3


def test_contradictory_ipv6_macs_keep_both_address_claims():
    obj = state()
    obj.ingest(ndp())
    obj.ingest(ndp(mac="020000000026", at="102"))
    graph = unified(obj)
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    assert graph["edges"][0]["source"] == graph["edges"][1]["source"]
    assert graph["edges"][0]["target"] != graph["edges"][1]["target"]
    assert obj.snapshot()["ndp_evidence"]["multiple_lla_addresses"] == 1


def test_dad_and_missing_tlla_do_not_create_edges_or_increment_unified_graph_revision():
    obj = state()
    before = unified(obj)
    obj.ingest(ndp(claim=False))
    dad = ndp(kind="ns", source="::", claim=False, at="102")
    dad["dad"] = True
    dad["unlinked_reason"] = "dad_tentative"
    obj.ingest(dad)
    graph = unified(obj)
    assert graph["edges"] == []
    assert graph["nodes"] == []
    assert graph["revision"] == before["revision"] == 0
    snap = obj.snapshot()
    assert snap["ndp_evidence"]["retained_unlinked"] == 2
    assert snap["ndp_evidence"]["dad"] == 1
    assert snap["revision"] > 1
    assert snap["graph_revision"] == 0


def test_ndp_frame_sender_is_not_substituted_for_missing_target_tlla():
    obj = state()
    obj.ingest(binding(mac="0200000000cc"))
    obj.ingest(ndp(claim=False))
    graph = unified(obj)
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["kind"] == "arp_sender"
    assert not any(n["kind"] == "ipv6" for n in graph["nodes"])


def test_repeated_ndp_claim_keeps_temporal_bounds_and_counts():
    obj = state()
    obj.ingest(ndp(at="105"))
    obj.ingest(ndp(at="101"))
    (edge,) = unified(obj)["edges"]
    assert edge["first_seen"] == "101"
    assert edge["last_seen"] == "105"
    assert edge["observation_count"] == 2
    assert edge["source_record_key"].startswith("unified:v1:")
    assert "source-record" in edge["source_record_key"]


def test_changed_arp_binding_discards_old_ipv4_sender_edge_without_changing_ndp():
    obj = state()
    obj.ingest(binding())
    obj.ingest(ndp())
    obj.ingest(binding(mac="020000000026", at="103"))
    graph = unified(obj)
    nodes = {n["id"]: n for n in graph["nodes"]}
    arp_edges = [e for e in graph["edges"] if e["kind"] == "arp_sender"]
    ndp_edges = [e for e in graph["edges"] if e["kind"] == "ndp_na_target_tlla"]
    assert len(arp_edges) == len(ndp_edges) == 1
    assert nodes[arp_edges[0]["target"]]["address_hex"] == "020000000026"
    assert nodes[ndp_edges[0]["target"]]["address_hex"] == "020000000025"
    assert graph["revision"] == 3
    assert obj.snapshot()["graph_revision"] == 2


def test_combined_payload_does_not_change_existing_arp_graph_shape_or_claims():
    obj = state()
    obj.ingest(binding())
    result = obj.snapshot()
    assert {c["kind"] for c in result["claims"]} == {"arp_sender"}
    assert {n["kind"] for n in result["nodes"]} == {"protocol", "hardware"}
    assert result["schema_version"] == 1
    assert result["mode"] == "live-arp"
    assert result["graph_revision"] == 1
    assert result["unified_address_graph"]["revision"] == 1
    obj.ingest(ndp())
    changed = obj.snapshot()
    assert changed["nodes"] == result["nodes"]
    assert changed["claims"] == result["claims"]
    assert changed["graph_revision"] == result["graph_revision"]


@pytest.mark.parametrize("protocols", [("arp",), ("arp", "mdns")])
def test_legacy_sessions_do_not_gain_unified_graph_payload(protocols):
    obj = state(protocols=protocols)
    obj.ingest(binding())
    result = obj.snapshot()
    assert "unified_address_graph" not in result
    assert "ndp_evidence" not in result
    assert result["graph_revision"] == 1
    assert len(result["claims"]) == 1


def test_offline_sanitized_replay_has_no_unified_graph_key():
    from novxis.web.graph_data import DEFAULT_FIXTURE, build_arp_graph
    result = build_arp_graph(DEFAULT_FIXTURE)
    assert "unified_address_graph" not in result
    assert result["schema_version"] == 1
    assert len(result["claims"]) == 6


def test_capture_scope_is_stable_across_snapshots_but_not_across_sessions():
    first, second = state(), state()
    first.ingest(binding())
    second.ingest(binding())
    a, b = unified(first), unified(second)
    assert a["capture_scope"] != b["capture_scope"]
    assert a["capture_scope"] == unified(first)["capture_scope"]
    assert {x["id"] for x in a["nodes"]}.isdisjoint(
        {x["id"] for x in b["nodes"]}
    )


def test_rejected_wrong_interface_ndp_is_atomic_for_both_graphs():
    obj = state()
    obj.ingest(binding())
    before = deepcopy(obj.snapshot())
    with pytest.raises(ValueError, match="authorized capture"):
        obj.ingest({**ndp(), "interface": "en5"})
    after = obj.snapshot()
    assert after == before


def test_invalid_ndp_claim_does_not_mutate_unified_state():
    obj = state()
    baseline = obj.snapshot()
    with pytest.raises(ValueError, match="unusable NDP"):
        obj.ingest({**ndp(), "claim_mac_hex": "000000000000"})
    result = obj.snapshot()
    assert result["revision"] == baseline["revision"]
    assert result["unified_address_graph"] == baseline["unified_address_graph"]


def test_ndp_decode_error_updates_ndp_diagnostics_without_spurious_unified_edges():
    obj = state()
    obj.ingest({"type": "ndp_decode_error", "interface": "en0"})
    assert obj.snapshot()["ndp_evidence"]["decode_errors"] == 1
    assert unified(obj)["revision"] == 0
    assert not unified(obj)["edges"]


def test_unsupported_arp_data_is_skipped_but_original_arp_view_remains_available():
    obj = state()
    obj.ingest(binding(hardware_type=6))
    snap = obj.snapshot()
    assert len(snap["claims"]) == 1
    assert len(snap["nodes"]) == 2
    assert snap["unified_address_graph"]["nodes"] == []
    assert snap["unified_address_graph"]["edges"] == []
    assert snap["unified_address_graph"]["skipped_unsupported_arp_bindings"] == 1


def test_arp_capacity_flag_propagates_to_unified_graph_without_fabricating_missing_nodes():
    obj = state(max_bindings=1)
    obj.ingest(binding())
    obj.ingest(binding(address="c000021a", mac="020000000026"))
    snap = obj.snapshot()
    graph = snap["unified_address_graph"]
    assert graph["arp_bindings_truncated"]
    assert graph["truncated"]
    assert len(graph["edges"]) == 1
    assert len(snap["claims"]) == 1


def test_ndp_capacity_truncation_preserves_only_retained_claims():
    obj = state()
    for i in range(129):
        obj.ingest(ndp(target=str(IPv6Address(int(IPv6Address("2001:db8::")) + i + 1)),
                       at=str(101 + i)))
    snap = obj.snapshot()
    graph = snap["unified_address_graph"]
    assert snap["ndp_evidence"]["retained_claims"] == 128
    assert graph["omitted_ndp_claims"] == 1
    assert graph["truncated"] is True
    assert len(graph["edges"]) == 128
    assert len(graph["nodes"]) == 129


def test_schema_is_json_serializable_and_no_raw_packet_metadata_crosses_browser_boundary():
    obj = state()
    obj.ingest(binding())
    obj.ingest(ndp())
    graph = unified(obj)
    assert json.loads(json.dumps(graph)) == graph
    assert "payload" not in json.dumps(graph)
    assert "packet_bytes" not in json.dumps(graph)
    assert all(e["id"] != e["source_record_key"] for e in graph["edges"])
    assert all(node["kind"] in ("ipv4", "ipv6", "hardware")
               for node in graph["nodes"])


def test_snapshot_is_deterministic_without_new_source_events():
    obj = state()
    obj.ingest(binding())
    obj.ingest(ndp())
    assert unified(obj) == unified(obj)


def test_existing_local_http_endpoint_serves_additive_unified_payload():
    obj = state()
    obj.ingest(binding())
    obj.ingest(ndp())
    server = create_server(obj.snapshot, port=0)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/api/graph") as response:
            body = json.load(response)
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["Access-Control-Allow-Origin"] is None
        assert body["schema_version"] == 1
        assert len(body["claims"]) == 1
        assert len(body["unified_address_graph"]["edges"]) == 2
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_consume_ndjson_pipe_produces_graph_without_modifying_producer_contract():
    obj = LiveARPGraphState(clock=lambda: 105)
    records = [
        {"type": "session", "interface": "en0",
         "protocols": ["arp", "mdns", "ndp"]},
        binding(), ndp(), {"type": "completed"},
    ]
    lines = "".join(json.dumps(record) + "\n" for record in records)
    consume_stream(io.StringIO(lines), obj)
    snap = obj.snapshot()
    assert snap["capture_status"] == "ended"
    assert len(snap["unified_address_graph"]["edges"]) == 2
    assert len(snap["claims"]) == 1
    assert len(snap["ndp_evidence"]["claims"]) == 1


def test_direct_adapter_rejects_cross_interface_claim_snapshot():
    ndp_snapshot = {
        "origin": "ndp-observation", "interface": "en5",
        "claims": [], "omitted_claims": 0, "omitted_unlinked": 0,
    }
    with pytest.raises(ValueError, match="outside live capture"):
        project_live_unified_address_graph(
            [], ndp_snapshot, interface="en0",
            capture_scope="fixture-1", revision=0,
        )


def test_adapted_snapshot_has_only_source_record_references_not_fake_packet_ids():
    obj = state()
    obj.ingest(ndp())
    graph = unified(obj)
    (edge,) = graph["edges"]
    assert "source-record" in edge["source_record_key"]
    assert not any(key in edge for key in (
        "latest_observation", "captured_frame", "raw_packet", "payload",
    ))
