"""Phase 1N-M Stage 2: receiver-validated DNS-SD graph JSON and revisions.

All names/addresses below are synthetic documentation fixture values.
No raw capture, network request, or active discovery is required.
"""

from copy import deepcopy
from decimal import Decimal
from ipaddress import IPv4Address
import io
import json
from threading import Thread
from urllib.request import urlopen

import pytest

from novxis.web.live_state import LiveARPGraphState, consume_stream
from novxis.web.server import create_server
from novxis.web.dnssd_service_live import (
    build_live_dnssd_service_graph, serialize_dnssd_service_graph,
    service_graph_semantic_signature,
)


def session(*, protocols=("arp", "mdns", "ndp"), now=None):
    if now is None:
        now = [105]
    state = LiveARPGraphState(clock=lambda: now[0])
    state.ingest({
        "type": "session", "interface": "en0", "protocols": list(protocols),
    })
    return state, now


def binding(*, ip="192.0.2.20", mac="020000000020", count=1, at="100"):
    return {
        "type": "binding", "interface": "en0",
        "hardware_type": 1, "protocol_type": 0x0800,
        "protocol_hex": IPv4Address(ip).packed.hex(),
        "hardware_hex": mac,
        "first_seen": at, "last_seen": at, "observation_count": count,
    }


def ndp(*, ip="2001:db8::20", mac="020000000020", claim=True, at="101"):
    return {
        "type": "ndp", "interface": "en0", "observed_at": at,
        "message_type": "na", "source_ipv6": "fe80::1",
        "target_ipv6": ip, "frame_source_hex": "0200000000aa",
        "claim_kind": "na_target_tlla" if claim else None,
        "claim_ipv6": ip if claim else None,
        "claim_mac_hex": mac if claim else None,
        "unlinked_reason": None if claim else "na_missing_tlla",
        "dad": False,
    }


def mdns(*, ptr_ttl=120, srv_ttl=120, ip_ttl=120,
         addresses=None, at="100", name="Printer._ipp._tcp.local",
         targets=True, count=None, role="response"):
    if addresses is None:
        addresses = ["192.0.2.20", "2001:db8::20"]
    advertised = []
    if role == "response":
        advertised = [{
            "service_type": "_ipp._tcp.local",
            "instance": name, "ttl": ptr_ttl,
            "targets": ([{
                "target": "printer.local", "port": 631,
                "ttl": srv_ttl,
                "addresses": [{
                    "address": address,
                    "family": 6 if ":" in address else 4,
                    "ttl": ip_ttl,
                } for address in addresses],
            }] if targets else []),
        }]
    return {
        "type": "mdns", "interface": "en0",
        "ip_version": 4, "role": role, "observed_at": at,
        "advertisement_count": (
            len(advertised) if count is None else count
        ),
        "advertisements": advertised,
    }


def service_graph(state):
    return state.snapshot()["unified_service_graph"]


def test_empty_combined_session_has_versioned_empty_service_graph():
    state, _ = session()
    payload = state.snapshot()
    graph = payload["unified_service_graph"]
    assert graph["schema_version"] == 1
    assert graph["origin"] == "passive-arp-ndp-mdns"
    assert graph["interface"] == "en0"
    assert graph["revision"] == 0
    assert graph["nodes"] == graph["edges"] == []
    assert graph["as_of"] == "105"
    assert not graph["truncated"]
    assert len(graph["capture_scope"]) == 32
    assert graph["capture_scope"] == payload["unified_address_graph"]["capture_scope"]
    assert payload["nodes"] == payload["claims"] == []


@pytest.mark.parametrize("protocols", [
    ("arp",), ("arp", "mdns"),
])
def test_legacy_sessions_remain_without_unified_service_graph(protocols):
    state, _ = session(protocols=protocols)
    state.ingest(binding())
    if "mdns" in protocols:
        state.ingest(mdns())
    result = state.snapshot()
    assert "unified_service_graph" not in result
    assert "unified_address_graph" not in result
    assert result["graph_revision"] == 1
    assert len(result["claims"]) == 1
    assert ("mdns_evidence" in result) == ("mdns" in protocols)


def test_combined_advertisement_reuses_exact_ip_ids_and_mac_edges():
    state, _ = session()
    state.ingest(binding())
    state.ingest(ndp())
    state.ingest(mdns())
    payload = state.snapshot()
    graph = payload["unified_service_graph"]
    unified = payload["unified_address_graph"]
    assert graph["revision"] >= 1
    assert len(graph["nodes"]) == 4
    assert len(graph["edges"]) == 4
    original_nodes = {node["id"]: node for node in unified["nodes"]}
    original_edges = {edge["id"]: edge for edge in unified["edges"]}
    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = {edge["id"]: edge for edge in graph["edges"]}
    assert {k: nodes[k] for k in original_nodes} == original_nodes
    assert {k: edges[k] for k in original_edges} == original_edges
    services = [n for n in graph["nodes"] if n["kind"] == "dnssd_service"]
    assert len(services) == 1
    assert services[0]["instance"] == "Printer._ipp._tcp.local"
    advertised = [
        e for e in graph["edges"] if e["kind"] == "dnssd_advertised_endpoint"
    ]
    assert len(advertised) == 2
    assert {e["source"] for e in advertised} == {
        node["id"] for node in graph["nodes"] if node["kind"] in ("ipv4", "ipv6")
    }
    assert {e["target"] for e in advertised} == {services[0]["id"]}
    for edge in advertised:
        assert edge["capture_scope"] == graph["capture_scope"]
        assert edge["interface"] == "en0"
        assert edge["path_fresh"]
        assert edge["ptr"]["observation_count"] == 1
        assert edge["ptr"]["service_type"] == "_ipp._tcp.local"
        assert edge["ptr"]["source"] == "ptr-observation"
        assert edge["srv"]["target_name"] == "printer.local"
        assert edge["srv"]["port"] == 631
        assert edge["srv"]["source"] == "same-mdns-response"
        assert edge["address"]["source"] == "same-mdns-response"
        assert edge["ptr"]["ttl_seconds"] == 120
        assert edge["srv"]["ttl_seconds"] == 120
        assert edge["address"]["ttl_seconds"] == 120
        assert all(edge[key]["source_record_key"].startswith("unified:v1:")
                   for key in ("ptr", "srv", "address"))
    assert {e["address"]["kind"] for e in advertised} == {"a", "aaaa"}
    assert len(payload["nodes"]) == 2 and len(payload["claims"]) == 1
    assert payload["mdns_evidence"]["retained_instances"] == 1
    assert payload["graph_revision"] == 1
    assert payload["unified_address_graph"]["revision"] == 2


def test_advertisement_only_ip_is_independent_of_hardware_associations():
    state, _ = session()
    state.ingest(mdns(addresses=["192.0.2.88", "2001:db8::88"]))
    graph = service_graph(state)
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    assert {node["kind"] for node in graph["nodes"]} == {
        "ipv4", "ipv6", "dnssd_service",
    }
    assert all(e["kind"] == "dnssd_advertised_endpoint"
               for e in graph["edges"])
    assert all(e["kind"] != "hardware" for e in graph["nodes"])
    assert service_graph(state)["revision"] == graph["revision"]


def test_ptr_without_srv_is_standalone_service_node():
    state, _ = session()
    state.ingest(mdns(targets=False))
    graph = service_graph(state)
    assert [n["kind"] for n in graph["nodes"]] == ["dnssd_service"]
    assert graph["edges"] == []
    assert graph["nodes"][0]["ptr"]["fresh"]


def test_empty_mdns_query_does_not_advance_service_semantic_revision():
    state, _ = session()
    state.ingest(mdns())
    first = state.snapshot()
    state.ingest(mdns(role="query", at="102"))
    after = state.snapshot()
    assert after["revision"] > first["revision"]
    assert after["unified_service_graph"]["revision"] == (
        first["unified_service_graph"]["revision"]
    )
    assert after["unified_service_graph"]["nodes"] == (
        first["unified_service_graph"]["nodes"]
    )
    assert after["unified_service_graph"]["edges"] == (
        first["unified_service_graph"]["edges"]
    )


def test_new_ptr_epoch_and_count_increment_service_revision():
    state, now = session()
    state.ingest(mdns())
    first = service_graph(state)
    now[0] = 108
    state.ingest(mdns(at="108"))
    second = service_graph(state)
    assert second["revision"] == first["revision"] + 1
    service = next(n for n in second["nodes"] if n["kind"] == "dnssd_service")
    assert service["ptr"]["observation_count"] == 2
    assert service["ptr"]["observed_at"] == "108"
    endpoint = next(e for e in second["edges"]
                    if e["kind"] == "dnssd_advertised_endpoint")
    assert endpoint["ptr"]["observed_at"] == "108"


def test_ttl_expiration_changes_only_service_revision_when_no_packets_arrive():
    state, now = session()
    state.ingest(binding())
    state.ingest(mdns(ptr_ttl=10))
    first = state.snapshot()
    first_service = first["unified_service_graph"]
    assert all(e["path_fresh"] for e in first_service["edges"]
               if e["kind"] == "dnssd_advertised_endpoint")
    now[0] = 110
    second = state.snapshot()
    assert second["unified_service_graph"]["revision"] > first_service["revision"]
    advertised = [e for e in second["unified_service_graph"]["edges"]
                  if e["kind"] == "dnssd_advertised_endpoint"]
    assert len(advertised) == 2 and not any(e["path_fresh"] for e in advertised)
    assert not any(e["ptr"]["fresh"] for e in advertised)
    assert all(e["srv"]["fresh"] and e["address"]["fresh"]
               for e in advertised)
    assert second["graph_revision"] == first["graph_revision"]
    assert second["unified_address_graph"]["revision"] == (
        first["unified_address_graph"]["revision"]
    )
    assert second["unified_service_graph"]["nodes"][0]["kind"] in (
        "hardware", "ipv4", "ipv6", "dnssd_service",
    )
    third = state.snapshot()
    assert third["unified_service_graph"]["revision"] == (
        second["unified_service_graph"]["revision"]
    )


def test_unlinked_na_never_invents_mac_or_changes_service_nodes():
    state, _ = session()
    state.ingest(mdns())
    before = state.snapshot()
    state.ingest(ndp(claim=False))
    after = state.snapshot()
    assert after["unified_service_graph"]["nodes"] == (
        before["unified_service_graph"]["nodes"]
    )
    assert after["unified_service_graph"]["edges"] == (
        before["unified_service_graph"]["edges"]
    )
    assert after["unified_service_graph"]["revision"] == (
        before["unified_service_graph"]["revision"]
    )


def test_address_only_changes_advance_service_revision_but_not_ptr_data():
    state, _ = session()
    state.ingest(mdns())
    first = state.snapshot()
    state.ingest(binding())
    second = state.snapshot()
    assert second["unified_service_graph"]["revision"] > (
        first["unified_service_graph"]["revision"]
    )
    assert second["unified_service_graph"]["nodes"] != (
        first["unified_service_graph"]["nodes"]
    )
    assert (second["mdns_evidence"]["services"][0]["instance"] ==
            first["mdns_evidence"]["services"][0]["instance"])
    # The legacy Services sidebar separately gains an ARP jump link,
    # so its complete display payload correctly does change.
    assert len(second["unified_service_graph"]["edges"]) == 3


def test_explicit_cross_response_reconciliation_and_retraction():
    state, _ = session()
    state.ingest(mdns(targets=False))
    initial = state.snapshot()["unified_service_graph"]
    assert not initial["edges"]
    reconciliation = {
        "type": "mdns_reconciliation",
        "interface": "en0", "service_type": "_ipp._tcp.local",
        "instance": "Printer._ipp._tcp.local",
        "ptr_observed_at": "100", "as_of": "103",
        "relationships_omitted": False,
        "targets": [{
            "target": "printer.local", "port": 631,
            "ttl": 120, "observed_at": "101",
            "origin": "cross-mdns-response",
            "addresses": [{
                "address": "192.0.2.20", "family": 4, "ttl": 120,
                "observed_at": "102", "origin": "cross-mdns-response",
            }],
        }],
    }
    state.ingest(reconciliation)
    linked = service_graph(state)
    assert linked["revision"] > initial["revision"]
    assert len(linked["edges"]) == 1
    assert linked["edges"][0]["srv"]["source"] == "cross-mdns-response"
    assert linked["edges"][0]["address"]["source"] == "cross-mdns-response"
    state.ingest({
        "type": "mdns_reconciliation_clear",
        "interface": "en0", "service_type": "_ipp._tcp.local",
        "instance": "Printer._ipp._tcp.local",
        "ptr_observed_at": "100", "as_of": "104",
    })
    retracted = service_graph(state)
    assert retracted["edges"] == []
    assert len(retracted["nodes"]) == 1
    assert retracted["revision"] > linked["revision"]


def test_cross_interface_ingestion_rejection_retains_previous_service_snapshot():
    state, _ = session()
    state.ingest(mdns())
    before = state.snapshot()
    malformed = mdns()
    malformed["interface"] = "en5"
    with pytest.raises(ValueError, match="outside authorized capture"):
        state.ingest(malformed)
    after = state.snapshot()
    assert after["unified_service_graph"] == before["unified_service_graph"]


def test_separate_live_sessions_get_unique_scope_qualified_service_nodes():
    first, _ = session()
    second, _ = session()
    first.ingest(mdns())
    second.ingest(mdns())
    a, b = service_graph(first), service_graph(second)
    assert a["capture_scope"] != b["capture_scope"]
    assert {n["id"] for n in a["nodes"]}.isdisjoint({
        n["id"] for n in b["nodes"]
    })
    assert {e["id"] for e in a["edges"]}.isdisjoint({
        e["id"] for e in b["edges"]
    })


def test_omitted_mdns_claims_mark_service_graph_truncated_without_new_edges():
    state, _ = session()
    original = mdns(targets=False, count=4)
    state.ingest(original)
    result = state.snapshot()["unified_service_graph"]
    assert result["mdns_truncated"]
    assert result["omitted_mdns_advertisements"] == 3
    assert result["truncated"]
    assert result["edges"] == []


def test_receiver_rejects_bad_mdns_payload_before_service_graph_is_changed():
    state, _ = session()
    state.ingest(mdns())
    before = deepcopy(service_graph(state))
    broken = mdns()
    broken["advertisements"][0]["targets"][0]["addresses"][0]["family"] = 6
    with pytest.raises(ValueError, match="mismatched"):
        state.ingest(broken)
    assert service_graph(state) == before


def test_no_unchecked_v4_v6_inference_is_produced_by_separate_records():
    state, _ = session()
    state.ingest(mdns(targets=False))
    state.ingest(binding())
    graph = service_graph(state)
    assert not any(e["kind"] == "dnssd_advertised_endpoint"
                   for e in graph["edges"])
    assert any(e["kind"] == "arp_sender" for e in graph["edges"])


def test_pure_adapter_has_independent_signature_and_rejects_mismatched_inputs():
    state, _ = session()
    state.ingest(mdns())
    payload = state.snapshot()
    # Build directly from already validated receiver state, not HTTP.
    receiver = state._mdns.snapshot(Decimal("105"))[0]
    receiver["interface"] = "en0"
    ndp_state = payload["ndp_evidence"]
    address_state = tuple(state._bindings.values())
    snap = build_live_dnssd_service_graph(
        address_state, ndp_state, receiver, interface="en0",
        capture_scope=payload["unified_address_graph"]["capture_scope"],
    )
    signature = service_graph_semantic_signature(snap)
    assert signature == service_graph_semantic_signature(snap)
    assert snap.as_of == Decimal("105")
    with pytest.raises(ValueError, match="outside live capture interface"):
        build_live_dnssd_service_graph(
            address_state, ndp_state, receiver, interface="en5",
            capture_scope=snap.capture_scope,
        )
    with pytest.raises(TypeError):
        service_graph_semantic_signature(None)


@pytest.mark.parametrize(("revisions", "arp_flag", "omitted_claims"), [
    (-1, False, 0), (True, False, 0),
    (0, "no", 0), (0, False, -1),
])
def test_serializer_rejects_invalid_revision_and_omission_metadata(
    revisions, arp_flag, omitted_claims,
):
    state, _ = session()
    state.ingest(mdns())
    data = state.snapshot()
    evidence = state._mdns.snapshot(Decimal("105"))[0]
    evidence["interface"] = "en0"
    snap = build_live_dnssd_service_graph(
        tuple(state._bindings.values()), data["ndp_evidence"], evidence,
        interface="en0",
        capture_scope=data["unified_address_graph"]["capture_scope"],
    )
    with pytest.raises(ValueError):
        serialize_dnssd_service_graph(
            snap, revision=revisions, arp_truncated=arp_flag,
            omitted_ndp_claims=omitted_claims,
            omitted_ndp_unlinked=0,
        )


def test_existing_local_http_api_exposes_additive_service_graph():
    state, _ = session()
    state.ingest(binding())
    state.ingest(ndp())
    state.ingest(mdns())
    server = create_server(state.snapshot, port=0)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/api/graph") as response:
            body = json.load(response)
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["Access-Control-Allow-Origin"] is None
        assert body["schema_version"] == 1
        assert body["mode"] == "live-arp"
        assert len(body["claims"]) == 1
        assert len(body["unified_address_graph"]["edges"]) == 2
        assert len(body["unified_service_graph"]["edges"]) == 4
        assert body["unified_service_graph"]["origin"] == "passive-arp-ndp-mdns"
        assert body["unified_service_graph"]["interface"] == "en0"
        assert body["mdns_evidence"]["retained_instances"] == 1
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_existing_ndjson_pipe_integration_needs_no_new_event_types():
    state = LiveARPGraphState(clock=lambda: 105)
    records = [
        {"type": "session", "interface": "en0",
         "protocols": ["arp", "mdns", "ndp"]},
        binding(), ndp(), mdns(), {"type": "completed"},
    ]
    consume_stream(
        io.StringIO("".join(json.dumps(item) + "\n" for item in records)),
        state,
    )
    payload = state.snapshot()
    assert payload["capture_status"] == "ended"
    assert len(payload["claims"]) == 1
    assert len(payload["unified_address_graph"]["edges"]) == 2
    assert len(payload["unified_service_graph"]["edges"]) == 4
    assert len(payload["unified_service_graph"]["nodes"]) == 4
    assert json.loads(json.dumps(payload)) == payload


def test_live_adapter_does_not_import_packet_parsers_or_make_new_requests():
    from pathlib import Path

    app = (Path(__file__).parents[2] / "novxis" / "web" /
           "dnssd_service_live.py").read_text(encoding="utf-8")
    assert "scapy" not in app
    assert "socket." not in app
    assert "subprocess" not in app
    assert "urlopen" not in app
    assert "raw_packet" not in app
