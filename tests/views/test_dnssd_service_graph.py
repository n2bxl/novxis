"""Phase 1N-M Stage 1: bounded, evidence-first DNS-SD graph projection."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address

import pytest

from novxis.state.arp import ARPBinding
from novxis.state.ndp import NDAddressClaim
from novxis.views.dnssd_service_graph import (
    DNSSDAddressRecord, DNSSDEndpointEdge, DNSSDServiceGraphSnapshot,
    DNSSDServiceNode, project_dnssd_service_graph,
)
from novxis.views.unified_address_graph import (
    project_unified_address_graph,
)
from novxis.web.mdns_live import LiveMDNSState

SCOPE = "synthetic-session"
IFACE = "en0"
MAC_A = bytes.fromhex("020000000020")
MAC_B = bytes.fromhex("020000000021")


def address_graph(*, second_mac=False, other_interface=False, scope=SCOPE):
    arps = [ARPBinding(
        interface=IFACE, hardware_type=1, protocol_type=0x0800,
        protocol_address=IPv4Address("192.0.2.20").packed,
        hardware_address=MAC_A, first_seen=Decimal("90"),
        last_seen=Decimal("100"), observation_count=2,
    )]
    if other_interface:
        arps.append(replace(arps[0], interface="en5"))
    ndps = [NDAddressClaim(
        interface=IFACE,
        ipv6_address=IPv6Address("2001:db8::20").packed,
        link_layer_address=MAC_A, kind="ns_source_slla",
        first_seen=Decimal("93"), last_seen=Decimal("104"),
        observation_count=3, latest_observation=None,
    )]
    if second_mac:
        ndps.append(replace(ndps[0], link_layer_address=MAC_B))
    return project_unified_address_graph(arps, ndps, capture_scope=scope)


def fresh(at, ttl, as_of):
    at, as_of = Decimal(str(at)), Decimal(str(as_of))
    return ttl > 0 and at <= as_of < at + ttl


def address(ip="192.0.2.20", *, at="102", ttl=120, as_of="110",
            source="same-mdns-response"):
    return {
        "address": ip, "family": 6 if ":" in ip else 4,
        "ttl": ttl, "observed_at": str(at),
        "fresh": fresh(at, ttl, as_of),
        "path_fresh": fresh("100", 120, as_of) and
        fresh("101", 120, as_of) and fresh(at, ttl, as_of),
        "source": source,
    }


def target(*, hostname="printer.local", port=631, at="101", ttl=120,
           as_of="110", addresses=None, source="same-mdns-response"):
    if addresses is None:
        addresses = [address(as_of=as_of)]
    return {
        "target": hostname, "port": port, "observed_at": str(at),
        "ttl_seconds": ttl, "fresh": fresh(at, ttl, as_of),
        "path_fresh": fresh("100", 120, as_of) and fresh(at, ttl, as_of),
        "source": source, "addresses": addresses,
    }


def instance(*, name="Laser._ipp._tcp.local", service_type="_ipp._tcp.local",
             as_of="110", ttl=120, targets=None):
    if targets is None:
        targets = [target(as_of=as_of)]
    return {
        "instance": name, "service_type": service_type,
        "last_seen": "100", "ttl_seconds": ttl,
        "observations": 2, "fresh": fresh("100", ttl, as_of),
        "targets": targets,
    }


def evidence(*, services=None, as_of="110", interface=IFACE,
             truncated=False, omitted=0):
    if services is None:
        services = [instance(as_of=as_of)]
    return {
        "schema_version": 1, "origin": "mdns-observation",
        "interface": interface, "as_of": str(as_of),
        "services": services, "retained_instances": len(services),
        "truncated": truncated, "omitted_advertisements": omitted,
    }


def project(mdns=None, address_snapshot=None, *, interface=IFACE, scope=SCOPE):
    if mdns is None:
        mdns = evidence()
    if address_snapshot is None:
        address_snapshot = address_graph()
    return project_dnssd_service_graph(
        address_snapshot, mdns, interface=interface, capture_scope=scope,
    )


def test_ipv4_ipv6_and_service_only_address_share_the_expected_identity():
    item = instance(targets=[target(addresses=[
        address("192.0.2.20"),
        address("2001:db8::20"),
        address("192.0.2.55"),
    ])])
    snap = project(evidence(services=[item]))
    assert isinstance(snap, DNSSDServiceGraphSnapshot)
    assert len(snap.nodes) == 5  # MAC, 2 known IPs, new IP, service
    assert len(snap.edges) == 5  # original ARP/NDP plus 3 DNS-SD paths
    assert len(snap.service_nodes) == 1
    assert len(snap.endpoint_edges) == 3
    assert {n.kind for n in snap.nodes} == {
        "hardware", "ipv4", "ipv6", "dnssd_service",
    }
    shared = {n.key for n in address_graph().nodes}
    assert shared.issubset({n.key for n in snap.nodes})
    additional = [n for n in snap.nodes if n.kind == "ipv4"
                  and n.address == IPv4Address("192.0.2.55").packed]
    assert len(additional) == 1
    assert additional[0].key in {e.protocol_node for e in snap.endpoint_edges}
    assert all(e.protocol_node != additional[0].key
               for e in snap.edges if not isinstance(e, DNSSDEndpointEdge))
    assert all(e.service_node == snap.service_nodes[0].key
               for e in snap.endpoint_edges)


def test_explicit_ptr_srv_a_aaaa_evidence_is_immutable_and_inspectable():
    item = instance(targets=[target(addresses=[
        address("192.0.2.20"), address("2001:db8::20"),
    ])])
    snap = project(evidence(services=[item]))
    first = snap.endpoint_edges[0]
    assert first.kind == "dnssd_advertised_endpoint"
    assert first.ptr.service_type == "_ipp._tcp.local"
    assert first.ptr.instance == "Laser._ipp._tcp.local"
    assert first.ptr.observations == 2
    assert first.ptr.observed_at == Decimal("100")
    assert first.ptr.ttl_seconds == 120
    assert first.srv.owner_name == first.ptr.instance
    assert first.srv.target_name == "printer.local"
    assert first.srv.port == 631
    assert first.srv.observed_at == Decimal("101")
    assert first.srv.source == "same-mdns-response"
    assert first.address.owner_name == first.srv.target_name
    assert first.address.observed_at == Decimal("102")
    assert first.address.source == "same-mdns-response"
    assert first.path_fresh
    assert first.ptr.key != first.srv.key != first.address.key
    assert "dnssd-record" in first.ptr.key
    assert isinstance(first.address, DNSSDAddressRecord)
    assert {e.address.kind for e in snap.endpoint_edges} == {"a", "aaaa"}
    with pytest.raises(FrozenInstanceError):
        first.path_fresh = False
    with pytest.raises(FrozenInstanceError):
        snap.capture_scope = "altered"


def test_ptr_only_creates_standalone_advertised_service_not_endpoint():
    snap = project(evidence(services=[instance(targets=[])]),
                   address_snapshot=project_unified_address_graph(
                       (), (), capture_scope=SCOPE,
                   ))
    assert len(snap.service_nodes) == len(snap.nodes) == 1
    assert len(snap.edges) == 0
    assert snap.service_nodes[0].ptr.fresh


def test_srv_without_a_aaaa_is_not_an_endpoint():
    snap = project(evidence(services=[instance(
        targets=[target(addresses=[])],
    )]))
    assert len(snap.service_nodes) == 1
    assert len(snap.endpoint_edges) == 0


def test_no_ptr_means_no_service_node_or_endpoint_even_with_address_claims():
    baseline = address_graph()
    snap = project(evidence(services=[]), address_snapshot=baseline)
    assert len(snap.service_nodes) == len(snap.endpoint_edges) == 0
    assert set(snap.nodes) == set(baseline.nodes)
    assert set(snap.edges) == set(baseline.edges)


def test_one_service_can_have_multiple_ip_addresses_and_families():
    ads = [address("192.0.2.20"), address("2001:db8::20"),
           address("2001:db8::55")]
    snap = project(evidence(services=[instance(
        targets=[target(addresses=ads)],
    )]))
    assert len(snap.service_nodes) == 1
    assert len(snap.endpoint_edges) == 3
    assert len({e.protocol_node for e in snap.endpoint_edges}) == 3
    assert len({e.service_node for e in snap.endpoint_edges}) == 1


def test_two_services_can_advertise_one_address_without_claiming_owner():
    services = [
        instance(),
        instance(name="Web._http._tcp.local", service_type="_http._tcp.local",
                 targets=[target(port=8080)]),
    ]
    snap = project(evidence(services=services))
    assert len(snap.service_nodes) == 2
    assert len(snap.endpoint_edges) == 2
    assert len({e.protocol_node for e in snap.endpoint_edges}) == 1
    assert len({e.service_node for e in snap.endpoint_edges}) == 2


def test_parallel_srv_targets_and_ports_have_distinct_inspectable_edges():
    services = [instance(targets=[
        target(hostname="printer.local", port=631),
        target(hostname="other.local", port=8631),
    ])]
    snap = project(evidence(services=services))
    assert len(snap.endpoint_edges) == 2
    assert len({e.key for e in snap.endpoint_edges}) == 2
    assert len({e.protocol_node for e in snap.endpoint_edges}) == 1
    assert {e.srv.port for e in snap.endpoint_edges} == {631, 8631}


def test_duplicate_identical_target_claim_does_not_duplicate_edge():
    t = target()
    snap = project(evidence(services=[instance(targets=[t, deepcopy(t)])]))
    assert len(snap.endpoint_edges) == 1


def test_distinct_record_epochs_remain_separate_paths_for_same_ip():
    earlier = target(addresses=[address(at="102")])
    later = target(addresses=[address(at="103")])
    snap = project(evidence(services=[instance(targets=[earlier, later])]))
    assert len(snap.endpoint_edges) == 2
    assert len({e.address.key for e in snap.endpoint_edges}) == 2


@pytest.mark.parametrize(("as_of", "expected"), [
    ("109", True), ("110", False), ("111", False),
])
def test_exact_ptr_ttl_boundary_never_reports_active_service(as_of, expected):
    ptr_ttl = 10
    srv = target(as_of=as_of, addresses=[
        address(as_of=as_of),
    ])
    # This fixture deliberately varies the PTR TTL (normally 120 s).
    srv["addresses"][0]["path_fresh"] = (
        expected and srv["fresh"] and srv["addresses"][0]["fresh"]
    )
    snap = project(evidence(
        as_of=as_of,
        services=[instance(as_of=as_of, ttl=ptr_ttl, targets=[srv])],
    ))
    assert snap.service_nodes[0].ptr.fresh is expected
    assert snap.endpoint_edges[0].path_fresh is expected


@pytest.mark.parametrize(("srv_ttl", "addr_ttl", "expected"), [
    (8, 120, "srv"), (120, 8, "address"), (120, 120, None),
])
def test_component_freshness_preserved_independently(srv_ttl, addr_ttl, expected):
    at = "110"
    t = target(ttl=srv_ttl, as_of=at, addresses=[
        address(ttl=addr_ttl, as_of=at),
    ])
    # The bounded live snapshot computes path_fresh from all components.
    t["path_fresh"] = fresh("100", 120, at) and fresh("101", srv_ttl, at)
    t["addresses"][0]["path_fresh"] = (
        t["path_fresh"] and fresh("102", addr_ttl, at)
    )
    e = project(evidence(services=[instance(as_of=at, targets=[t])],
                         as_of=at)).endpoint_edges[0]
    assert e.ptr.fresh
    assert e.srv.fresh is (expected != "srv")
    assert e.address.fresh is (expected != "address")
    assert e.path_fresh is (expected is None)


def test_ttl_zero_retains_stale_record_evidence_not_active_endpoint():
    at = "110"
    a = address(ttl=0, as_of=at)
    t = target(as_of=at, addresses=[a])
    snap = project(evidence(services=[instance(targets=[t])]))
    assert len(snap.endpoint_edges) == 1
    assert not snap.endpoint_edges[0].path_fresh
    assert not snap.endpoint_edges[0].address.fresh


def test_cross_response_reconciliation_is_accepted_then_explicitly_retracted():
    state = LiveMDNSState()
    state.observe({
        "interface": IFACE, "ip_version": 4, "role": "response",
        "observed_at": "100", "advertisement_count": 1,
        "advertisements": [{
            "service_type": "_ipp._tcp.local",
            "instance": "Laser._ipp._tcp.local", "ttl": 120,
            "targets": [],
        }],
    }, IFACE)
    reconciled = {
        "interface": IFACE, "service_type": "_ipp._tcp.local",
        "instance": "Laser._ipp._tcp.local",
        "ptr_observed_at": "100", "as_of": "103",
        "relationships_omitted": False,
        "targets": [{
            "target": "printer.local", "port": 631, "ttl": 120,
            "observed_at": "101", "origin": "cross-mdns-response",
            "addresses": [{
                "address": "192.0.2.20", "family": 4, "ttl": 120,
                "observed_at": "102", "origin": "cross-mdns-response",
            }],
        }],
    }
    assert state.observe_reconciliation(reconciled, IFACE)
    observed, _ = state.snapshot(Decimal("105"))
    observed["interface"] = IFACE
    linked = project(observed)
    assert len(linked.endpoint_edges) == 1
    edge = linked.endpoint_edges[0]
    assert edge.srv.source == "cross-mdns-response"
    assert edge.address.source == "cross-mdns-response"
    assert edge.path_fresh
    assert state.clear_reconciliation({
        "interface": IFACE, "service_type": "_ipp._tcp.local",
        "instance": "Laser._ipp._tcp.local", "ptr_observed_at": "100",
        "as_of": "104",
    }, IFACE)
    after, _ = state.snapshot(Decimal("105"))
    after["interface"] = IFACE
    cleared = project(after)
    assert len(cleared.service_nodes) == 1
    assert len(cleared.endpoint_edges) == 0


def test_one_ip_claimed_by_two_macs_preserves_both_original_edges():
    baseline = address_graph(second_mac=True)
    snap = project(address_snapshot=baseline)
    address_edges = [e for e in snap.edges if not isinstance(e, DNSSDEndpointEdge)]
    assert set(address_edges) == set(baseline.edges)
    assert len(address_edges) == 3
    assert len(snap.endpoint_edges) == 1
    assert sum(n.kind == "hardware" for n in snap.nodes) == 2
    assert len({e.protocol_node for e in snap.endpoint_edges}) == 1


def test_same_address_different_capture_interfaces_never_fuse():
    baseline = address_graph(other_interface=True)
    snap = project(address_snapshot=baseline)
    assert all(n.interface == IFACE for n in snap.nodes)
    assert all(e.interface == IFACE for e in snap.edges)
    assert len(snap.endpoint_edges) == 1
    assert len([e for e in snap.edges if not isinstance(e, DNSSDEndpointEdge)]) == 2


def test_different_capture_scopes_never_share_service_or_address_ids():
    first = project()
    second = project(
        address_snapshot=address_graph(scope="other-session"),
        scope="other-session",
    )
    assert {n.key for n in first.nodes}.isdisjoint({n.key for n in second.nodes})
    assert {e.key for e in first.edges}.isdisjoint({e.key for e in second.edges})


@pytest.mark.parametrize("wrong", [
    {"interface": "en5"}, {"origin": "mdns-unverified"},
    {"schema_version": 2}, {"as_of": "NaN"}, {"truncated": None},
    {"omitted_advertisements": -1},
])
def test_invalid_or_unqualified_mdns_snapshot_is_rejected(wrong):
    payload = evidence()
    payload.update(wrong)
    with pytest.raises(ValueError):
        project(payload)


def test_capture_scope_mismatch_rejected_before_dns_merge():
    with pytest.raises(ValueError, match="capture scope mismatch"):
        project(address_snapshot=address_graph(scope="foreign"))


@pytest.mark.parametrize("mutation", [
    lambda d: d["services"][0].update({"last_seen": "-1"}),
    lambda d: d["services"][0].update({"ttl_seconds": True}),
    lambda d: d["services"][0].update({"fresh": False}),
    lambda d: d["services"][0]["targets"][0].update({"source": "unknown"}),
    lambda d: d["services"][0]["targets"][0].update({"path_fresh": False}),
    lambda d: d["services"][0]["targets"][0]["addresses"][0].update({
        "address": "192.0.2.999",
    }),
    lambda d: d["services"][0]["targets"][0]["addresses"][0].update({
        "family": 6,
    }),
    lambda d: d["services"][0]["targets"][0]["addresses"][0].update({
        "fresh": False,
    }),
])
def test_invalid_claim_or_inconsistent_ttl_metadata_is_rejected(mutation):
    payload = evidence()
    mutation(payload)
    with pytest.raises(ValueError):
        project(payload)


def test_unicast_only_endpoint_filter_retains_service_and_accounts_for_skips():
    ads = [address("0.0.0.0"), address("224.0.0.251"),
           address("192.0.2.20")]
    snap = project(evidence(services=[instance(targets=[
        target(addresses=ads),
    ])]))
    assert len(snap.endpoint_edges) == 1
    assert snap.skipped_unsupported_addresses == 2
    assert len(snap.service_nodes) == 1


def test_bounded_metadata_omissions_not_mistaken_for_full_inventory():
    snap = project(evidence(truncated=True, omitted=9))
    assert snap.source_truncated is True
    assert snap.omitted_advertisements == 9


def test_more_than_128_services_is_rejected_even_when_fresh():
    payload = evidence(services=[
        instance(name=f"Printer{i}._ipp._tcp.local", targets=[])
        for i in range(129)
    ])
    with pytest.raises(ValueError, match="unbounded PTR-backed services"):
        project(payload)


def test_deterministic_output_for_unordered_service_and_address_arrays():
    one = instance(targets=[target(addresses=[
        address("192.0.2.20"), address("2001:db8::20"),
    ])])
    two = instance(name="Web._http._tcp.local",
                   service_type="_http._tcp.local",
                   targets=[target(port=8080, addresses=[
                       address("192.0.2.66"), address("192.0.2.67"),
                   ])])
    a = evidence(services=[one, two])
    b = evidence(services=[deepcopy(two), deepcopy(one)])
    b["services"][0]["targets"][0]["addresses"].reverse()
    b["services"][1]["targets"][0]["addresses"].reverse()
    assert project(a) == project(b)


def test_input_snapshots_remain_unmodified_after_projection():
    payload = evidence()
    before = deepcopy(payload)
    base = address_graph()
    assert project(payload, address_snapshot=base)
    assert payload == before
    assert base == address_graph()


def test_case_insensitive_service_identity_preserves_display_spelling():
    standard = project()
    payload = evidence(services=[instance(
        name="LASER._IPP._TCP.LOCAL",
        service_type="_IPP._TCP.LOCAL",
    )])
    upper = project(payload)
    assert standard.service_nodes[0].key == upper.service_nodes[0].key
    assert upper.service_nodes[0].instance == "LASER._IPP._TCP.LOCAL"


def test_no_raw_packet_data_or_network_effects_are_required():
    from pathlib import Path

    module = (Path(__file__).parents[2] / "novxis" / "views" /
              "dnssd_service_graph.py").read_text(encoding="utf-8")
    assert "scapy" not in module
    assert "socket." not in module
    assert "subprocess" not in module
    assert "requests." not in module
    assert "raw_packet" not in module
