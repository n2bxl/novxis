"""Phase 1N-L Stage 1: deterministic IPv4/IPv6/MAC evidence projection."""

from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from typing import cast

import pytest

from novxis.pipeline.ndp import NeighborDiscoveryObserved
from novxis.state.arp import ARPBinding
from novxis.state.ndp import NDAddressClaim, NDUnlinkedObservation
from novxis.views.unified_address_graph import (
    UnifiedAddressGraphSnapshot,
    project_unified_address_graph,
)

MAC_A = bytes.fromhex("020000000025")
MAC_B = bytes.fromhex("020000000026")
SCOPE = "session-1"


def arp(
    ip="192.0.2.25", mac=MAC_A, *, interface="en0",
    hardware_type=1, protocol_type=0x0800,
    first="100", last="120", count=3,
):
    return ARPBinding(
        interface=interface, hardware_type=hardware_type,
        protocol_type=protocol_type, protocol_address=IPv4Address(ip).packed,
        hardware_address=mac, first_seen=Decimal(first),
        last_seen=Decimal(last), observation_count=count,
    )


def ndp(
    ip="2001:db8::25", mac=MAC_A, *, interface="en0",
    kind="ns_source_slla", first="105", last="130", count=2,
):
    # Raw NDP observations remain opaque to the graph projection.
    # Stage 2 already validates and aggregates these typed records.
    original = cast(NeighborDiscoveryObserved, object())
    return NDAddressClaim(
        interface=interface, ipv6_address=IPv6Address(ip).packed,
        link_layer_address=mac, kind=kind,
        first_seen=Decimal(first), last_seen=Decimal(last),
        observation_count=count, latest_observation=original,
    )


def project(arps=(), ndps=(), *, scope=SCOPE):
    return project_unified_address_graph(
        arps, ndps, capture_scope=scope,
    )


def test_empty_projection_is_immutable_and_adds_no_network_objects():
    snapshot = project()
    assert isinstance(snapshot, UnifiedAddressGraphSnapshot)
    assert snapshot.nodes == ()
    assert snapshot.edges == ()
    assert snapshot.skipped_unsupported_arp_bindings == 0
    assert snapshot.capture_scope == SCOPE
    with pytest.raises(FrozenInstanceError):
        snapshot.capture_scope = "another"


def test_one_ipv4_and_ipv6_share_exactly_one_scoped_hardware_node():
    snapshot = project([arp()], [ndp()])
    nodes = {node.key: node for node in snapshot.nodes}
    assert len(snapshot.nodes) == 3
    assert len(snapshot.edges) == 2
    assert sorted(node.kind for node in snapshot.nodes) == [
        "hardware", "ipv4", "ipv6",
    ]
    (v4, v6) = sorted(snapshot.edges, key=lambda e: e.evidence_kind)
    assert v4.evidence_kind == "arp_sender"
    assert v6.evidence_kind == "ndp_ns_source_slla"
    assert v4.hardware_node == v6.hardware_node
    assert v4.protocol_node != v6.protocol_node
    assert nodes[v4.hardware_node].address == MAC_A
    assert nodes[v4.protocol_node].address == IPv4Address("192.0.2.25").packed
    assert nodes[v6.protocol_node].address == IPv6Address("2001:db8::25").packed
    assert {edge.capture_scope for edge in snapshot.edges} == {SCOPE}


def test_multiple_ipv6_addresses_keep_distinct_nodes_and_typed_edges():
    snapshot = project(
        [arp()],
        [ndp(ip="2001:db8::25"), ndp(ip="2001:db8::26", kind="na_target_tlla")],
    )
    assert len(snapshot.nodes) == 4
    assert len(snapshot.edges) == 3
    assert len({edge.hardware_node for edge in snapshot.edges}) == 1
    assert len({edge.protocol_node for edge in snapshot.edges}) == 3
    assert {edge.evidence_kind for edge in snapshot.edges} == {
        "arp_sender", "ndp_ns_source_slla", "ndp_na_target_tlla",
    }


def test_two_ndp_kinds_for_same_ip_and_mac_retain_two_distinct_claims():
    snapshot = project([], [
        ndp(kind="ns_source_slla"),
        ndp(kind="na_target_tlla", count=9, first="110", last="140"),
    ])
    assert len(snapshot.nodes) == 2
    assert len(snapshot.edges) == 2
    assert len({edge.protocol_node for edge in snapshot.edges}) == 1
    assert len({edge.hardware_node for edge in snapshot.edges}) == 1
    assert len({edge.key for edge in snapshot.edges}) == 2
    assert {edge.observation_count for edge in snapshot.edges} == {2, 9}


def test_contradictory_ipv6_link_layer_options_do_not_collapse():
    snapshot = project([], [ndp(mac=MAC_A), ndp(mac=MAC_B)])
    assert len(snapshot.nodes) == 3
    assert len(snapshot.edges) == 2
    assert snapshot.edges[0].protocol_node == snapshot.edges[1].protocol_node
    assert snapshot.edges[0].hardware_node != snapshot.edges[1].hardware_node
    assert {node.address for node in snapshot.nodes if node.kind == "hardware"} == {
        MAC_A, MAC_B,
    }


def test_same_mac_across_interfaces_remains_separate_even_in_one_capture_scope():
    snapshot = project(
        [arp(interface="en0"), arp(interface="en5")],
        [ndp(interface="en0"), ndp(interface="en5")],
    )
    hardware = [n for n in snapshot.nodes if n.kind == "hardware"]
    assert len(hardware) == 2
    assert len({n.key for n in hardware}) == 2
    assert {n.interface for n in hardware} == {"en0", "en5"}
    assert len(snapshot.nodes) == 6
    assert len(snapshot.edges) == 4
    for edge in snapshot.edges:
        match = next(n for n in hardware if n.key == edge.hardware_node)
        assert edge.interface == match.interface


def test_identical_observations_in_independent_capture_scopes_do_not_merge():
    first = project([arp()], [ndp()], scope="capture-A")
    second = project([arp()], [ndp()], scope="capture-B")
    assert not (
        {n.key for n in first.nodes} & {n.key for n in second.nodes}
    )
    assert not (
        {e.key for e in first.edges} & {e.key for e in second.edges}
    )


def test_length_prefixed_scope_and_interface_identifiers_are_unambiguous():
    first = project([arp(interface="c")], scope="ab:c")
    second = project([arp(interface="b:c")], scope="a")
    third = project([arp(interface="c")], scope="ab")
    assert {n.key for n in first.nodes}.isdisjoint(
        {n.key for n in second.nodes} | {n.key for n in third.nodes}
    )


def test_unicode_scope_and_interface_length_prefixes_count_utf8_bytes():
    snapshot = project([arp(interface="én0")], scope="café")
    assert all("caf" in node.key for node in snapshot.nodes)
    assert all("én0" in node.key for node in snapshot.nodes)


def test_projection_is_order_independent_and_input_is_not_mutated():
    arps = [arp(ip="192.0.2.25"), arp(ip="192.0.2.26", mac=MAC_B)]
    ndps = [ndp(ip="2001:db8::25"), ndp(ip="2001:db8::26", mac=MAC_B)]
    baseline = project(arps, ndps)
    assert baseline == project(reversed(arps), reversed(ndps))
    assert arps[0].first_seen == Decimal("100")
    assert ndps[0].observation_count == 2
    assert tuple(node.key for node in baseline.nodes) == tuple(sorted(
        node.key for node in baseline.nodes
    ))
    assert tuple(edge.key for edge in baseline.edges) == tuple(sorted(
        edge.key for edge in baseline.edges
    ))


def test_metadata_retains_original_timestamps_counts_and_aggregated_record_refs():
    binding = arp(first="100.125", last="105.5", count=15)
    claim = ndp(first="101.75", last="107.25", count=8)
    edges = {e.evidence_kind: e for e in project([binding], [claim]).edges}
    assert edges["arp_sender"].first_seen == Decimal("100.125")
    assert edges["arp_sender"].last_seen == Decimal("105.5")
    assert edges["arp_sender"].observation_count == 15
    assert edges["ndp_ns_source_slla"].first_seen == Decimal("101.75")
    assert edges["ndp_ns_source_slla"].last_seen == Decimal("107.25")
    assert edges["ndp_ns_source_slla"].observation_count == 8
    assert edges["arp_sender"].source_record_key != (
        edges["ndp_ns_source_slla"].source_record_key
    )
    assert all("source-record" in edge.source_record_key for edge in edges.values())
    assert all("packet" not in edge.source_record_key for edge in edges.values())


def test_duplicate_identical_input_is_idempotent_not_counted_twice():
    binding, claim = arp(), ndp()
    assert project([binding, binding], [claim, claim]) == project(
        [binding], [claim],
    )


@pytest.mark.parametrize("replacement", [
    {"last_seen": Decimal("150")},
    {"observation_count": 4},
    {"first_seen": Decimal("80")},
])
def test_inconsistent_duplicate_source_record_is_rejected(replacement):
    first = ndp()
    altered = replace(first, **replacement)
    with pytest.raises(ValueError, match="inconsistent duplicate"):
        project([], [first, altered])


@pytest.mark.parametrize("kind", [
    "ns_source_slla",
    "na_target_tlla",
])
def test_ndp_source_and_target_are_separate_provenance_kinds(kind):
    (edge,) = project([], [ndp(kind=kind)]).edges
    assert edge.evidence_kind == (
        "ndp_ns_source_slla" if kind == "ns_source_slla"
        else "ndp_na_target_tlla"
    )


def test_unlinked_ndp_is_not_a_supported_claim_input():
    # The Stage 2 state owns unlinked observations; projection consumes
    # only its .claims collection, never DAD or NA-without-TLLA evidence.
    unlinked = NDUnlinkedObservation(
        interface="en0",
        source_address=IPv6Address("fe80::10").packed,
        target_address=IPv6Address("2001:db8::25").packed,
        reason="na_missing_tlla", first_seen=Decimal("100"),
        last_seen=Decimal("100"), observation_count=1,
        latest_observation=cast(NeighborDiscoveryObserved, object()),
    )
    with pytest.raises(TypeError, match="option-backed NDAddressClaim"):
        project([], [unlinked])


def test_empty_ndp_claim_collection_never_invents_ip_to_mac_edges():
    # Stage 2 excludes DAD and unlinked NA observations from .claims.
    snapshot = project([arp()], [])
    assert len(snapshot.nodes) == 2
    assert len(snapshot.edges) == 1
    assert snapshot.edges[0].evidence_kind == "arp_sender"
    assert not any(node.kind == "ipv6" for node in snapshot.nodes)


@pytest.mark.parametrize("mac", [
    bytes(6),
    bytes.fromhex("01005e000001"),
    bytes.fromhex("ffffffffffff"),
    bytes.fromhex("02000000"),
])
def test_unusable_or_non_ethernet_arp_address_is_explicitly_skipped(mac):
    result = project([arp(mac=mac)], [])
    assert result.nodes == ()
    assert result.edges == ()
    assert result.skipped_unsupported_arp_bindings == 1


@pytest.mark.parametrize("binding", [
    arp(hardware_type=6),
    arp(protocol_type=0x86DD),
    replace(arp(), protocol_address=bytes(6)),
    replace(arp(), protocol_address=bytes(4)),
    arp(ip="224.0.0.1"),
    arp(ip="0.0.0.0"),
    arp(ip="255.255.255.255"),
])
def test_non_ethernet_or_unusable_ipv4_arp_record_is_not_unified(binding):
    snap = project([arp()], [])
    result = project([binding], [])
    assert result.skipped_unsupported_arp_bindings == 1
    assert result.nodes == ()
    assert snap.skipped_unsupported_arp_bindings == 0


@pytest.mark.parametrize("address", [
    IPv6Address("::").packed,
    IPv6Address("ff02::1").packed,
    bytes(15),
])
def test_unusable_ipv6_claims_fail_closed(address):
    bad = replace(ndp(), ipv6_address=address)
    with pytest.raises(ValueError, match="invalid option-backed"):
        project([], [bad])


@pytest.mark.parametrize("mac", [
    bytes(6),
    bytes.fromhex("01005e000001"),
    bytes(5),
])
def test_unusable_ndp_link_layer_option_fails_closed(mac):
    with pytest.raises(ValueError, match="invalid option-backed"):
        project([], [ndp(mac=mac)])


def test_unsupported_ndp_kind_is_not_silently_promoted_to_edge():
    with pytest.raises(ValueError, match="unsupported NDP"):
        project([], [replace(ndp(), kind="dad_tentative")])


@pytest.mark.parametrize("scope", ["", "\n", "\t", "x" * 129, None, 17])
def test_missing_invalid_or_too_large_capture_scope_rejected(scope):
    with pytest.raises(ValueError, match="capture_scope"):
        project([arp()], [ndp()], scope=scope)


@pytest.mark.parametrize("interface", ["", "\n", "x" * 129])
def test_invalid_interface_scoping_is_rejected(interface):
    with pytest.raises(ValueError, match="interface"):
        project([arp(interface=interface)], [])
    with pytest.raises(ValueError, match="interface"):
        project([], [ndp(interface=interface)])


@pytest.mark.parametrize("first,last,count", [
    ("NaN", "100", 1),
    ("-1", "100", 1),
    ("101", "100", 1),
    ("100", "Infinity", 1),
    ("100", "110", 0),
    ("100", "110", True),
])
def test_invalid_ndp_observation_metadata_fails_closed(first, last, count):
    with pytest.raises(ValueError, match="timestamps or observation count"):
        project([], [ndp(first=first, last=last, count=count)])


def test_invalid_arp_observation_metadata_fails_closed():
    with pytest.raises(ValueError, match="timestamps"):
        project([arp(first="101", last="100")], [])


def test_wrong_input_model_types_are_rejected():
    with pytest.raises(TypeError, match="ARPBinding"):
        project([object()], [])
    with pytest.raises(TypeError, match="NDAddressClaim"):
        project([], [object()])


def test_node_and_edge_instances_have_no_layout_or_liveness_fields():
    snap = project([arp()], [ndp()])
    (node,) = [n for n in snap.nodes if n.kind == "hardware"]
    (edge,) = [e for e in snap.edges if e.evidence_kind == "arp_sender"]
    with pytest.raises(FrozenInstanceError):
        node.address = MAC_B
    with pytest.raises(FrozenInstanceError):
        edge.observation_count = 999
    assert not hasattr(node, "position")
    assert not hasattr(edge, "reachable")
    assert not hasattr(edge, "ttl")
    assert not hasattr(edge, "is_device")
