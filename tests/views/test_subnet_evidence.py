"""Scoped IPv4 subnet comparisons: configuration and ARP remain separate facts."""

from decimal import Decimal

import pytest

from novxis.state.arp import ARPBinding
from novxis.views.arp_address_map import project_arp_address_map
from novxis.views.subnet_evidence import project_subnet_evidence


def binding(address: str, *, interface: str = "en0",
            protocol_type: int = 0x0800, hw: int = 10) -> ARPBinding:
    from ipaddress import IPv4Address
    payload = IPv4Address(address).packed
    return ARPBinding(
        interface=interface, hardware_type=1,
        protocol_type=protocol_type, protocol_address=payload,
        hardware_address=bytes([2, 0, 0, 0, 0, hw]),
        first_seen=Decimal("100.1"), last_seen=Decimal("105.2"),
        observation_count=2,
    )


def context(*, interface: str = "en0", prefixes=None,
            gateway: str = "192.0.2.1",
            route_interface: str = "en0") -> dict:
    return {
        "schema_version": 1,
        "origin": "local-os",
        "interface": interface,
        "status": "reported",
        "observed_at": "2026-11-02T20:00:00+00:00",
        "ipv4_addresses": prefixes if prefixes is not None else [
            {"address": "192.0.2.34", "prefix_length": 24,
             "network": "192.0.2.0/24"},
        ],
        "default_route": {
            "gateway": gateway,
            "interface": route_interface,
            "scope": "os-selected-ipv4-default",
        },
    }


def test_reported_prefix_contains_observed_ipv4_senders_not_devices():
    graph = project_arp_address_map((
        binding("192.0.2.34"),
        binding("192.0.2.1", hw=11),
        binding("198.51.100.10", hw=12),
    ))
    original = graph
    lens = project_subnet_evidence(graph, context(), capture_interface="en0")

    assert lens["schema_version"] == 1
    assert lens["origin"] == "derived-comparison"
    assert lens["source_types"] == [
        "local-os-configured-prefix", "arp-sender-observation"
    ]
    assert lens["capture_interface"] == "en0"
    assert lens["observed_ipv4_address_count"] == 3
    assert lens["reported_prefix_count"] == 1
    group = lens["configured_prefixes"][0]
    assert group["network"] == "192.0.2.0/24"
    assert group["configured_address"] == "192.0.2.34"
    assert group["observed_address_count"] == 2
    assert [x["address"] for x in group["matching_observed_ipv4"]] == [
        "192.0.2.1", "192.0.2.34",
    ]
    assert [x["address"] for x in lens["outside_reported_prefixes"]] == [
        "198.51.100.10"
    ]
    # Graph remains the exact same immutable semantic nodes and claims.
    assert graph == original
    assert len(graph.nodes) == 6
    assert len(graph.claims) == 3
    assert all(x["node_id"].startswith("arp:protocol:") for x in (
        group["matching_observed_ipv4"] + lens["outside_reported_prefixes"]
    ))


def test_cross_reference_requires_route_interface_and_observed_sender():
    graph = project_arp_address_map((binding("192.0.2.1"),))
    lens = project_subnet_evidence(graph, context(), capture_interface="en0")
    match = lens["gateway_address_cross_reference"]
    assert match["address"] == "192.0.2.1"
    assert match["relationship"] == "os-route-address-matches-arp-sender"
    assert match["route_interface"] == "en0"
    assert match["node_id"] in {node.key for node in graph.nodes}
    assert project_subnet_evidence(
        graph, context(route_interface="en5"), capture_interface="en0"
    )["gateway_address_cross_reference"] is None
    assert project_subnet_evidence(
        graph, context(gateway="192.0.2.2"), capture_interface="en0"
    )["gateway_address_cross_reference"] is None


def test_scope_is_capture_interface_and_ipv4_protocol_only():
    graph = project_arp_address_map((
        binding("192.0.2.1", interface="en0", hw=10),
        binding("192.0.2.2", interface="en5", hw=11),
        binding("192.0.2.3", interface="en0",
                protocol_type=0x86DD, hw=12),
    ))
    lens = project_subnet_evidence(graph, context(), capture_interface="en0")
    assert lens["observed_ipv4_address_count"] == 1
    assert [x["address"] for x in lens["configured_prefixes"][0][
        "matching_observed_ipv4"
    ]] == ["192.0.2.1"]


def test_multiple_and_overlapping_prefixes_do_not_invent_identity():
    prefixes = [
        {"address": "192.0.2.40", "prefix_length": 24,
         "network": "192.0.2.0/24"},
        {"address": "192.0.2.50", "prefix_length": 25,
         "network": "192.0.2.0/25"},
    ]
    graph = project_arp_address_map((
        binding("192.0.2.100"), binding("192.0.2.200", hw=11),
    ))
    lens = project_subnet_evidence(
        graph, context(prefixes=prefixes), capture_interface="en0"
    )
    assert lens["reported_prefix_count"] == 2
    counts = {
        entry["network"]: entry["observed_address_count"]
        for entry in lens["configured_prefixes"]
    }
    assert counts == {"192.0.2.0/24": 2, "192.0.2.0/25": 1}
    assert lens["observed_ipv4_address_count"] == 2
    assert lens["outside_reported_prefixes"] == []


@pytest.mark.parametrize("invalid", [
    None,
    {},
    {"origin": "arp-inferred", "schema_version": 1, "interface": "en0"},
    {"origin": "local-os", "schema_version": 2, "interface": "en0"},
    {"origin": "local-os", "schema_version": 1, "interface": "en5"},
])
def test_missing_untrusted_or_mismatched_host_context_is_not_a_subnet(invalid):
    graph = project_arp_address_map((binding("192.0.2.10"),))
    assert project_subnet_evidence(
        graph, invalid, capture_interface="en0"
    ) is None


@pytest.mark.parametrize("bad", [
    {"address": "192.0.2.34", "prefix_length": 24, "network": "192.0.3.0/24"},
    {"address": "192.0.2.34", "prefix_length": True,
     "network": "192.0.2.0/24"},
    {"address": "192.0.2.34", "prefix_length": 33,
     "network": "192.0.2.0/24"},
    {"address": "192.0.2.34", "prefix_length": 24,
     "network": "192.0.2.1/24"},
    {"address": "invalid", "prefix_length": 24,
     "network": "192.0.2.0/24"},
])
def test_invalid_reported_prefix_never_creates_a_group(bad):
    graph = project_arp_address_map((binding("192.0.2.10"),))
    lens = project_subnet_evidence(
        graph, context(prefixes=[bad]), capture_interface="en0"
    )
    assert lens["reported_prefix_count"] == 0
    assert lens["configured_prefixes"] == []
    assert lens["outside_reported_prefixes"] == []
    assert len(lens["unclassified_without_prefix"]) == 1


def test_no_configured_prefix_does_not_claim_off_prefix_or_full_inventory():
    graph = project_arp_address_map((binding("198.51.100.10"),))
    lens = project_subnet_evidence(
        graph, context(prefixes=[]), capture_interface="en0"
    )
    assert lens["reported_prefix_count"] == 0
    assert lens["observed_ipv4_address_count"] == 1
    assert lens["outside_reported_prefixes"] == []
    assert len(lens["unclassified_without_prefix"]) == 1
    assert "not evidence" in lens["limitations"]


def test_duplicate_os_prefixes_are_deduplicated():
    configured = {
        "address": "192.0.2.34", "prefix_length": 24,
        "network": "192.0.2.0/24",
    }
    graph = project_arp_address_map((binding("192.0.2.10"),))
    lens = project_subnet_evidence(
        graph,
        context(prefixes=[configured, configured]),
        capture_interface="en0",
    )
    assert lens["reported_prefix_count"] == 1
