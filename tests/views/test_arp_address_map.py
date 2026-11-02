"""Evidence-only ARP address graph projection tests."""

from dataclasses import FrozenInstanceError
from decimal import Decimal

import pytest

from novxis.presentation.arp_address_map_console import format_arp_address_map
from novxis.state.arp import ARPBinding
from novxis.views.arp_address_map import project_arp_address_map


def _binding(
    *, interface="en0", ip=b"\xc0\x00\x02\x0a",
    mac=b"\x02\x00\x00\x00\x00\x0a",
    hardware_type=1, protocol_type=0x0800,
    first="100", last="104", count=2,
):
    return ARPBinding(
        interface=interface, hardware_type=hardware_type,
        protocol_type=protocol_type, protocol_address=ip,
        hardware_address=mac, first_seen=Decimal(first),
        last_seen=Decimal(last), observation_count=count,
    )


def test_empty_map_has_no_invented_nodes():
    snapshot = project_arp_address_map(())
    assert snapshot.nodes == ()
    assert snapshot.claims == ()
    assert "no usable ARP sender claims" in format_arp_address_map(snapshot)


def test_sender_binding_has_typed_nodes_and_original_metadata():
    binding = _binding()
    snapshot = project_arp_address_map([binding])
    assert len(snapshot.nodes) == 2
    assert {node.kind for node in snapshot.nodes} == {"protocol", "hardware"}
    assert len(snapshot.claims) == 1
    claim = snapshot.claims[0]
    nodes = {node.key: node for node in snapshot.nodes}
    assert nodes[claim.protocol_node].address == binding.protocol_address
    assert nodes[claim.hardware_node].address == binding.hardware_address
    assert claim.first_seen == Decimal("100")
    assert claim.last_seen == Decimal("104")
    assert claim.observation_count == 2
    assert claim.evidence_kind == "arp_sender"
    with pytest.raises(FrozenInstanceError):
        claim.last_seen = Decimal("999")


def test_shared_hardware_address_can_have_multiple_protocol_claims():
    snapshot = project_arp_address_map([
        _binding(ip=b"\xc0\x00\x02\x0a"),
        _binding(ip=b"\xc0\x00\x02\x0b"),
    ])
    assert len(snapshot.nodes) == 3
    assert len(snapshot.claims) == 2
    assert snapshot.claims[0].hardware_node == snapshot.claims[1].hardware_node


def test_identical_addresses_are_not_joined_across_interfaces():
    snapshot = project_arp_address_map([
        _binding(interface="en0"), _binding(interface="en5"),
    ])
    assert len(snapshot.nodes) == 4
    assert len(snapshot.claims) == 2
    assert snapshot.claims[0].protocol_node != snapshot.claims[1].protocol_node
    assert snapshot.claims[0].hardware_node != snapshot.claims[1].hardware_node


def test_arp_hardware_and_protocol_types_remain_distinct():
    snapshot = project_arp_address_map([
        _binding(hardware_type=1),
        _binding(hardware_type=2),
        _binding(protocol_type=0x1234),
    ])
    assert len(snapshot.nodes) == 6


def test_projection_and_console_are_order_independent():
    bindings = [
        _binding(interface="en5", ip=b"\xc0\x00\x02\x14"),
        _binding(interface="en0", ip=b"\xc0\x00\x02\x0a"),
    ]
    first = project_arp_address_map(bindings)
    assert first == project_arp_address_map(reversed(bindings))
    output = format_arp_address_map(first)
    assert "192.0.2.10" in output
    assert "192.0.2.20" in output
    assert "Evidence only" in output


def test_conflicting_synthetic_claims_are_not_silently_collapsed():
    snapshot = project_arp_address_map([
        _binding(mac=b"\x02\x00\x00\x00\x00\x0a"),
        _binding(mac=b"\x02\x00\x00\x00\x00\x0b"),
    ])
    assert len(snapshot.nodes) == 3
    assert len(snapshot.claims) == 2
    assert snapshot.claims[0].protocol_node == snapshot.claims[1].protocol_node
    assert snapshot.claims[0].hardware_node != snapshot.claims[1].hardware_node
    # Actual NetworkState keeps the latest sender binding for an address.
