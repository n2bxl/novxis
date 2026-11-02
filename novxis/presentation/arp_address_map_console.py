"""Console adapter for immutable ARP observed-address map snapshots."""

from novxis.presentation.arp_state_console import (
    _format_hardware,
    _format_protocol,
)
from novxis.views.arp_address_map import ARPAddressMapSnapshot


def format_arp_address_map(snapshot: ARPAddressMapSnapshot) -> str:
    nodes = {node.key: node for node in snapshot.nodes}
    lines = [
        "Observed ARP address map (sender claims only)",
        f"  address nodes={len(snapshot.nodes)}; "
        f"sender claims={len(snapshot.claims)}",
    ]
    if not snapshot.claims:
        lines.append("  (no usable ARP sender claims observed)")
    for claim in snapshot.claims:
        protocol = nodes[claim.protocol_node]
        hardware = nodes[claim.hardware_node]
        lines.append(
            f"  {claim.interface}: "
            f"{_format_protocol(protocol.protocol_type, protocol.address)} "
            f"-> {_format_hardware(hardware.address)} "
            f"[ARP sender; observations={claim.observation_count}; "
            f"first={claim.first_seen}; last={claim.last_seen}]"
        )
    lines.append(
        "  Evidence only: not verified physical devices, links, "
        "subnet membership, or online status."
    )
    return "\n".join(lines)


def print_arp_address_map(snapshot: ARPAddressMapSnapshot) -> None:
    print(format_arp_address_map(snapshot))
