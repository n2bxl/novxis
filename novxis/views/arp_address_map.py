"""Renderer-neutral graph of ARP sender address claims.

These are interface-scoped associations, not physical devices, network
cables, currently reachable hosts, or verified subnet membership.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

from novxis.state.arp import ARPBinding

ARPAddressKind = Literal["protocol", "hardware"]


@dataclass(frozen=True, slots=True)
class ARPAddressNode:
    """One observed address within its full ARP and interface scope."""

    key: str
    kind: ARPAddressKind
    interface: str
    hardware_type: int
    protocol_type: int
    address: bytes


@dataclass(frozen=True, slots=True)
class ARPSenderClaim:
    """Latest ARP sender claim with original observation metadata."""

    protocol_node: str
    hardware_node: str
    interface: str
    first_seen: Decimal
    last_seen: Decimal
    observation_count: int
    evidence_kind: Literal["arp_sender"] = "arp_sender"


@dataclass(frozen=True, slots=True)
class ARPAddressMapSnapshot:
    """Immutable and time-agnostic projection of latest ARP binding state."""

    nodes: tuple[ARPAddressNode, ...]
    claims: tuple[ARPSenderClaim, ...]


def _node_key(kind: ARPAddressKind, binding: ARPBinding, address: bytes) -> str:
    # Length-prefix interface names for unambiguous, stable node IDs.
    interface = binding.interface
    return (
        f"arp:{kind}:{len(interface.encode('utf-8'))}:{interface}:"
        f"{binding.hardware_type}:{binding.protocol_type}:{address.hex()}"
    )


def project_arp_address_map(
    bindings: Iterable[ARPBinding],
) -> ARPAddressMapSnapshot:
    """Project sender bindings without inferring host identity or liveness.

    The input is NetworkState's latest ARP binding snapshot. No ARP target
    is interpreted as a binding, and replaced bindings are not recreated.
    """
    nodes: dict[str, ARPAddressNode] = {}
    claims: list[ARPSenderClaim] = []
    for binding in sorted(
        bindings,
        key=lambda b: (
            b.interface, b.hardware_type, b.protocol_type,
            b.protocol_address, b.hardware_address,
        ),
    ):
        protocol_key = _node_key("protocol", binding, binding.protocol_address)
        hardware_key = _node_key("hardware", binding, binding.hardware_address)
        nodes[protocol_key] = ARPAddressNode(
            key=protocol_key, kind="protocol", interface=binding.interface,
            hardware_type=binding.hardware_type,
            protocol_type=binding.protocol_type,
            address=binding.protocol_address,
        )
        nodes[hardware_key] = ARPAddressNode(
            key=hardware_key, kind="hardware", interface=binding.interface,
            hardware_type=binding.hardware_type,
            protocol_type=binding.protocol_type,
            address=binding.hardware_address,
        )
        claims.append(ARPSenderClaim(
            protocol_node=protocol_key,
            hardware_node=hardware_key,
            interface=binding.interface,
            first_seen=binding.first_seen,
            last_seen=binding.last_seen,
            observation_count=binding.observation_count,
        ))

    return ARPAddressMapSnapshot(
        nodes=tuple(sorted(nodes.values(), key=lambda node: node.key)),
        claims=tuple(sorted(
            claims,
            key=lambda claim: (
                claim.interface, claim.protocol_node, claim.hardware_node,
            ),
        )),
    )
