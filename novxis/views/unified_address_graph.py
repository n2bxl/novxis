"""Renderer-independent IPv4, IPv6, and Ethernet address evidence.

This is a pure projection of *existing* ARP sender bindings and
option-backed NDP source/target assertions. The nodes are addresses,
not devices; the edges are protocol claims, not topology or liveness.
No packet parsing, capture, DNS-SD, gateway, or OS inference happens here.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from novxis.state.arp import ARPBinding
from novxis.state.ndp import NDAddressClaim

UnifiedNodeKind = Literal["ipv4", "ipv6", "hardware"]
UnifiedEvidenceKind = Literal[
    "arp_sender", "ndp_ns_source_slla", "ndp_na_target_tlla",
]


@dataclass(frozen=True, slots=True)
class UnifiedAddressNode:
    """One protocol or hardware address in an explicit observation scope."""

    key: str
    kind: UnifiedNodeKind
    capture_scope: str
    interface: str
    address: bytes


@dataclass(frozen=True, slots=True)
class UnifiedAddressEdge:
    """An observed protocol claim, never proof of device identity."""

    key: str
    protocol_node: str
    hardware_node: str
    capture_scope: str
    interface: str
    evidence_kind: UnifiedEvidenceKind
    # Refers to the *aggregated source state record*, not a raw packet ID.
    source_record_key: str
    first_seen: Decimal
    last_seen: Decimal
    observation_count: int


@dataclass(frozen=True, slots=True)
class UnifiedAddressGraphSnapshot:
    """Immutable, deterministically sorted evidence, with no layout data."""

    capture_scope: str
    nodes: tuple[UnifiedAddressNode, ...]
    edges: tuple[UnifiedAddressEdge, ...]
    skipped_unsupported_arp_bindings: int


def _scoped_identifier(*parts: str) -> str:
    """Length-prefix UTF-8 fields to avoid delimiter and scope collisions."""
    return "unified:v1:" + "".join(
        f"{len(part.encode('utf-8'))}:{part}" for part in parts
    )


def _scope_part(value: str, label: str) -> str:
    if not isinstance(value, str) or not (
        1 <= len(value.encode("utf-8")) <= 128 and value.isprintable()
    ):
        raise ValueError(f"{label} must be a printable, nonempty string (<=128 bytes)")
    return value


def _times(first: Decimal, last: Decimal, count: int) -> None:
    if (
        not isinstance(first, Decimal)
        or not isinstance(last, Decimal)
        or not first.is_finite()
        or not last.is_finite()
        or first < 0
        or last < first
        or type(count) is not int
        or count < 1
    ):
        raise ValueError("invalid evidence timestamps or observation count")


def _ethernet_unicast(value: bytes) -> bool:
    return (
        type(value) is bytes
        and len(value) == 6
        and value != bytes(6)
        and not value[0] & 1
    )


def _ipv4_sender(value: bytes) -> bool:
    if type(value) is not bytes or len(value) != 4:
        return False
    address = IPv4Address(value)
    return not (
        address.is_unspecified
        or address.is_multicast
        or address == IPv4Address("255.255.255.255")
    )


def _ipv6_claimed(value: bytes) -> bool:
    if type(value) is not bytes or len(value) != 16:
        return False
    address = IPv6Address(value)
    return not (address.is_unspecified or address.is_multicast)


def project_unified_address_graph(
    arp_bindings: Iterable[ARPBinding],
    ndp_claims: Iterable[NDAddressClaim],
    *,
    capture_scope: str,
) -> UnifiedAddressGraphSnapshot:
    """Join only explicitly claimed addresses within capture+interface scope.

    Supply a distinct capture_scope for each independent capture/session.
    ARP's *current* binding state contains its latest sender association;
    earlier replaced ARP mappings are not reconstructed. NDP Stage 2
    retains separate conflicting option-backed claims by design.

    NDP's unlinked observations are deliberately NOT an input. A DAD
    probe, NS target without its own SLLA, or NA without TLLA cannot
    become an IPv6-to-Ethernet edge by matching other packet fields.
    """
    scope = _scope_part(capture_scope, "capture_scope")
    nodes: dict[str, UnifiedAddressNode] = {}
    edges: dict[str, UnifiedAddressEdge] = {}
    skipped_arp = 0

    def add_claim(
        interface: str,
        family: Literal["ipv4", "ipv6"],
        address: bytes,
        mac: bytes,
        evidence_kind: UnifiedEvidenceKind,
        first: Decimal,
        last: Decimal,
        count: int,
        record_key: str,
    ) -> None:
        interface = _scope_part(interface, "capture interface")
        _times(first, last, count)
        ip_key = _scoped_identifier(
            "node", scope, interface, family, address.hex(),
        )
        mac_key = _scoped_identifier(
            "node", scope, interface, "hardware", mac.hex(),
        )
        nodes[ip_key] = UnifiedAddressNode(
            key=ip_key, kind=family, capture_scope=scope,
            interface=interface, address=address,
        )
        nodes[mac_key] = UnifiedAddressNode(
            key=mac_key, kind="hardware", capture_scope=scope,
            interface=interface, address=mac,
        )
        edge_key = _scoped_identifier(
            "edge", scope, interface, evidence_kind, family,
            address.hex(), mac.hex(),
        )
        edge = UnifiedAddressEdge(
            key=edge_key, protocol_node=ip_key, hardware_node=mac_key,
            capture_scope=scope, interface=interface,
            evidence_kind=evidence_kind, source_record_key=record_key,
            first_seen=first, last_seen=last, observation_count=count,
        )
        previous = edges.get(edge_key)
        if previous is not None and previous != edge:
            # Both state stores already aggregate repeated observations.
            # Do not guess how to merge duplicate, inconsistent snapshots.
            raise ValueError("inconsistent duplicate evidence state records")
        edges[edge_key] = edge

    for binding in arp_bindings:
        if not isinstance(binding, ARPBinding):
            raise TypeError("ARP input must consist of ARPBinding records")
        _scope_part(binding.interface, "capture interface")
        # This first slice connects Ethernet MACs and IPv4 senders only.
        # Other ARP hardware/protocol families stay in the existing view.
        if not (
            binding.hardware_type == 1
            and binding.protocol_type == 0x0800
            and _ethernet_unicast(binding.hardware_address)
            and _ipv4_sender(binding.protocol_address)
        ):
            skipped_arp += 1
            continue
        add_claim(
            binding.interface, "ipv4", binding.protocol_address,
            binding.hardware_address, "arp_sender", binding.first_seen,
            binding.last_seen, binding.observation_count,
            _scoped_identifier(
                "source-record", scope, binding.interface, "arp_sender",
                str(binding.hardware_type), str(binding.protocol_type),
                binding.protocol_address.hex(), binding.hardware_address.hex(),
            ),
        )

    for claim in ndp_claims:
        if not isinstance(claim, NDAddressClaim):
            raise TypeError("NDP input must consist of option-backed NDAddressClaim records")
        if claim.kind not in ("ns_source_slla", "na_target_tlla"):
            raise ValueError("unsupported NDP address-claim kind")
        if not (
            _ipv6_claimed(claim.ipv6_address)
            and _ethernet_unicast(claim.link_layer_address)
        ):
            raise ValueError("invalid option-backed NDP address claim")
        evidence_kind: UnifiedEvidenceKind = (
            "ndp_ns_source_slla" if claim.kind == "ns_source_slla"
            else "ndp_na_target_tlla"
        )
        add_claim(
            claim.interface, "ipv6", claim.ipv6_address,
            claim.link_layer_address, evidence_kind,
            claim.first_seen, claim.last_seen, claim.observation_count,
            _scoped_identifier(
                "source-record", scope, claim.interface, claim.kind,
                claim.ipv6_address.hex(), claim.link_layer_address.hex(),
            ),
        )

    return UnifiedAddressGraphSnapshot(
        capture_scope=scope,
        nodes=tuple(nodes[k] for k in sorted(nodes)),
        edges=tuple(edges[k] for k in sorted(edges)),
        skipped_unsupported_arp_bindings=skipped_arp,
    )
