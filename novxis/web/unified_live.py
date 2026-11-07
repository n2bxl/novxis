"""Read-only adapter: sanitized live NDP + ARP -> Stage 1 address graph.

The privileged producer sends bounded NDJSON metadata, never packet bytes.
The unprivileged receiver validates that metadata in LiveNDPState before
this adapter reconstructs *claim fields only* for the pure Stage 1 projector.
A raw original NeighborDiscoveryObserved object is intentionally unavailable.
"""

from collections.abc import Iterable, Mapping
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address

from novxis.state.arp import ARPBinding
from novxis.state.ndp import NDAddressClaim
from novxis.views.unified_address_graph import (
    UnifiedAddressGraphSnapshot, project_unified_address_graph,
)


def _validated_claims(
    ndp_evidence: Mapping, *, interface: str,
) -> tuple[NDAddressClaim, ...]:
    """Convert receiver-validated sanitized claims, not frame senders.

    Do not pass `unlinked` observations to the graph projection. The
    `latest_observation=None` field explicitly denotes that the privileged
    original packet is *not available* across the NDJSON boundary.
    The Stage 1 projector never accesses that field.
    """
    if (ndp_evidence.get("origin") != "ndp-observation"
            or ndp_evidence.get("interface") != interface):
        raise ValueError("NDP snapshot outside live capture interface")
    claims = ndp_evidence.get("claims")
    if not isinstance(claims, list):
        raise ValueError("missing validated NDP claims")
    if len(claims) > 4096:
        raise ValueError("NDP claim count exceeds bounded receiver capacity")
    converted = []
    for item in claims:
        if not isinstance(item, dict) or item.get("interface") != interface:
            raise ValueError("NDP claim outside live capture interface")
        # The receiver already checked canonical IPv6, Ethernet unicast,
        # option-backed NS-source vs NA-target association, and time bounds.
        # This is an *internal* snapshot, not a new public ingestion path.
        converted.append(NDAddressClaim(
            interface=interface,
            ipv6_address=IPv6Address(item["address"]).packed,
            link_layer_address=bytes.fromhex(item["mac"]),
            kind=item["kind"],
            first_seen=Decimal(item["first_seen"]),
            last_seen=Decimal(item["last_seen"]),
            observation_count=item["observations"],
            latest_observation=None,
        ))
    return tuple(converted)


def serialize_unified_address_graph(
    snapshot: UnifiedAddressGraphSnapshot,
    *,
    interface: str,
    revision: int,
    arp_truncated: bool,
    omitted_ndp_claims: int,
    omitted_ndp_unlinked: int,
) -> dict:
    """Produce a separate versioned JSON view; never mutate ARP schema."""
    nodes = [
        {
            "id": node.key,
            "kind": node.kind,
            "capture_scope": node.capture_scope,
            "interface": node.interface,
            "address_hex": node.address.hex(),
            "display_address": (
                str(IPv4Address(node.address)) if node.kind == "ipv4"
                else str(IPv6Address(node.address)) if node.kind == "ipv6"
                else ":".join(f"{octet:02x}" for octet in node.address)
            ),
        }
        for node in snapshot.nodes
    ]
    edges = [
        {
            "id": edge.key,
            "source": edge.protocol_node,
            "target": edge.hardware_node,
            "capture_scope": edge.capture_scope,
            "interface": edge.interface,
            "kind": edge.evidence_kind,
            "source_record_key": edge.source_record_key,
            "first_seen": str(edge.first_seen),
            "last_seen": str(edge.last_seen),
            "observation_count": edge.observation_count,
        }
        for edge in snapshot.edges
    ]
    return {
        "schema_version": 1,
        "origin": "passive-arp-ndp",
        "capture_scope": snapshot.capture_scope,
        "interface": interface,
        "revision": revision,
        "nodes": nodes,
        "edges": edges,
        "skipped_unsupported_arp_bindings": (
            snapshot.skipped_unsupported_arp_bindings
        ),
        "arp_bindings_truncated": arp_truncated,
        "omitted_ndp_claims": omitted_ndp_claims,
        "omitted_ndp_unlinked": omitted_ndp_unlinked,
        "truncated": bool(
            arp_truncated or omitted_ndp_claims or omitted_ndp_unlinked
        ),
        "limitation": (
            "Address-to-MAC packet assertions only; not device identity, "
            "verified host ownership, liveness, cables, or physical topology."
        ),
    }


def project_live_unified_address_graph(
    bindings: Iterable[ARPBinding],
    ndp_evidence: Mapping,
    *,
    interface: str,
    capture_scope: str,
    revision: int,
    arp_truncated: bool = False,
) -> dict:
    """Adapt one validated live session to the pure Stage 1 graph.

    Capture scope is allocated by the unprivileged state owner, not
    claimed by an untrusted NDJSON sender.
    """
    if not isinstance(interface, str) or not interface:
        raise ValueError("missing capture interface")
    if type(revision) is not int or revision < 0:
        raise ValueError("invalid unified graph revision")
    ndp_claims = _validated_claims(ndp_evidence, interface=interface)
    snapshot = project_unified_address_graph(
        bindings, ndp_claims, capture_scope=capture_scope,
    )
    # The Stage 1 projector also rejects malformed claim kinds and values.
    for node in snapshot.nodes:
        if node.interface != interface:
            raise ValueError("unified graph includes another capture interface")
    omitted_claims = ndp_evidence.get("omitted_claims", 0)
    omitted_unlinked = ndp_evidence.get("omitted_unlinked", 0)
    if any(type(n) is not int or n < 0 for n in
           (omitted_claims, omitted_unlinked)):
        raise ValueError("invalid NDP truncation metadata")
    return serialize_unified_address_graph(
        snapshot,
        interface=interface,
        revision=revision,
        arp_truncated=arp_truncated,
        omitted_ndp_claims=omitted_claims,
        omitted_ndp_unlinked=omitted_unlinked,
    )
