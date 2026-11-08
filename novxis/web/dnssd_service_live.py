"""Unprivileged, additive serialization for scoped live DNS-SD graph evidence.

Consumes only validated bounded mDNS and option-backed NDP receiver state,
plus existing ARP bindings. No raw packet reconstruction, network activity,
new capture privilege, or inferred host/service ownership.
"""

from collections.abc import Iterable, Mapping
from ipaddress import IPv4Address, IPv6Address

from novxis.state.arp import ARPBinding
from novxis.views.dnssd_service_graph import (
    DNSSDAddressRecord, DNSSDEndpointEdge, DNSSDPTRRecord,
    DNSSDSRVRecord, DNSSDServiceGraphSnapshot, DNSSDServiceNode,
    project_dnssd_service_graph,
)
from novxis.views.unified_address_graph import (
    UnifiedAddressEdge, UnifiedAddressNode, project_unified_address_graph,
)
from novxis.web.unified_live import _validated_claims


def build_live_dnssd_service_graph(
    bindings: Iterable[ARPBinding],
    ndp_evidence: Mapping,
    mdns_evidence: Mapping,
    *,
    interface: str,
    capture_scope: str,
) -> DNSSDServiceGraphSnapshot:
    """Produce the pure service graph from already receiver-validated state.

    The address-only Stage 2 projector uses the identical
    project_unified_address_graph() function and the same NDP adapter.
    Existing unlinked/DAD observations never become address-to-MAC edges.
    """
    if not isinstance(interface, str) or not interface:
        raise ValueError("missing live capture interface")
    address_snapshot = project_unified_address_graph(
        bindings, _validated_claims(ndp_evidence, interface=interface),
        capture_scope=capture_scope,
    )
    if any(node.interface != interface for node in address_snapshot.nodes):
        raise ValueError("service graph includes another capture interface")
    return project_dnssd_service_graph(
        address_snapshot, mdns_evidence, interface=interface,
        capture_scope=capture_scope,
    )


def service_graph_semantic_signature(
    snapshot: DNSSDServiceGraphSnapshot,
) -> tuple:
    """Exclude continuously advancing as_of, but capture every state change.

    Freshness booleans of PTR/SRV/A/AAAA are part of immutable node/edge
    records, so exact TTL expiry advances the semantic signature. Source
    truncation, accepted record epochs, counts and ARP/NDP claims do too.
    """
    if not isinstance(snapshot, DNSSDServiceGraphSnapshot):
        raise TypeError("expected DNS-SD service graph")
    return (
        snapshot.nodes, snapshot.edges, snapshot.source_truncated,
        snapshot.omitted_advertisements,
        snapshot.skipped_unsupported_addresses,
    )


def _ptr(value: DNSSDPTRRecord) -> dict:
    return {
        "source_record_key": value.key,
        "service_type": value.service_type,
        "instance": value.instance,
        "observed_at": str(value.observed_at),
        "ttl_seconds": value.ttl_seconds,
        "observation_count": value.observations,
        "fresh": value.fresh,
        "source": value.source,
    }


def _srv(value: DNSSDSRVRecord) -> dict:
    return {
        "source_record_key": value.key,
        "owner_name": value.owner_name,
        "target_name": value.target_name,
        "port": value.port,
        "observed_at": str(value.observed_at),
        "ttl_seconds": value.ttl_seconds,
        "fresh": value.fresh,
        "source": value.source,
    }


def _address(value: DNSSDAddressRecord) -> dict:
    return {
        "source_record_key": value.key,
        "owner_name": value.owner_name,
        "kind": value.kind,
        "address": (
            str(IPv4Address(value.address)) if value.kind == "a"
            else str(IPv6Address(value.address))
        ),
        "observed_at": str(value.observed_at),
        "ttl_seconds": value.ttl_seconds,
        "fresh": value.fresh,
        "source": value.source,
    }


def _node(value: UnifiedAddressNode | DNSSDServiceNode) -> dict:
    if isinstance(value, DNSSDServiceNode):
        return {
            "id": value.key, "kind": value.kind,
            "capture_scope": value.capture_scope,
            "interface": value.interface,
            "service_type": value.service_type,
            "instance": value.instance,
            "ptr": _ptr(value.ptr),
        }
    if not isinstance(value, UnifiedAddressNode):
        raise TypeError("unsupported service graph node")
    return {
        "id": value.key, "kind": value.kind,
        "capture_scope": value.capture_scope,
        "interface": value.interface,
        "address_hex": value.address.hex(),
        "display_address": (
            str(IPv4Address(value.address)) if value.kind == "ipv4"
            else str(IPv6Address(value.address)) if value.kind == "ipv6"
            else ":".join(f"{octet:02x}" for octet in value.address)
        ),
    }


def _edge(value: UnifiedAddressEdge | DNSSDEndpointEdge) -> dict:
    if isinstance(value, DNSSDEndpointEdge):
        return {
            "id": value.key,
            "kind": value.kind,
            "source": value.protocol_node,
            "target": value.service_node,
            "capture_scope": value.capture_scope,
            "interface": value.interface,
            "path_fresh": value.path_fresh,
            "ptr": _ptr(value.ptr),
            "srv": _srv(value.srv),
            "address": _address(value.address),
        }
    if not isinstance(value, UnifiedAddressEdge):
        raise TypeError("unsupported service graph edge")
    return {
        "id": value.key,
        "source": value.protocol_node,
        "target": value.hardware_node,
        "capture_scope": value.capture_scope,
        "interface": value.interface,
        "kind": value.evidence_kind,
        "source_record_key": value.source_record_key,
        "first_seen": str(value.first_seen),
        "last_seen": str(value.last_seen),
        "observation_count": value.observation_count,
    }


def serialize_dnssd_service_graph(
    snapshot: DNSSDServiceGraphSnapshot,
    *,
    revision: int,
    arp_truncated: bool,
    omitted_ndp_claims: int,
    omitted_ndp_unlinked: int,
) -> dict:
    """Separate versioned API projection; legacy API shapes stay unchanged."""
    if not isinstance(snapshot, DNSSDServiceGraphSnapshot):
        raise TypeError("expected DNS-SD service graph")
    if type(revision) is not int or revision < 0:
        raise ValueError("invalid service graph revision")
    if type(arp_truncated) is not bool:
        raise ValueError("invalid ARP truncation marker")
    if any(type(n) is not int or n < 0 for n in (
        omitted_ndp_claims, omitted_ndp_unlinked,
    )):
        raise ValueError("invalid NDP omission metadata")
    return {
        "schema_version": 1,
        "origin": "passive-arp-ndp-mdns",
        "capture_scope": snapshot.capture_scope,
        "interface": snapshot.interface,
        "revision": revision,
        "as_of": str(snapshot.as_of),
        "nodes": [_node(n) for n in snapshot.nodes],
        "edges": [_edge(e) for e in snapshot.edges],
        "mdns_truncated": snapshot.source_truncated,
        "omitted_mdns_advertisements": snapshot.omitted_advertisements,
        "skipped_unsupported_addresses": (
            snapshot.skipped_unsupported_addresses
        ),
        "arp_bindings_truncated": arp_truncated,
        "omitted_ndp_claims": omitted_ndp_claims,
        "omitted_ndp_unlinked": omitted_ndp_unlinked,
        "truncated": bool(
            snapshot.source_truncated or arp_truncated
            or omitted_ndp_claims or omitted_ndp_unlinked
        ),
        "limitation": (
            "PTR-backed DNS-SD advertisements are not verified running "
            "services, open ports, reachability or physical device ownership. "
            "All address-to-hardware claims remain independent ARP/NDP evidence."
        ),
    }
