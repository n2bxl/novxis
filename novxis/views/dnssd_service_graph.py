"""Pure, renderer-independent PTR-backed DNS-SD service evidence graph.

Only the *validated and bounded* LiveMDNSState.snapshot() projection is
accepted. That state already established PTR -> SRV -> A/AAAA name joins,
including its accepted/retracted cross-response reconciliations. This
module never re-correlates DNS records, initiates traffic, interprets TXT,
or upgrades advertisements to verified service or device identities.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Literal

from novxis.views.unified_address_graph import (
    UnifiedAddressEdge, UnifiedAddressGraphSnapshot, UnifiedAddressNode,
    _scope_part, _scoped_identifier,
)

DNSSDRecordSource = Literal[
    "ptr-observation", "same-mdns-response", "cross-mdns-response",
]
DNSSDAddressKind = Literal["a", "aaaa"]
DNSSD_EDGE_KIND = "dnssd_advertised_endpoint"

_MAX_SERVICES = 128
_MAX_TARGETS = 2
_MAX_ADDRESSES = 3
_MAX_NAME_LENGTH = 180
_MAX_TIMESTAMP = Decimal("10000000000000")
_MAX_TTL = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class DNSSDPTRRecord:
    """Retained PTR instance metadata, not a reference to a raw packet."""

    key: str
    service_type: str
    instance: str
    observed_at: Decimal
    ttl_seconds: int
    observations: int
    fresh: bool
    source: Literal["ptr-observation"] = "ptr-observation"


@dataclass(frozen=True, slots=True)
class DNSSDSRVRecord:
    """Validated SRV target/port for an already retained PTR instance."""

    key: str
    owner_name: str
    target_name: str
    port: int
    observed_at: Decimal
    ttl_seconds: int
    fresh: bool
    source: Literal["same-mdns-response", "cross-mdns-response"]


@dataclass(frozen=True, slots=True)
class DNSSDAddressRecord:
    """Validated target A/AAAA claim within an accepted SRV path."""

    key: str
    owner_name: str
    kind: DNSSDAddressKind
    address: bytes
    observed_at: Decimal
    ttl_seconds: int
    fresh: bool
    source: Literal["same-mdns-response", "cross-mdns-response"]


@dataclass(frozen=True, slots=True)
class DNSSDServiceNode:
    """PTR-backed advertised instance, NOT a verified running service."""

    key: str
    capture_scope: str
    interface: str
    service_type: str
    instance: str
    ptr: DNSSDPTRRecord


@dataclass(frozen=True, slots=True)
class DNSSDEndpointEdge:
    """Inspectible PTR + SRV + A/AAAA chain, not service reachability."""

    key: str
    kind: Literal["dnssd_advertised_endpoint"]
    capture_scope: str
    interface: str
    protocol_node: str
    service_node: str
    ptr: DNSSDPTRRecord
    srv: DNSSDSRVRecord
    address: DNSSDAddressRecord
    path_fresh: bool


@dataclass(frozen=True, slots=True)
class DNSSDServiceGraphSnapshot:
    """Address/MAC evidence plus optional DNS-SD service path evidence."""

    capture_scope: str
    interface: str
    as_of: Decimal
    nodes: tuple[UnifiedAddressNode | DNSSDServiceNode, ...]
    edges: tuple[UnifiedAddressEdge | DNSSDEndpointEdge, ...]
    source_truncated: bool
    omitted_advertisements: int
    skipped_unsupported_addresses: int

    @property
    def service_nodes(self) -> tuple[DNSSDServiceNode, ...]:
        return tuple(n for n in self.nodes if isinstance(n, DNSSDServiceNode))

    @property
    def endpoint_edges(self) -> tuple[DNSSDEndpointEdge, ...]:
        return tuple(e for e in self.edges if isinstance(e, DNSSDEndpointEdge))


def _text(value: object, label: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= _MAX_NAME_LENGTH
            or not value.isprintable()):
        raise ValueError(f"invalid {label}")
    return value


def _timestamp(value: object, label: str) -> Decimal:
    if not isinstance(value, str) or len(value) > 48:
        raise ValueError(f"invalid {label}")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid {label}") from exc
    if not parsed.is_finite() or not 0 <= parsed <= _MAX_TIMESTAMP:
        raise ValueError(f"invalid {label}")
    return parsed


def _integer(value: object, label: str, *, minimum: int = 0,
             maximum: int = _MAX_TTL) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"invalid {label}")
    return value


def _fresh(seen: Decimal, ttl: int, as_of: Decimal) -> bool:
    return ttl > 0 and seen <= as_of < seen + ttl


def _check_fresh(value: object, expected: bool, label: str) -> None:
    if type(value) is not bool or value is not expected:
        raise ValueError(f"inconsistent {label} freshness")


def _source(value: object, label: str) -> Literal[
    "same-mdns-response", "cross-mdns-response",
]:
    if value not in ("same-mdns-response", "cross-mdns-response"):
        raise ValueError(f"invalid {label} provenance")
    return value


def _records(value: object, limit: int, label: str) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"invalid or unbounded {label}")
    return value


def _endpoint_address(value: object, family: object) -> IPv4Address | IPv6Address:
    if type(family) is not int or family not in (4, 6):
        raise ValueError("invalid A/AAAA family")
    if not isinstance(value, str) or len(value) > 45:
        raise ValueError("invalid A/AAAA address")
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise ValueError("invalid A/AAAA address") from exc
    if address.version != family or str(address) != value:
        raise ValueError("noncanonical or mismatched A/AAAA address")
    return address


def _supported_endpoint(address: IPv4Address | IPv6Address) -> bool:
    return not (
        address.is_unspecified or address.is_multicast or
        (isinstance(address, IPv4Address) and
         address == IPv4Address("255.255.255.255"))
    )


def project_dnssd_service_graph(
    address_graph: UnifiedAddressGraphSnapshot,
    mdns_evidence: Mapping,
    *,
    interface: str,
    capture_scope: str,
) -> DNSSDServiceGraphSnapshot:
    """Project only retained, receiver-accepted DNS-SD claims.

    Stage 2 supplies the already validated mDNS snapshot for one capture
    interface and the Stage 1N-L immutable address graph. No DNS join,
    link-layer association, reachability or active discovery occurs here.
    A retained expired path remains inspectable, but a *retracted* join
    is absent from the receiver snapshot and cannot be resurrected.
    """
    if not isinstance(address_graph, UnifiedAddressGraphSnapshot):
        raise TypeError("expected a unified address evidence snapshot")
    scope = _scope_part(capture_scope, "capture scope")
    iface = _scope_part(interface, "capture interface")
    if address_graph.capture_scope != scope:
        raise ValueError("address graph capture scope mismatch")
    if not isinstance(mdns_evidence, Mapping):
        raise TypeError("expected validated mDNS evidence")
    if (mdns_evidence.get("origin") != "mdns-observation"
            or mdns_evidence.get("schema_version") != 1
            or mdns_evidence.get("interface") != iface):
        raise ValueError("mDNS evidence outside authorized capture interface")

    as_of = _timestamp(mdns_evidence.get("as_of"), "mDNS snapshot time")
    truncated = mdns_evidence.get("truncated")
    if type(truncated) is not bool:
        raise ValueError("invalid mDNS truncation marker")
    omitted = _integer(
        mdns_evidence.get("omitted_advertisements"),
        "omitted advertisements", maximum=100000000,
    )
    services = _records(mdns_evidence.get("services"), _MAX_SERVICES,
                        "PTR-backed services")
    if "retained_instances" in mdns_evidence and (
        mdns_evidence["retained_instances"] != len(services)
        or type(mdns_evidence["retained_instances"]) is not int
    ):
        raise ValueError("inconsistent retained service count")

    # Preserve original graph objects/keys, including contradictory MAC
    # claims. A different interface's nodes may be present in an upstream
    # multi-interface projection but must not appear in this scope's map.
    nodes: dict[str, UnifiedAddressNode | DNSSDServiceNode] = {}
    edges: dict[str, UnifiedAddressEdge | DNSSDEndpointEdge] = {}
    for node in address_graph.nodes:
        if node.capture_scope != scope:
            raise ValueError("address node from another capture scope")
        if node.interface == iface:
            if node.key in nodes and nodes[node.key] != node:
                raise ValueError("conflicting address node identity")
            nodes[node.key] = node
    for edge in address_graph.edges:
        if edge.capture_scope != scope:
            raise ValueError("address edge from another capture scope")
        if edge.interface == iface:
            if edge.protocol_node not in nodes or edge.hardware_node not in nodes:
                raise ValueError("unresolved address evidence edge")
            if edge.key in edges and edges[edge.key] != edge:
                raise ValueError("conflicting address edge identity")
            edges[edge.key] = edge

    skipped = 0
    for item in services:
        if not isinstance(item, Mapping):
            raise ValueError("invalid PTR-backed service")
        service_type = _text(item.get("service_type"), "service type")
        instance = _text(item.get("instance"), "service instance")
        ptr_at = _timestamp(item.get("last_seen"), "PTR timestamp")
        ptr_ttl = _integer(item.get("ttl_seconds"), "PTR TTL")
        count = _integer(item.get("observations"), "PTR observation count",
                         minimum=1, maximum=100000000)
        ptr_fresh = _fresh(ptr_at, ptr_ttl, as_of)
        _check_fresh(item.get("fresh"), ptr_fresh, "PTR")
        service_id = _scoped_identifier(
            "dnssd-service", scope, iface, service_type.lower(),
            instance.lower(),
        )
        ptr = DNSSDPTRRecord(
            key=_scoped_identifier(
                "dnssd-record", scope, iface, "ptr",
                service_type.lower(), instance.lower(),
                str(ptr_at), str(ptr_ttl),
            ),
            service_type=service_type, instance=instance,
            observed_at=ptr_at, ttl_seconds=ptr_ttl,
            observations=count, fresh=ptr_fresh,
        )
        service = DNSSDServiceNode(
            key=service_id, capture_scope=scope, interface=iface,
            service_type=service_type, instance=instance, ptr=ptr,
        )
        if service_id in nodes and nodes[service_id] != service:
            raise ValueError("conflicting normalized DNS-SD service identity")
        nodes[service_id] = service

        for target in _records(item.get("targets"), _MAX_TARGETS, "SRV targets"):
            if not isinstance(target, Mapping):
                raise ValueError("invalid SRV target")
            hostname = _text(target.get("target"), "SRV target hostname")
            port = _integer(target.get("port"), "SRV port", maximum=65535)
            srv_at = _timestamp(target.get("observed_at"), "SRV timestamp")
            srv_ttl = _integer(target.get("ttl_seconds"), "SRV TTL")
            srv_source = _source(target.get("source"), "SRV")
            srv_fresh = _fresh(srv_at, srv_ttl, as_of)
            _check_fresh(target.get("fresh"), srv_fresh, "SRV")
            _check_fresh(target.get("path_fresh"),
                         ptr_fresh and srv_fresh, "PTR/SRV path")
            srv = DNSSDSRVRecord(
                key=_scoped_identifier(
                    "dnssd-record", scope, iface, "srv", instance.lower(),
                    hostname.lower(), str(port), str(srv_at),
                    str(srv_ttl), srv_source,
                ),
                owner_name=instance, target_name=hostname, port=port,
                observed_at=srv_at, ttl_seconds=srv_ttl,
                fresh=srv_fresh, source=srv_source,
            )
            for record in _records(target.get("addresses"), _MAX_ADDRESSES,
                                   "A/AAAA target records"):
                if not isinstance(record, Mapping):
                    raise ValueError("invalid A/AAAA record")
                addr = _endpoint_address(record.get("address"),
                                         record.get("family"))
                addr_at = _timestamp(record.get("observed_at"),
                                     "A/AAAA timestamp")
                addr_ttl = _integer(record.get("ttl"), "A/AAAA TTL")
                addr_source = _source(record.get("source"), "A/AAAA")
                addr_fresh = _fresh(addr_at, addr_ttl, as_of)
                _check_fresh(record.get("fresh"), addr_fresh, "A/AAAA")
                path_fresh = ptr_fresh and srv_fresh and addr_fresh
                _check_fresh(record.get("path_fresh"), path_fresh,
                             "PTR/SRV/A/AAAA path")
                if not _supported_endpoint(addr):
                    # Valid DNS evidence, but not a usable unicast endpoint.
                    # Keep the service itself; never manufacture a MAC link.
                    skipped += 1
                    continue
                family: Literal["ipv4", "ipv6"] = (
                    "ipv4" if addr.version == 4 else "ipv6"
                )
                ip_id = _scoped_identifier(
                    "node", scope, iface, family, addr.packed.hex(),
                )
                address_node = UnifiedAddressNode(
                    key=ip_id, kind=family, capture_scope=scope,
                    interface=iface, address=addr.packed,
                )
                if ip_id in nodes and nodes[ip_id] != address_node:
                    raise ValueError("conflicting address evidence identity")
                nodes[ip_id] = address_node
                evidence = DNSSDAddressRecord(
                    key=_scoped_identifier(
                        "dnssd-record", scope, iface, family,
                        hostname.lower(), addr.packed.hex(),
                        str(addr_at), str(addr_ttl), addr_source,
                    ),
                    owner_name=hostname,
                    kind="a" if addr.version == 4 else "aaaa",
                    address=addr.packed, observed_at=addr_at,
                    ttl_seconds=addr_ttl, fresh=addr_fresh,
                    source=addr_source,
                )
                edge = DNSSDEndpointEdge(
                    key=_scoped_identifier(
                        "edge", scope, iface, DNSSD_EDGE_KIND,
                        service_type.lower(), instance.lower(),
                        hostname.lower(), str(port), family,
                        addr.packed.hex(), ptr.key, srv.key, evidence.key,
                    ),
                    kind=DNSSD_EDGE_KIND, capture_scope=scope,
                    interface=iface, protocol_node=ip_id,
                    service_node=service_id, ptr=ptr, srv=srv,
                    address=evidence, path_fresh=path_fresh,
                )
                if edge.key in edges and edges[edge.key] != edge:
                    raise ValueError("conflicting DNS-SD endpoint evidence")
                edges[edge.key] = edge

    return DNSSDServiceGraphSnapshot(
        capture_scope=scope, interface=iface, as_of=as_of,
        nodes=tuple(nodes[k] for k in sorted(nodes)),
        edges=tuple(edges[k] for k in sorted(edges)),
        source_truncated=truncated,
        omitted_advertisements=omitted,
        skipped_unsupported_addresses=skipped,
    )
