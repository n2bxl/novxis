"""Evidence-only grouping of observed ARP IPv4 addresses by host OS prefixes.

A configured prefix is a host OS fact; an ARP sender address is a captured
claim. Address containment is a comparison of two independent sources,
not verification of host identity, link adjacency, reachability or membership.
"""

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Any

from novxis.views.arp_address_map import ARPAddressMapSnapshot

MAX_PREFIXES = 16


def _configured_prefixes(host_context: dict) -> tuple[tuple[IPv4Network, str], ...]:
    """Accept only internally consistent, normalized IPv4 configuration."""
    values = host_context.get("ipv4_addresses")
    if not isinstance(values, list):
        return ()
    result = {}
    for value in values[:MAX_PREFIXES]:
        if not isinstance(value, dict):
            continue
        address = value.get("address")
        prefix = value.get("prefix_length")
        network = value.get("network")
        if not isinstance(address, str) or type(prefix) is not int:
            continue
        if not isinstance(network, str):
            continue
        try:
            if not 0 <= prefix <= 32:
                continue
            configured = IPv4Interface(f"{address}/{prefix}")
            reported = IPv4Network(network, strict=True)
            if configured.network != reported or (
                str(configured.ip) != address
                or str(reported) != network
            ):
                continue
        except ValueError:
            continue
        result[str(reported)] = (reported, address)
    return tuple(result[key] for key in sorted(
        result, key=lambda cidr: (
            int(IPv4Network(cidr).network_address),
            IPv4Network(cidr).prefixlen,
        )
    ))


def project_subnet_evidence(
    snapshot: ARPAddressMapSnapshot,
    host_context: dict | None,
    *,
    capture_interface: str,
) -> dict[str, Any] | None:
    """Project a bounded, typed, interface-scoped IPv4 subnet evidence lens.

    When no trustworthy host context exists, do not derive a subnet from
    ARP observations. Unmatched ARP senders are only outside *reported*
    prefixes, not proven remote or on another L2 segment.
    """
    if (
        not isinstance(host_context, dict)
        or host_context.get("origin") != "local-os"
        or host_context.get("schema_version") != 1
        or host_context.get("interface") != capture_interface
        or not capture_interface
    ):
        return None

    prefixes = _configured_prefixes(host_context)
    protocol_nodes = []
    for node in snapshot.nodes:
        if (
            node.kind != "protocol"
            or node.interface != capture_interface
            or node.protocol_type != 0x0800
            or len(node.address) != 4
        ):
            continue
        protocol_nodes.append((node.key, IPv4Address(node.address)))

    protocol_nodes.sort(key=lambda item: (int(item[1]), item[0]))
    groups = []
    grouped_keys: set[str] = set()
    for network, configured_address in prefixes:
        matches = [
            {"node_id": node_id, "address": str(address)}
            for node_id, address in protocol_nodes if address in network
        ]
        grouped_keys.update(item["node_id"] for item in matches)
        groups.append({
            "network": str(network),
            "configured_address": configured_address,
            "origin": "local-os-configured-prefix",
            "matching_observed_ipv4": matches,
            "observed_address_count": len(matches),
        })

    outside = [
        {"node_id": node_id, "address": str(address)}
        for node_id, address in protocol_nodes if node_id not in grouped_keys
    ] if prefixes else []

    # Only display an independent same-interface cross-reference where the
    # OS route's actual interface agrees with this capture scope. Neither
    # source alone establishes an edge to the gateway or a physical device.
    gateway_reference = None
    route = host_context.get("default_route")
    if isinstance(route, dict) and (
        route.get("scope") == "os-selected-ipv4-default"
        and route.get("interface") == capture_interface
    ):
        gateway = route.get("gateway")
        try:
            if not isinstance(gateway, str):
                raise ValueError("non-string gateway")
            parsed_gateway = IPv4Address(gateway)
            for node_id, address in protocol_nodes:
                if address == parsed_gateway:
                    gateway_reference = {
                        "node_id": node_id,
                        "address": str(address),
                        "relationship": "os-route-address-matches-arp-sender",
                        "route_interface": capture_interface,
                    }
                    break
        except ValueError:
            pass

    return {
        "schema_version": 1,
        "origin": "derived-comparison",
        "source_types": ["local-os-configured-prefix", "arp-sender-observation"],
        "capture_interface": capture_interface,
        "host_context_observed_at": host_context.get("observed_at"),
        "reported_prefix_count": len(groups),
        "observed_ipv4_address_count": len(protocol_nodes),
        "configured_prefixes": groups,
        "outside_reported_prefixes": outside,
        "unclassified_without_prefix": (
            [{"node_id": key, "address": str(address)}
             for key, address in protocol_nodes]
            if not prefixes else []
        ),
        "gateway_address_cross_reference": gateway_reference,
        "limitations": (
            "Address containment in a reported OS prefix is not evidence "
            "of host reachability, physical attachment, or subnet membership."
        ),
    }
