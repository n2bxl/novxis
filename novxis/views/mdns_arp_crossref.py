"""Read-only, exact-address cross-reference between independent mDNS and ARP evidence.

A matching IPv4 byte sequence on the same capture interface offers
navigation only. It does not prove service reachability, device
identity, protocol adjacency or a physical network connection.
"""

from ipaddress import IPv4Address


def cross_reference_mdns_arp(mdns_evidence: dict, nodes: list[dict]) -> dict:
    """Add existing interface-scoped IPv4 ARP node IDs to mDNS A claims."""
    interface = mdns_evidence.get("interface")
    arp_by_ip = {}
    for node in nodes:
        if (
            node.get("kind") == "protocol"
            and node.get("interface") == interface
            and node.get("protocol_type") == 0x0800
            and node.get("hardware_type") == 1
            and isinstance(node.get("address_hex"), str)
            and isinstance(node.get("id"), str)
        ):
            arp_by_ip[node["address_hex"]] = node["id"]

    services = []
    for item in mdns_evidence.get("services", []):
        targets = []
        for target in item.get("targets", []):
            addresses = []
            for address in target.get("addresses", []):
                scoped = dict(address)
                if scoped.get("family") == 4:
                    try:
                        address_hex = IPv4Address(scoped["address"]).packed.hex()
                    except (ValueError, KeyError, TypeError):
                        address_hex = None
                    node_id = arp_by_ip.get(address_hex)
                    if node_id is not None:
                        scoped["arp_node_id"] = node_id
                        scoped["arp_cross_reference"] = (
                            "independent_same_interface_ipv4_address"
                        )
                addresses.append(scoped)
            targets.append({**target, "addresses": addresses})
        services.append({**item, "targets": targets})
    return {**mdns_evidence, "services": services}
