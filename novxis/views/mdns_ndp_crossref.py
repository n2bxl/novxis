"""Cross-reference DNS-SD AAAA to independently observed IPv6 NDP claims.

Links navigate existing same-interface evidence only; a matching IPv6
string is not authenticated service ownership or a physical host link.
NAs without TLLA and tentative DAD targets cannot create a link.
"""

from ipaddress import IPv6Address


def cross_reference_mdns_ndp(mdns: dict, ndp: dict) -> dict:
    """Annotate exact-scope AAAA address records only, never create nodes."""
    if mdns.get("interface") != ndp.get("interface"):
        return mdns
    known = {}
    for claim in ndp.get("claims", []):
        if claim.get("interface") != ndp.get("interface"):
            continue
        if claim.get("kind") not in ("ns_source_slla", "na_target_tlla"):
            continue
        try:
            address = str(IPv6Address(claim["address"]))
        except (ValueError, TypeError, KeyError):
            continue
        known.setdefault(address, set()).add(claim["mac"])

    services = []
    for item in mdns.get("services", []):
        targets = []
        for target in item.get("targets", []):
            addresses = []
            for original in target.get("addresses", []):
                record = dict(original)
                if record.get("family") == 6:
                    try:
                        address = str(IPv6Address(record["address"]))
                    except (ValueError, TypeError, KeyError):
                        address = None
                    if address in known:
                        record["ndp_address"] = address
                        record["ndp_cross_reference"] = (
                            "independent_same_interface_ipv6_option_claim"
                        )
                        record["ndp_mac_variant_count"] = len(known[address])
                addresses.append(record)
            targets.append({**target, "addresses": addresses})
        services.append({**item, "targets": targets})
    return {**mdns, "services": services}
