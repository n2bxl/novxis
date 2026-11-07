"""Bounded, typed NDP observation metadata for a local-only NDJSON pipe.

Capture/packet bytes and ICMPv6 option data never cross the privilege
boundary. The original Stage 2 evidence model decides which option
supports an address claim, not the unprivileged browser.
"""

from ipaddress import IPv6Address

from novxis.state.ndp import NDAddressClaim


def ndp_message(result) -> dict:
    """Export a single NS/NA observation without inventing an IPv6 host."""
    observed, evidence = result.observation, result.evidence
    msg = observed.message
    claimed = isinstance(evidence, NDAddressClaim)
    return {
        "type": "ndp",
        "interface": observed.captured.interface,
        "observed_at": str(observed.captured.timestamp),
        "message_type": "ns" if msg.type == 135 else "na",
        "source_ipv6": str(IPv6Address(msg.source)),
        "target_ipv6": str(IPv6Address(msg.target)),
        # Separate frame sender provenance; never the target's MAC.
        "frame_source_hex": observed.ethernet.source.hex(),
        "claim_kind": evidence.kind if claimed else None,
        "claim_ipv6": str(IPv6Address(evidence.ipv6_address)) if claimed else None,
        "claim_mac_hex": evidence.link_layer_address.hex() if claimed else None,
        "unlinked_reason": None if claimed else evidence.reason,
        "dad": bool(getattr(msg, "is_dad_probe", False)),
    }
