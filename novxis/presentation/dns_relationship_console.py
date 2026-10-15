"""Console-only formatting for UI-neutral DNS relationship snapshots.

Do not put terminal symbols or text-layout concerns into DNS evidence state
or the view-model projection. Other renderers can use the same snapshot.
"""

from novxis.views.dns_relationships import DNSRelationshipSnapshot


def format_dns_relationship_snapshot(snapshot: DNSRelationshipSnapshot) -> str:
    """Render an aggregated, deterministic, non-interactive text snapshot."""
    lines = [
        "NOVXIS DNS relationship evidence (not a DNS cache or physical topology)",
        (
            f"as_of={snapshot.as_of}s mode={snapshot.mode} "
            f"relationships={len(snapshot.relationships)} "
            f"fresh={snapshot.fresh_count} expired={snapshot.expired_count}"
        ),
    ]
    if not snapshot.relationships:
        lines.append("  No supported correlated DNS answer records observed in this view.")
    for relation in snapshot.relationships:
        lines.append(
            f"  [{relation.freshness.upper()}] "
            f"{relation.owner} --{relation.record_type}--> {relation.target} "
            f"ttl={relation.ttl_seconds}s "
            f"remaining={relation.remaining_seconds:.3f}s "
            f"observed={relation.observed_at}s "
            f"resolver={relation.resolver_ipv4} "
            f"requester={relation.requester_ipv4} "
            f"interface={relation.interface} "
            f"dns_id=0x{relation.transaction_id:04x}"
        )
    lines.append(
        "Freshness is relative to observed TTLs only; no reachability, "
        "DNS authenticity or hostname-to-device identity is asserted."
    )
    return "\n".join(lines)


def print_dns_relationship_snapshot(snapshot: DNSRelationshipSnapshot) -> None:
    print(format_dns_relationship_snapshot(snapshot))
