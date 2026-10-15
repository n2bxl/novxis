"""Console adapter for grouped DNS evidence; no parsing or topology changes."""

from novxis.views.dns_groups import DNSGroupedSnapshot


def format_dns_grouped_snapshot(snapshot: DNSGroupedSnapshot) -> str:
    """Display grouped evidence without asserting current DNS resolution."""
    lines = [
        "NOVXIS grouped DNS evidence (observed naming, not physical topology)",
        (
            f"as_of={snapshot.as_of}s mode={snapshot.mode} "
            f"groups={len(snapshot.groups)} "
            f"relationships={snapshot.relationship_count} "
            f"fresh={snapshot.fresh_count} expired={snapshot.expired_count}"
        ),
    ]
    if not snapshot.groups:
        lines.append("  No supported correlated DNS relationship groups observed.")

    for group in snapshot.groups:
        root_label = ", ".join(group.roots) or "(no root observed)"
        lines.append(
            f"\n  {group.kind.upper()} names={len(group.nodes)} "
            f"roots={root_label} "
            f"records={len(group.relationships)} "
            f"fresh={group.fresh_count} expired={group.expired_count} "
            f"alias_cycle={int(group.has_alias_cycle)} "
            f"address_observed={int(group.has_address_evidence)}"
        )
        lines.append(
            f"    scope: interface={group.interface} "
            f"requester={group.requester_ipv4} resolver={group.resolver_ipv4}"
        )
        for row in group.relationships:
            lines.append(
                f"    [{row.freshness.upper()}] "
                f"{row.owner} --{row.record_type}--> {row.target} "
                f"ttl={row.ttl_seconds}s remaining={row.remaining_seconds:.3f}s "
                f"observed={row.observed_at}s dns_id=0x{row.transaction_id:04x}"
            )

    lines.append(
        "\nGroups are observational naming associations, not verified current "
        "RRsets, packet routes, physical links, or reachable devices. "
        "Expired edges remain historical evidence."
    )
    return "\n".join(lines)


def print_dns_grouped_snapshot(snapshot: DNSGroupedSnapshot) -> None:
    print(format_dns_grouped_snapshot(snapshot))
