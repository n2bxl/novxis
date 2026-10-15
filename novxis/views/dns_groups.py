"""Read-only, UI-independent grouping of observed DNS relationships.

This layer groups *evidence* for navigation and presentation. It does not
resolve DNS, assert a current RRset, merge client/resolver scopes, or infer
physical links. Each input relationship appears in exactly one group.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

from novxis.views.dns_relationships import (
    DNSRelationshipSnapshot,
    DNSRelationshipView,
    DNSViewMode,
)

DNSGroupKind = Literal["forward", "reverse"]


@dataclass(frozen=True, slots=True)
class DNSRelationshipGroup:
    """A connected naming component within one observed DNS client scope."""

    kind: DNSGroupKind
    interface: str
    requester_ipv4: str
    resolver_ipv4: str
    roots: tuple[str, ...]
    nodes: tuple[str, ...]
    relationships: tuple[DNSRelationshipView, ...]
    has_alias_cycle: bool
    has_address_evidence: bool

    @property
    def fresh_count(self) -> int:
        return sum(row.freshness == "fresh" for row in self.relationships)

    @property
    def expired_count(self) -> int:
        return len(self.relationships) - self.fresh_count


@dataclass(frozen=True, slots=True)
class DNSGroupedSnapshot:
    """Immutable groups with the original snapshot's clock and totals."""

    as_of: Decimal
    mode: DNSViewMode
    groups: tuple[DNSRelationshipGroup, ...]
    relationship_count: int
    fresh_count: int
    expired_count: int


def _key(text: str) -> str:
    """ASCII-insensitive DNS name comparison, without modifying wire evidence."""
    return text.lower()


def _row_sort(row: DNSRelationshipView) -> tuple:
    return (
        row.owner.lower(), row.record_type, row.target.lower(),
        row.observed_at, row.expires_at, row.transaction_id,
    )


def _forward_groups(
    scope: tuple[str, str, str],
    rows: tuple[DNSRelationshipView, ...],
) -> list[DNSRelationshipGroup]:
    # A CNAME links two *names*, whereas A/AAAA targets are IP literals.
    # PTR is deliberately excluded from this forward-name graph.
    names: set[str] = set()
    neighbors: dict[str, set[str]] = defaultdict(set)
    directed: dict[str, set[str]] = defaultdict(set)
    by_owner: dict[str, list[DNSRelationshipView]] = defaultdict(list)

    for row in rows:
        owner = _key(row.owner)
        names.add(owner)
        by_owner[owner].append(row)
        if row.relationship_kind == "alias":
            target = _key(row.target)
            names.add(target)
            neighbors[owner].add(target)
            neighbors[target].add(owner)
            directed[owner].add(target)

    remaining = set(names)
    groups: list[DNSRelationshipGroup] = []
    while remaining:
        # Only observed CNAME links can connect separate name owners.
        start = min(remaining)
        visited = {start}
        queue = deque([start])
        while queue:
            name = queue.popleft()
            for neighbor in sorted(neighbors[name]):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        remaining.difference_update(visited)

        indegree = {node: 0 for node in visited}
        for owner in visited:
            for target in directed[owner]:
                if target in indegree:
                    indegree[target] += 1

        # Kahn's algorithm detects a directed alias cycle without recursion.
        indegree_work = dict(indegree)
        ready = deque(sorted(
            node for node, degree in indegree_work.items() if degree == 0
        ))
        removed = 0
        while ready:
            node = ready.popleft()
            removed += 1
            for target in sorted(directed[node]):
                indegree_work[target] -= 1
                if indegree_work[target] == 0:
                    ready.append(target)
        cyclic = removed != len(visited)

        roots = tuple(sorted(
            node for node in visited
            if indegree[node] == 0 and node in by_owner
        ))
        # Name-depth is an ordering hint only, not a network distance.
        depth: dict[str, int] = {}
        seeds = roots if roots else (min(visited),)
        queue = deque((root, 0) for root in seeds)
        while queue:
            name, level = queue.popleft()
            if name in depth and depth[name] <= level:
                continue
            depth[name] = level
            for target in sorted(directed[name]):
                queue.append((target, level + 1))

        component_rows = [
            row for name in visited for row in by_owner[name]
        ]
        component_rows.sort(key=lambda row: (
            depth.get(_key(row.owner), len(visited)),
            0 if row.relationship_kind == "alias" else 1,
            *_row_sort(row),
        ))
        groups.append(DNSRelationshipGroup(
            kind="forward",
            interface=scope[0],
            requester_ipv4=scope[1],
            resolver_ipv4=scope[2],
            roots=roots,
            nodes=tuple(sorted(visited)),
            relationships=tuple(component_rows),
            has_alias_cycle=cyclic,
            has_address_evidence=any(
                row.relationship_kind in ("ipv4", "ipv6")
                for row in component_rows
            ),
        ))
    return groups


def _reverse_groups(
    scope: tuple[str, str, str],
    rows: tuple[DNSRelationshipView, ...],
) -> list[DNSRelationshipGroup]:
    # PTR -> name is reverse evidence, never a CNAME hop.
    by_owner: dict[str, list[DNSRelationshipView]] = defaultdict(list)
    for row in rows:
        by_owner[_key(row.owner)].append(row)
    return [
        DNSRelationshipGroup(
            kind="reverse",
            interface=scope[0],
            requester_ipv4=scope[1],
            resolver_ipv4=scope[2],
            roots=(owner,),
            nodes=(owner,),
            relationships=tuple(sorted(owner_rows, key=_row_sort)),
            has_alias_cycle=False,
            has_address_evidence=False,
        )
        for owner, owner_rows in sorted(by_owner.items())
    ]


def group_dns_relationships(
    snapshot: DNSRelationshipSnapshot,
) -> DNSGroupedSnapshot:
    """Partition a snapshot into scoped forward chains and reverse-name groups.

    Shared CNAME targets yield a group with multiple roots. Missing links,
    contradictory alias observations and cycles remain visible evidence, not
    silently repaired or interpreted as a valid current DNS resolution.
    History mode retains repeated observations individually.
    """
    scopes: dict[
        tuple[str, str, str], list[DNSRelationshipView]
    ] = defaultdict(list)
    for row in snapshot.relationships:
        scopes[(row.interface, row.requester_ipv4, row.resolver_ipv4)].append(row)

    groups: list[DNSRelationshipGroup] = []
    for scope, scoped in sorted(scopes.items()):
        forward = tuple(
            row for row in scoped
            if row.relationship_kind in ("ipv4", "ipv6", "alias")
        )
        reverse = tuple(
            row for row in scoped if row.relationship_kind == "reverse_name"
        )
        groups.extend(_forward_groups(scope, forward))
        groups.extend(_reverse_groups(scope, reverse))

    groups.sort(key=lambda group: (
        group.interface, group.requester_ipv4, group.resolver_ipv4,
        group.kind, group.roots, group.nodes,
    ))
    flattened = tuple(
        row for group in groups for row in group.relationships
    )
    # The projection is a partition: no input observation can disappear
    # or multiply when alias chains are grouped.
    assert len(flattened) == len(snapshot.relationships)
    return DNSGroupedSnapshot(
        as_of=snapshot.as_of,
        mode=snapshot.mode,
        groups=tuple(groups),
        relationship_count=len(flattened),
        fresh_count=sum(row.freshness == "fresh" for row in flattened),
        expired_count=sum(row.freshness == "expired" for row in flattened),
    )
