"""UI-neutral projection of DNS relationship evidence into immutable view data.

No console formatting, graphics dependencies, packet capture, clock reads,
or mutation of DNS evidence occurs here. Renderers consume the same snapshot.
"""

from dataclasses import dataclass
from decimal import Decimal
from ipaddress import IPv4Address
from typing import Literal

from novxis.state.dns import DNSRecordEvidence, DNSRelationshipState

DNSViewMode = Literal["latest", "history"]
DNSFreshness = Literal["fresh", "expired"]
DNSRelationKind = Literal["ipv4", "ipv6", "alias", "reverse_name"]

_KIND: dict[int, tuple[str, DNSRelationKind]] = {
    1: ("A", "ipv4"),
    28: ("AAAA", "ipv6"),
    5: ("CNAME", "alias"),
    12: ("PTR", "reverse_name"),
}


@dataclass(frozen=True, slots=True)
class DNSRelationshipView:
    """One factual DNS relationship, with TTL-relative freshness and source."""

    owner: str
    record_type: str
    relationship_kind: DNSRelationKind
    target: str
    freshness: DNSFreshness
    ttl_seconds: int
    remaining_seconds: Decimal
    observed_at: Decimal
    expires_at: Decimal
    interface: str
    requester_ipv4: str
    resolver_ipv4: str
    transaction_id: int


@dataclass(frozen=True, slots=True)
class DNSRelationshipSnapshot:
    """Stable read-only projection, directly consumable by any UI adapter."""

    as_of: Decimal
    mode: DNSViewMode
    relationships: tuple[DNSRelationshipView, ...]
    fresh_count: int
    expired_count: int


def _row(evidence: DNSRecordEvidence, as_of: Decimal) -> DNSRelationshipView:
    name, kind = _KIND[evidence.record_type]
    fresh = evidence.is_fresh(as_of)
    return DNSRelationshipView(
        owner=evidence.owner.text,
        record_type=name,
        relationship_kind=kind,
        target=evidence.value,
        freshness="fresh" if fresh else "expired",
        ttl_seconds=evidence.ttl_seconds,
        remaining_seconds=(
            max(Decimal(0), evidence.expires_at - as_of) if fresh else Decimal(0)
        ),
        observed_at=evidence.observed_at,
        expires_at=evidence.expires_at,
        interface=evidence.interface,
        requester_ipv4=str(IPv4Address(evidence.requester_ipv4)),
        resolver_ipv4=str(IPv4Address(evidence.resolver_ipv4)),
        transaction_id=evidence.source.request.message.header.transaction_id,
    )


def project_dns_relationships(
    state: DNSRelationshipState,
    *,
    as_of: Decimal,
    mode: DNSViewMode = "latest",
) -> DNSRelationshipSnapshot:
    """Produce a bounded, deterministic view as of an explicit capture time.

    'latest' means the most recent observation for each *scoped record key*
    at or before as_of, rather than the resolver's current RRset. 'history'
    exposes each retained observation up to that time. The bounded state may
    have evicted old history, so arbitrary past-time reconstruction is not
    guaranteed complete.
    """
    if not isinstance(as_of, Decimal) or not as_of.is_finite():
        raise ValueError("as_of must be a finite Decimal timestamp")
    if mode not in ("latest", "history"):
        raise ValueError("mode must be 'latest' or 'history'")

    eligible = tuple(
        record for record in state.history
        if record.observed_at <= as_of
    )
    if mode == "latest":
        # Respect the state layer's latest-record capacity at present/future
        # timestamps. A past-time view reconstructs a best-effort snapshot
        # from bounded retained history instead; evicted history cannot be
        # reconstructed.
        latest = state.latest_records
        if not latest or as_of >= max(item.observed_at for item in latest):
            evidence_rows = latest
        else:
            by_key = {}
            for evidence in eligible:
                previous = by_key.get(evidence.key)
                if previous is None or evidence.observed_at >= previous.observed_at:
                    by_key[evidence.key] = evidence
            evidence_rows = tuple(by_key.values())
    else:
        evidence_rows = eligible

    # Deterministic ordering independent of arrival order / dictionary order.
    evidence_rows = tuple(sorted(
        evidence_rows,
        key=lambda item: (
            item.owner.text.lower(), item.record_type, item.value.lower(),
            item.interface, item.requester_ipv4, item.resolver_ipv4,
            item.observed_at,
        ),
    ))
    rows = tuple(_row(record, as_of) for record in evidence_rows)
    fresh_count = sum(row.freshness == "fresh" for row in rows)
    return DNSRelationshipSnapshot(
        as_of=as_of,
        mode=mode,
        relationships=rows,
        fresh_count=fresh_count,
        expired_count=len(rows) - fresh_count,
    )
