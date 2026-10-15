"""Pure DNS chain grouping: no packet parsing or network-state mutation."""

from dataclasses import replace
from decimal import Decimal

import pytest

from novxis.presentation.dns_group_console import format_dns_grouped_snapshot
from novxis.views.dns_groups import group_dns_relationships
from novxis.views.dns_relationships import (
    DNSRelationshipSnapshot,
    DNSRelationshipView,
)

AS_OF = Decimal("120")


def _row(
    owner: str, record_type: str, target: str,
    *, ttl: int = 60, observed: str = "100",
    interface: str = "en0", requester: str = "192.0.2.10",
    resolver: str = "198.51.100.53", txid: int = 0x100,
) -> DNSRelationshipView:
    kind = {
        "A": "ipv4", "AAAA": "ipv6",
        "CNAME": "alias", "PTR": "reverse_name",
    }[record_type]
    stamp = Decimal(observed)
    expires = stamp + ttl
    fresh = ttl > 0 and stamp <= AS_OF < expires
    return DNSRelationshipView(
        owner=owner, record_type=record_type, relationship_kind=kind,
        target=target, freshness="fresh" if fresh else "expired",
        ttl_seconds=ttl,
        remaining_seconds=max(Decimal(0), expires - AS_OF) if fresh else Decimal(0),
        observed_at=stamp, expires_at=expires, interface=interface,
        requester_ipv4=requester, resolver_ipv4=resolver,
        transaction_id=txid,
    )


def _snapshot(*rows: DNSRelationshipView, mode="latest"):
    return DNSRelationshipSnapshot(
        as_of=AS_OF, mode=mode, relationships=rows,
        fresh_count=sum(r.freshness == "fresh" for r in rows),
        expired_count=sum(r.freshness == "expired" for r in rows),
    )


def test_ordered_cname_chain_and_multiple_address_answers_one_group():
    rows = (
        _row("backend.example.test", "A", "192.0.2.5", ttl=2),
        _row("edge.example.test", "CNAME", "backend.example.test", ttl=300),
        _row("backend.example.test", "AAAA", "2001:db8::5", ttl=90),
        _row("start.example.test", "CNAME", "edge.example.test", ttl=180),
        _row("backend.example.test", "A", "192.0.2.6", ttl=90),
    )
    grouped = group_dns_relationships(_snapshot(*rows))
    assert grouped.relationship_count == len(rows)
    assert (grouped.fresh_count, grouped.expired_count) == (4, 1)
    assert len(grouped.groups) == 1
    group = grouped.groups[0]
    assert group.kind == "forward"
    assert group.roots == ("start.example.test",)
    assert group.nodes == (
        "backend.example.test", "edge.example.test", "start.example.test",
    )
    assert [r.owner for r in group.relationships][:2] == [
        "start.example.test", "edge.example.test",
    ]
    assert group.has_alias_cycle is False
    assert group.has_address_evidence is True
    assert group.expired_count == 1
    assert set(group.relationships) == set(rows)


def test_shared_target_has_two_roots_without_duplicating_address():
    rows = (
        _row("one.example.test", "CNAME", "shared.example.test"),
        _row("two.example.test", "CNAME", "shared.example.test"),
        _row("shared.example.test", "A", "192.0.2.9"),
    )
    grouped = group_dns_relationships(_snapshot(*rows))
    assert len(grouped.groups) == 1
    assert grouped.groups[0].roots == ("one.example.test", "two.example.test")
    assert len(grouped.groups[0].relationships) == 3
    assert grouped.relationship_count == 3


def test_scopes_never_join_even_for_same_cname_and_names():
    row = _row("alias.example.test", "CNAME", "target.example.test")
    scoped = (
        row,
        replace(row, resolver_ipv4="203.0.113.53"),
        replace(row, requester_ipv4="192.0.2.99"),
        replace(row, interface="en5"),
    )
    grouped = group_dns_relationships(_snapshot(*scoped))
    assert len(grouped.groups) == 4
    assert all(len(group.relationships) == 1 for group in grouped.groups)
    assert grouped.relationship_count == 4


def test_ptr_stays_reverse_and_does_not_merge_with_a_cname_target():
    rows = (
        _row("1.2.0.192.in-addr.arpa", "PTR", "service.example.test"),
        _row("service.example.test", "A", "192.0.2.1"),
    )
    grouped = group_dns_relationships(_snapshot(*rows))
    assert len(grouped.groups) == 2
    assert {g.kind for g in grouped.groups} == {"reverse", "forward"}
    assert grouped.relationship_count == 2


def test_cycles_do_not_hang_and_all_aliases_are_kept():
    rows = (
        _row("a.example.test", "CNAME", "b.example.test"),
        _row("b.example.test", "CNAME", "c.example.test"),
        _row("c.example.test", "CNAME", "a.example.test"),
    )
    grouped = group_dns_relationships(_snapshot(*rows))
    assert len(grouped.groups) == 1
    assert grouped.groups[0].has_alias_cycle is True
    assert grouped.groups[0].roots == ()
    assert len(grouped.groups[0].relationships) == len(rows)
    assert "alias_cycle=1" in format_dns_grouped_snapshot(grouped)


def test_self_alias_is_flagged_as_cycle():
    grouped = group_dns_relationships(_snapshot(
        _row("same.example.test", "CNAME", "same.example.test")
    ))
    assert grouped.groups[0].has_alias_cycle


def test_missing_cname_target_remains_incomplete_without_synthetic_a():
    grouped = group_dns_relationships(_snapshot(
        _row("alias.example.test", "CNAME", "unknown.example.test")
    ))
    assert len(grouped.groups) == 1
    group = grouped.groups[0]
    assert group.roots == ("alias.example.test",)
    assert group.nodes == ("alias.example.test", "unknown.example.test")
    assert group.has_address_evidence is False
    assert group.relationships[0].target == "unknown.example.test"


def test_conflicting_cname_targets_remain_observations_not_choice_of_truth():
    rows = (
        _row("service.example.test", "CNAME", "one.example.test", txid=11),
        _row("service.example.test", "CNAME", "two.example.test", txid=12),
    )
    grouped = group_dns_relationships(_snapshot(*rows))
    assert len(grouped.groups) == 1
    assert set(grouped.groups[0].relationships) == set(rows)
    assert grouped.groups[0].roots == ("service.example.test",)


def test_history_mode_preserves_duplicate_observations():
    older = _row("same.example.test", "A", "192.0.2.1", txid=1)
    newer = replace(
        older, observed_at=Decimal("105"), expires_at=Decimal("165"),
        remaining_seconds=Decimal("45"), transaction_id=2,
    )
    grouped = group_dns_relationships(_snapshot(older, newer, mode="history"))
    assert grouped.mode == "history"
    assert len(grouped.groups) == 1
    assert len(grouped.groups[0].relationships) == 2
    assert grouped.relationship_count == 2
    assert {r.transaction_id for r in grouped.groups[0].relationships} == {1, 2}


def test_name_matching_is_case_insensitive_without_modifying_wire_case():
    rows = (
        _row("LOUD.Example.Test", "CNAME", "target.example.test"),
        _row("TARGET.EXAMPLE.TEST", "A", "192.0.2.1"),
    )
    grouped = group_dns_relationships(_snapshot(*rows))
    assert len(grouped.groups) == 1
    assert {r.owner for r in grouped.groups[0].relationships} == {
        "LOUD.Example.Test", "TARGET.EXAMPLE.TEST",
    }


def test_grouping_is_deterministic_and_conserves_counts():
    rows = (
        _row("a.example.test", "CNAME", "b.example.test"),
        _row("b.example.test", "A", "192.0.2.1", ttl=2),
        _row("zzz.example.test", "A", "192.0.2.2"),
        _row("1.2.0.192.in-addr.arpa", "PTR", "b.example.test"),
    )
    first = group_dns_relationships(_snapshot(*rows))
    second = group_dns_relationships(_snapshot(*reversed(rows)))
    assert first == second
    assert sum(len(g.relationships) for g in first.groups) == len(rows)
    assert first.relationship_count == 4
    assert (first.fresh_count, first.expired_count) == (3, 1)


def test_empty_snapshot_and_console_are_safe():
    grouped = group_dns_relationships(_snapshot())
    assert grouped.groups == ()
    assert grouped.relationship_count == 0
    text = format_dns_grouped_snapshot(grouped)
    assert "groups=0" in text
    assert "No supported correlated DNS relationship groups" in text


def test_console_preserves_provenance_per_record_and_scope():
    grouped = group_dns_relationships(_snapshot(
        _row("alias.example.test", "CNAME", "edge.example.test"),
        _row("edge.example.test", "A", "192.0.2.20", ttl=2),
    ))
    rendered = format_dns_grouped_snapshot(grouped)
    assert "roots=alias.example.test" in rendered
    assert "alias.example.test --CNAME--> edge.example.test" in rendered
    assert "edge.example.test --A--> 192.0.2.20" in rendered
    assert "[EXPIRED]" in rendered
    assert "resolver=198.51.100.53" in rendered
    assert "requester=192.0.2.10" in rendered
    assert "dns_id=0x0100" in rendered
    assert "not physical topology" in rendered


def test_future_unsupported_relationship_type_fails_loudly():
    new_type = replace(
        _row("example.test", "A", "192.0.2.1"),
        relationship_kind="service",
    )
    with pytest.raises(ValueError, match="Unsupported DNS relationship kind"):
        group_dns_relationships(_snapshot(new_type))
