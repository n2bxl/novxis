"""Bounded, interface-scoped IPv6 Neighbor Discovery evidence.

These are unverified packet assertions, NOT an OS neighbor cache, live
reachability, address assignment, physical device identity or topology.
NS SLLA belongs to the IPv6 *source*, not the queried target.
NA TLLA belongs to the advertised *target*, not necessarily its sender.
A DAD NS target is tentative. Missing/ambiguous LLA remains unlinked.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from decimal import Decimal
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from novxis.pipeline.ndp import NeighborDiscoveryObserved
from novxis.protocols.icmpv6_nd import (
    NeighborAdvertisement, NeighborSolicitation,
    SOURCE_LINK_LAYER_ADDRESS, TARGET_LINK_LAYER_ADDRESS,
)

NDClaimKind = Literal["ns_source_slla", "na_target_tlla"]
NDUnlinkedReason = Literal[
    "dad_tentative",
    "ns_missing_slla", "na_missing_tlla",
    "ns_ambiguous_slla", "na_ambiguous_tlla",
    "ns_non_ethernet_slla", "na_non_ethernet_tlla",
    "ns_unusable_slla", "na_unusable_tlla",
    "ns_nonunicast_source",
]


@dataclass(frozen=True, slots=True)
class NDAddressClaim:
    """One distinct IPv6/LLA/kind assertion on a single capture interface."""

    interface: str
    ipv6_address: bytes
    link_layer_address: bytes
    kind: NDClaimKind
    first_seen: Decimal
    last_seen: Decimal
    observation_count: int
    latest_observation: NeighborDiscoveryObserved


@dataclass(frozen=True, slots=True)
class NDUnlinkedObservation:
    """NDP packet evidence with no justified IPv6-to-Ethernet association."""

    interface: str
    source_address: bytes
    target_address: bytes
    reason: NDUnlinkedReason
    first_seen: Decimal
    last_seen: Decimal
    observation_count: int
    latest_observation: NeighborDiscoveryObserved


@dataclass(frozen=True, slots=True)
class NDStateSnapshot:
    """Bounded evidence summary; no computed liveness or trust verdict."""

    messages: int
    solicitations: int
    advertisements: int
    dad_probes: int
    claims: tuple[NDAddressClaim, ...]
    unlinked: tuple[NDUnlinkedObservation, ...]
    distinct_claim_addresses: int
    multiple_link_layer_addresses: int
    omitted_claims: int
    omitted_unlinked: int
    history_truncated: bool

    @property
    def truncated(self) -> bool:
        return bool(self.omitted_claims or self.omitted_unlinked
                    or self.history_truncated)


def _positive(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")


def _link_layer_candidate(
    observed: NeighborDiscoveryObserved,
    option_type: int,
) -> tuple[bytes | None, Literal[
    "missing", "ambiguous", "non_ethernet", "unusable",
] | None]:
    matches = [item for item in observed.message.options
               if item.option_type == option_type]
    if not matches:
        return None, "missing"
    if len(matches) != 1:
        return None, "ambiguous"
    value = matches[0].ethernet_address
    if value is None:
        return None, "non_ethernet"
    # Zero and multicast/group Ethernet addresses do not justify an
    # individual IPv6-to-unicast-link-layer association.
    if value == bytes(6) or value[0] & 1:
        return None, "unusable"
    return value, None


class NDNeighborEvidenceState:
    """Retain packet-derived NS/NA assertions, including contradictions.

    Distinct kinds and different claimed LLAs remain distinct; last-wins
    would discard uncertainty, even when a NA has Override=1.
    Limits bound retained history and distinct evidence entries.
    """

    def __init__(
        self, *, max_claims: int = 256, max_unlinked: int = 256,
        max_history: int = 512,
    ) -> None:
        for label, value in (
            ("max_claims", max_claims),
            ("max_unlinked", max_unlinked),
            ("max_history", max_history),
        ):
            _positive(value, label)
        self.max_claims = max_claims
        self.max_unlinked = max_unlinked
        self._history: deque[NeighborDiscoveryObserved] = deque(
            maxlen=max_history
        )
        self._history_truncated = False
        self._claims: dict[tuple, NDAddressClaim] = {}
        self._unlinked: dict[tuple, NDUnlinkedObservation] = {}
        self.messages = 0
        self.solicitations = 0
        self.advertisements = 0
        self.dad_probes = 0
        self.omitted_claims = 0
        self.omitted_unlinked = 0

    @property
    def history(self) -> tuple[NeighborDiscoveryObserved, ...]:
        return tuple(self._history)

    def observe(
        self, observed: NeighborDiscoveryObserved,
    ) -> NDAddressClaim | NDUnlinkedObservation:
        """Store a Stage 1 verified NS/NA; return its updated typed evidence."""
        # Lazy import avoids a state <-> pipeline package import cycle.
        from novxis.pipeline.ndp import NeighborDiscoveryObserved

        if not isinstance(observed, NeighborDiscoveryObserved):
            raise TypeError("expected verified NeighborDiscoveryObserved")
        at = observed.captured.timestamp
        if not isinstance(at, Decimal) or not at.is_finite():
            raise ValueError("NDP capture timestamp must be a finite Decimal")
        interface = observed.captured.interface
        if not isinstance(interface, str) or not interface:
            raise ValueError("NDP interface must be nonempty")
        msg = observed.message
        if not isinstance(msg, (NeighborSolicitation, NeighborAdvertisement)):
            raise TypeError("unsupported NDP message")

        # Determine evidence kind before mutating any retained state.
        if isinstance(msg, NeighborSolicitation):
            if msg.is_dad_probe:
                claim = None
                reason: NDUnlinkedReason = "dad_tentative"
            elif IPv6Address(msg.source).is_multicast:
                claim = None
                reason = "ns_nonunicast_source"
            else:
                candidate, rejected = _link_layer_candidate(
                    observed, SOURCE_LINK_LAYER_ADDRESS,
                )
                claim = ("ns_source_slla", msg.source, candidate) if candidate else None
                reason = {
                    "missing": "ns_missing_slla",
                    "ambiguous": "ns_ambiguous_slla",
                    "non_ethernet": "ns_non_ethernet_slla",
                    "unusable": "ns_unusable_slla",
                }.get(rejected, "ns_missing_slla")
        else:
            candidate, rejected = _link_layer_candidate(
                observed, TARGET_LINK_LAYER_ADDRESS,
            )
            claim = ("na_target_tlla", msg.target, candidate) if candidate else None
            reason = {
                "missing": "na_missing_tlla",
                "ambiguous": "na_ambiguous_tlla",
                "non_ethernet": "na_non_ethernet_tlla",
                "unusable": "na_unusable_tlla",
            }.get(rejected, "na_missing_tlla")

        self.messages += 1
        self.solicitations += int(isinstance(msg, NeighborSolicitation))
        self.advertisements += int(isinstance(msg, NeighborAdvertisement))
        self.dad_probes += int(
            isinstance(msg, NeighborSolicitation) and msg.is_dad_probe
        )
        if len(self._history) == self._history.maxlen:
            self._history_truncated = True
        self._history.append(observed)

        if claim is not None:
            kind, address, hardware = claim
            key = (interface, address, hardware, kind)
            prev = self._claims.get(key)
            latest = (
                observed if prev is None or at >= prev.last_seen
                else prev.latest_observation
            )
            value = NDAddressClaim(
                interface=interface, ipv6_address=address,
                link_layer_address=hardware, kind=kind,
                first_seen=min(prev.first_seen, at) if prev else at,
                last_seen=max(prev.last_seen, at) if prev else at,
                observation_count=prev.observation_count + 1 if prev else 1,
                latest_observation=latest,
            )
            self._claims[key] = value
            if len(self._claims) > self.max_claims:
                oldest = min(
                    self._claims,
                    key=lambda k: (self._claims[k].last_seen, k),
                )
                del self._claims[oldest]
                self.omitted_claims += 1
            return value

        # Preserve differing Ethernet frame senders as distinct packet
        # provenance, without treating the sender as the target's LLA.
        key = (
            interface, msg.source, msg.target, reason,
            observed.ethernet.source,
        )
        prev = self._unlinked.get(key)
        latest = (
            observed if prev is None or at >= prev.last_seen
            else prev.latest_observation
        )
        value = NDUnlinkedObservation(
            interface=interface, source_address=msg.source,
            target_address=msg.target, reason=reason,
            first_seen=min(prev.first_seen, at) if prev else at,
            last_seen=max(prev.last_seen, at) if prev else at,
            observation_count=prev.observation_count + 1 if prev else 1,
            latest_observation=latest,
        )
        self._unlinked[key] = value
        if len(self._unlinked) > self.max_unlinked:
            oldest = min(
                self._unlinked,
                key=lambda k: (self._unlinked[k].last_seen, k),
            )
            del self._unlinked[oldest]
            self.omitted_unlinked += 1
        return value

    def snapshot(self) -> NDStateSnapshot:
        """Deterministic, immutable view of retained packet observations."""
        claims = tuple(
            self._claims[key] for key in sorted(self._claims)
        )
        unlinked = tuple(
            self._unlinked[key] for key in sorted(self._unlinked)
        )
        by_address: dict[tuple[str, bytes], set[bytes]] = {}
        for item in claims:
            by_address.setdefault(
                (item.interface, item.ipv6_address), set()
            ).add(item.link_layer_address)
        return NDStateSnapshot(
            messages=self.messages,
            solicitations=self.solicitations,
            advertisements=self.advertisements,
            dad_probes=self.dad_probes,
            claims=claims, unlinked=unlinked,
            distinct_claim_addresses=len(by_address),
            # Conflicting assertions, NOT confirmed duplicate hosts.
            multiple_link_layer_addresses=sum(
                len(llas) > 1 for llas in by_address.values()
            ),
            omitted_claims=self.omitted_claims,
            omitted_unlinked=self.omitted_unlinked,
            history_truncated=self._history_truncated,
        )
