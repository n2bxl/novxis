"""Timestamped DNS answer evidence, not DNS cache state or host discovery.

Only matched positive nontruncated DNS response answers are eligible.
Every record preserves its own observed TTL and its original packet
provenance through the correlated exchange. A freshness assessment is a
bounded interpretation of observed TTL, never proof of current DNS answers,
server authenticity, IP ownership or network reachability.
"""

from collections import deque
from dataclasses import dataclass
from decimal import Decimal

from novxis.events.dns_correlator import DNSExchangeCorrelated
from novxis.protocols.dns import DNSName, DNSResourceRecord

_SUPPORTED_TYPES = frozenset((1, 5, 12, 28))  # A, CNAME, PTR, AAAA
_DNS_IN = 1

type DNSRecordKey = tuple[
    str, bytes, bytes, tuple[bytes, ...], int, int, str
]


@dataclass(frozen=True, slots=True)
class DNSRecordEvidence:
    """One original DNS answer as observed in one matched exchange."""

    interface: str
    requester_ipv4: bytes
    resolver_ipv4: bytes
    record: DNSResourceRecord
    observed_at: Decimal
    source: DNSExchangeCorrelated

    @property
    def owner(self) -> DNSName:
        return self.record.name

    @property
    def value(self) -> str:
        """Decoded address or alias, without treating it as a host identity."""
        assert self.record.decoded_data is not None
        return self.record.decoded_data

    @property
    def record_type(self) -> int:
        return self.record.rtype

    @property
    def ttl_seconds(self) -> int:
        return self.record.ttl

    @property
    def expires_at(self) -> Decimal:
        """Observed reception timestamp plus the received TTL, in seconds."""
        return self.observed_at + Decimal(self.record.ttl)

    @property
    def key(self) -> DNSRecordKey:
        """Scoped RR identity, not a key for physical device identity."""
        return (
            self.interface,
            self.requester_ipv4,
            self.resolver_ipv4,
            tuple(label.lower() for label in self.owner.labels),
            self.record.rtype,
            self.record.rclass,
            self.value.lower(),
        )

    def is_fresh(self, as_of: Decimal) -> bool:
        """TTL not elapsed, as of a supplied timestamp on the capture clock."""
        if not as_of.is_finite():
            raise ValueError("as_of must be a finite Decimal timestamp")
        return (
            self.ttl_seconds > 0
            and self.observed_at <= as_of < self.expires_at
        )


class DNSRelationshipState:
    """Bounded history and latest-known DNS record observations.

    Records are keyed by interface, requester IP, resolver IP, RR owner,
    type, class, and value. Multiple addresses (or conflicting values)
    remain independent evidence, and unrelated resolvers are not collapsed.

    "Latest" is latest *observed* evidence for that exact key, not a
    simulation of the resolver's authoritative or recursive DNS cache.
    All query views are explicit-time to support deterministic PCAP replay.
    """

    def __init__(
        self, *, max_records: int = 2048, max_history: int = 4096
    ) -> None:
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records <= 0
        ):
            raise ValueError("max_records must be a positive integer")
        if (
            isinstance(max_history, bool)
            or not isinstance(max_history, int)
            or max_history <= 0
        ):
            raise ValueError("max_history must be a positive integer")
        self._max_records = max_records
        self._history: deque[DNSRecordEvidence] = deque(maxlen=max_history)
        self._latest: dict[DNSRecordKey, DNSRecordEvidence] = {}

    @property
    def history(self) -> tuple[DNSRecordEvidence, ...]:
        """Recent individual observations, including expired/old evidence."""
        return tuple(self._history)

    @property
    def latest_records(self) -> tuple[DNSRecordEvidence, ...]:
        """One most-recent observation per scoped RR; not a live DNS cache."""
        return tuple(self._latest.values())

    def fresh_records(self, as_of: Decimal) -> tuple[DNSRecordEvidence, ...]:
        """Return latest observations whose per-RR received TTL remains fresh."""
        if not as_of.is_finite():
            raise ValueError("as_of must be a finite Decimal timestamp")
        return tuple(
            evidence
            for evidence in self._latest.values()
            if evidence.is_fresh(as_of)
        )

    def observe_exchange(
        self, exchange: DNSExchangeCorrelated
    ) -> tuple[DNSRecordEvidence, ...]:
        """Record supported answers without claiming current reachability.

        Only positive (RCODE=0), non-truncated responses are used; NXDOMAIN,
        NODATA, SERVFAIL, and truncated messages don't create positive edges.
        Authority/additional sections are not imported. Unknown types,
        unsupported classes, and opaque/undecoded RDATA are ignored.
        TTL=0 records are retained as historical observations but never fresh.
        """
        response = exchange.response
        header = response.message.header
        if (
            not header.is_response
            or header.opcode != 0
            or header.response_code != 0
            or header.truncated
        ):
            return ()

        observed: list[DNSRecordEvidence] = []
        for rr in response.message.answers:
            if (
                rr.rclass != _DNS_IN
                or rr.rtype not in _SUPPORTED_TYPES
                or rr.decoded_data is None
            ):
                continue

            evidence = DNSRecordEvidence(
                interface=response.interface,
                requester_ipv4=exchange.request.ipv4.source,
                resolver_ipv4=response.ipv4.source,
                record=rr,
                observed_at=response.timestamp,
                source=exchange,
            )
            observed.append(evidence)
            self._history.append(evidence)
            previous = self._latest.get(evidence.key)
            if previous is None or evidence.observed_at >= previous.observed_at:
                self._latest[evidence.key] = evidence
                if len(self._latest) > self._max_records:
                    oldest_key = min(
                        self._latest,
                        key=lambda key: self._latest[key].observed_at,
                    )
                    del self._latest[oldest_key]
        return tuple(observed)
