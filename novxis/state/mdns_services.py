"""Bounded, TTL-aware observations of native DNS-SD service instances.

This is NOT the system's mDNS cache, a list of connected devices, nor a
trusted inventory. Only PTR-backed, same-message 1M-C service projections
are imported. Repeated IPv4/IPv6 observations can update one service
instance scoped to the capture interface and native DNS labels.

All times use the capture's Decimal clock, never wall-clock time. Each
record has its own TTL and semantic identity so different on-wire DNS
compression choices do not manufacture different endpoint records.
"""

from collections import deque
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Literal

from novxis.events.mdns import MDNSMessageObserved
from novxis.protocols.dns import DNSName
from novxis.protocols.dnssd import DNSSDSRV, DNSSDTXT
from novxis.protocols.mdns import MDNSRecord
from novxis.views.mdns_services import DNSSDServiceAdvertisement

type ServiceKey = tuple[str, tuple[bytes, ...], tuple[bytes, ...]]
type RecordKey = tuple[object, ...]
type RecordKind = Literal["PTR", "SRV", "TXT", "A", "AAAA"]


def _name_key(name: DNSName) -> tuple[bytes, ...]:
    return tuple(label.lower() for label in name.labels)


def _positive_int(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _timestamp(value: Decimal, name: str) -> None:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValueError(f"{name} must be a finite Decimal timestamp")


@dataclass(frozen=True, slots=True)
class MDNSServiceRecordEvidence:
    """One typed DNS-SD RR observation, with the entire source packet."""

    kind: RecordKind
    record: MDNSRecord
    value: DNSName | DNSSDSRV | DNSSDTXT | str
    observed_at: Decimal
    source: MDNSMessageObserved

    @property
    def expires_at(self) -> Decimal:
        return self.observed_at + Decimal(self.record.wire.ttl)

    @property
    def key(self) -> RecordKey:
        """Semantic RR identity independent of DNS compression and case.

        Conflicting SRV values retain independent record identities. The
        cache-flush bit is packet evidence, not permission to delete other
        contradictory records in this observational state model.
        """
        prefix: RecordKey = (
            self.kind, _name_key(self.record.wire.name),
            self.record.record_class,
        )
        if self.kind == "PTR":
            assert isinstance(self.value, DNSName)
            return prefix + (_name_key(self.value),)
        if self.kind == "SRV":
            assert isinstance(self.value, DNSSDSRV)
            srv = self.value
            return prefix + (
                _name_key(srv.target), srv.priority, srv.weight, srv.port,
            )
        if self.kind == "TXT":
            # Preserve arbitrary TXT bytes including empty vs absent values.
            return prefix + (self.record.wire.rdata,)
        return prefix + (self.record.wire.rdata,)

    def is_fresh(self, as_of: Decimal) -> bool:
        _timestamp(as_of, "as_of")
        return (
            self.record.wire.ttl > 0
            and self.observed_at <= as_of < self.expires_at
        )


@dataclass(frozen=True, slots=True)
class MDNSServiceObservation:
    """One PTR-backed advertisement observed in one original packet."""

    source: MDNSMessageObserved
    advertisement: DNSSDServiceAdvertisement


@dataclass(frozen=True, slots=True)
class MDNSServiceInstanceSnapshot:
    """Immutable snapshot, not verified live service or device identity."""

    interface: str
    service_type: DNSName
    instance: DNSName
    first_seen: Decimal
    last_seen: Decimal
    observation_count: int
    latest_records: tuple[MDNSServiceRecordEvidence, ...]
    fresh_records: tuple[MDNSServiceRecordEvidence, ...]
    as_of: Decimal

    @property
    def has_fresh_ptr(self) -> bool:
        return any(record.kind == "PTR" for record in self.fresh_records)

    @property
    def fresh_targets(self) -> tuple[MDNSServiceRecordEvidence, ...]:
        return tuple(r for r in self.fresh_records if r.kind == "SRV")

    @property
    def fresh_addresses(self) -> tuple[MDNSServiceRecordEvidence, ...]:
        return tuple(
            r for r in self.fresh_records if r.kind in ("A", "AAAA")
        )

    @property
    def has_conflicting_fresh_srv(self) -> bool:
        return len(self.fresh_targets) > 1


@dataclass(slots=True)
class _Instance:
    service_type: DNSName
    instance: DNSName
    interface: str
    first_seen: Decimal
    last_seen: Decimal
    observations: int = 0
    latest: dict[RecordKey, MDNSServiceRecordEvidence] = field(
        default_factory=dict
    )


class MDNSServiceEvidenceState:
    """Bounded per-interface service-instance and latest-RR observations.

    Ingest each original PTR-backed projected advertisement once. We do not
    merge different interfaces or infer a device from matching service names.
    No service advertisement is imported from queries or standalone SRV/A
    messages without a PTR. This is a conservative first aggregation slice.
    """

    def __init__(
        self, *, max_instances: int = 256,
        max_records_per_instance: int = 128, max_history: int = 4096,
    ) -> None:
        _positive_int(max_instances, "max_instances")
        _positive_int(max_records_per_instance, "max_records_per_instance")
        _positive_int(max_history, "max_history")
        self._max_instances = max_instances
        self._max_records_per_instance = max_records_per_instance
        self._history: deque[MDNSServiceObservation] = deque(maxlen=max_history)
        self._instances: dict[ServiceKey, _Instance] = {}
        self._last_event_time: Decimal | None = None

    @property
    def history(self) -> tuple[MDNSServiceObservation, ...]:
        return tuple(self._history)

    @property
    def instance_count(self) -> int:
        return len(self._instances)

    @property
    def latest_observed_at(self) -> Decimal | None:
        return self._last_event_time

    def observe(
        self,
        source: MDNSMessageObserved,
        advertisement: DNSSDServiceAdvertisement,
    ) -> None:
        """Record a PTR-backed projection and each linked RR independently."""
        if not source.message.is_response:
            raise ValueError("Cannot record query-side service advertisements")
        _timestamp(source.timestamp, "source timestamp")
        if advertisement.ptr_record.role not in (
            "response_answer", "response_additional", "response_authority"
        ):
            raise ValueError("PTR must originate from an mDNS response")
        key: ServiceKey = (
            source.interface,
            _name_key(advertisement.service_type),
            _name_key(advertisement.instance),
        )
        entry = self._instances.get(key)
        if entry is None:
            entry = _Instance(
                service_type=advertisement.service_type,
                instance=advertisement.instance,
                interface=source.interface,
                first_seen=source.timestamp,
                last_seen=source.timestamp,
            )
            self._instances[key] = entry
        else:
            entry.first_seen = min(entry.first_seen, source.timestamp)
            entry.last_seen = max(entry.last_seen, source.timestamp)
        entry.observations += 1
        self._history.append(MDNSServiceObservation(source, advertisement))
        if self._last_event_time is None or source.timestamp > self._last_event_time:
            self._last_event_time = source.timestamp

        def add(kind: RecordKind, record: MDNSRecord,
                value: DNSName | DNSSDSRV | DNSSDTXT | str) -> None:
            ev = MDNSServiceRecordEvidence(
                kind=kind, record=record, value=value,
                observed_at=source.timestamp, source=source,
            )
            existing = entry.latest.get(ev.key)
            if existing is None or ev.observed_at >= existing.observed_at:
                entry.latest[ev.key] = ev
            if len(entry.latest) > self._max_records_per_instance:
                oldest = min(
                    entry.latest,
                    key=lambda k: entry.latest[k].observed_at,
                )
                del entry.latest[oldest]

        add("PTR", advertisement.ptr_record, advertisement.instance)
        for target in advertisement.targets:
            add("SRV", target.srv_record, target.srv)
            for address in target.address_records:
                assert address.wire.decoded_data is not None
                kind: RecordKind = "A" if address.wire.rtype == 1 else "AAAA"
                add(kind, address, address.wire.decoded_data)
        for item in advertisement.txt_records:
            add("TXT", item.txt_record, item.txt)

        if len(self._instances) > self._max_instances:
            oldest_key = min(
                self._instances,
                key=lambda k: self._instances[k].last_seen,
            )
            del self._instances[oldest_key]

    def snapshots(
        self, as_of: Decimal,
    ) -> tuple[MDNSServiceInstanceSnapshot, ...]:
        """Take an explicit-time snapshot after the last ingested observation.

        Earlier-than-last observation time is rejected because bounded
        'latest' evidence cannot reconstruct arbitrary historical states.
        TTL expiry is assessed per record, never inferred from device reachability.
        """
        _timestamp(as_of, "as_of")
        if self._last_event_time is not None and as_of < self._last_event_time:
            raise ValueError("as_of precedes latest ingested observation")
        result: list[MDNSServiceInstanceSnapshot] = []
        for entry in self._instances.values():
            latest = tuple(entry.latest.values())
            result.append(MDNSServiceInstanceSnapshot(
                interface=entry.interface,
                service_type=entry.service_type,
                instance=entry.instance,
                first_seen=entry.first_seen,
                last_seen=entry.last_seen,
                observation_count=entry.observations,
                latest_records=latest,
                fresh_records=tuple(r for r in latest if r.is_fresh(as_of)),
                as_of=as_of,
            ))
        return tuple(sorted(
            result,
            key=lambda s: (
                s.interface, _name_key(s.service_type), _name_key(s.instance)
            ),
        ))
