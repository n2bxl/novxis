"""Opt-in, bounded cross-response DNS-SD evidence reconstruction.

This overlay never alters the Phase 1M-D-A per-PTR state. It holds only
typed RR evidence from mDNS response messages with no PTR-backed service
projection and resolves it at an explicit capture-clock snapshot time.

A shared hostname is *not* a physical device identity. Joining requires
a fresh service-type PTR, an exactly matching service-instance SRV/TXT
owner, and for A/AAAA a fresh SRV target name on the same interface.
"""

from collections import deque
from dataclasses import dataclass
from decimal import Decimal

from novxis.events.mdns import MDNSMessageObserved
from novxis.protocols.dns import DNSName
from novxis.protocols.dnssd import parse_dnssd_srv, parse_dnssd_txt
from novxis.state.mdns_services import (
    MDNSServiceEvidenceState, MDNSServiceInstanceSnapshot,
    MDNSServiceRecordEvidence, _name_key, _positive_int, _timestamp,
)
from novxis.views.mdns_services import (
    DNSSDServiceAdvertisement, project_dnssd_advertisements,
)


@dataclass(frozen=True, slots=True)
class MDNSReconciledServiceSnapshot:
    """An immutable, explicitly labeled projection of cross-message facts."""

    snapshot: MDNSServiceInstanceSnapshot
    cross_message_records: tuple[MDNSServiceRecordEvidence, ...]


class MDNSServiceReconciliation:
    """Preserve orphan response RRs without guessing devices or software.

    Observations without a PTR may be seen before or after a PTR-bearing
    message. At snapshot time, only unexpired evidence with a matching
    raw DNS owner chain is associated, and all original source packets
    and record TTLs remain separately available.
    """

    def __init__(
        self, *, max_instances: int = 256,
        max_records_per_instance: int = 128,
        max_history: int = 4096,
        max_unassociated: int = 2048,
    ) -> None:
        _positive_int(max_unassociated, "max_unassociated")
        self.state = MDNSServiceEvidenceState(
            max_instances=max_instances,
            max_records_per_instance=max_records_per_instance,
            max_history=max_history,
        )
        self._unassociated: deque[MDNSServiceRecordEvidence] = deque(
            maxlen=max_unassociated
        )
        self._latest_message_time: Decimal | None = None

    @property
    def unassociated_count(self) -> int:
        return len(self._unassociated)

    def observe_message(
        self, source: MDNSMessageObserved,
        advertisements: tuple[DNSSDServiceAdvertisement, ...] | None = None,
    ) -> int:
        """Ingest one mDNS message; return count of PTR advertisements.

        Queries, including known-answer sections, cannot assert records.
        Message-local PTR projections are delegated unchanged to 1M-D-A.
        Only PTR-less responses contribute to the bounded orphan pool.
        """
        _timestamp(source.timestamp, "source timestamp")
        if (
            self._latest_message_time is None
            or source.timestamp > self._latest_message_time
        ):
            self._latest_message_time = source.timestamp
        if not source.message.is_response:
            return 0
        if advertisements is None:
            advertisements = project_dnssd_advertisements(source)
        if advertisements:
            for advertisement in advertisements:
                self.state.observe(source, advertisement)
            return len(advertisements)

        for record in source.message.records:
            if record.record_class != 1:
                continue
            wire = record.wire
            kind = {33: "SRV", 16: "TXT", 1: "A", 28: "AAAA"}.get(wire.rtype)
            if kind is None:
                continue
            if kind == "SRV":
                value = parse_dnssd_srv(source.udp.payload, wire)
            elif kind == "TXT":
                value = parse_dnssd_txt(wire)
            else:
                if wire.decoded_data is None:
                    continue
                value = wire.decoded_data
            self._unassociated.append(MDNSServiceRecordEvidence(
                kind=kind, record=record, value=value,
                observed_at=source.timestamp, source=source,
            ))
        return 0

    def snapshots(
        self, as_of: Decimal,
    ) -> tuple[MDNSReconciledServiceSnapshot, ...]:
        """Join only by fresh protocol name chain, never by string similarity."""
        _timestamp(as_of, "as_of")
        if (
            self._latest_message_time is not None
            and as_of < self._latest_message_time
        ):
            raise ValueError("as_of precedes latest observed message")
        bases = self.state.snapshots(as_of)
        results: list[MDNSReconciledServiceSnapshot] = []

        for base in bases:
            if not base.has_fresh_ptr:
                results.append(MDNSReconciledServiceSnapshot(base, ()))
                continue

            # One record identity may be advertised repeatedly in either
            # message stream. The latest observation for that semantic key
            # wins. TTL=0 replaces the same value without deleting history.
            merged = {record.key: record for record in base.latest_records}
            added: dict[tuple[object, ...], MDNSServiceRecordEvidence] = {}

            def try_add(record: MDNSServiceRecordEvidence) -> None:
                key = record.key
                previous = merged.get(key)
                if previous is not None and previous.observed_at >= record.observed_at:
                    return
                merged[key] = record
                added[key] = record

            # Service-instance exact owner match, scoped to capture
            # interface. Raw labels are ASCII case-insensitive.
            same_instance = [
                r for r in self._unassociated
                if r.source.interface == base.interface
                and r.observed_at <= as_of
                and r.expires_at > as_of
                and _name_key(r.record.wire.name) == _name_key(base.instance)
                and r.kind in ("SRV", "TXT")
            ]
            for record in same_instance:
                try_add(record)

            # A/AAAA can join only through currently fresh SRV target
            # names; never because sender IP or string keywords match.
            target_names = {
                _name_key(record.value.target)
                for record in merged.values()
                if record.kind == "SRV"
                and record.is_fresh(as_of)
            }
            for record in self._unassociated:
                if (
                    record.kind not in ("A", "AAAA")
                    or record.source.interface != base.interface
                    or record.observed_at > as_of
                    or record.expires_at <= as_of
                    or _name_key(record.record.wire.name) not in target_names
                ):
                    continue
                try_add(record)

            # Never promote an expired or zero-TTL record to a fresh fact.
            # Preserve base records as history; newly reconstructed RRs
            # remain separately marked in the immutable wrapper.
            combined = tuple(merged.values())
            snapshot = MDNSServiceInstanceSnapshot(
                interface=base.interface,
                service_type=base.service_type,
                instance=base.instance,
                first_seen=base.first_seen,
                last_seen=base.last_seen,
                observation_count=base.observation_count,
                latest_records=combined,
                fresh_records=tuple(
                    r for r in combined if r.is_fresh(as_of)
                ),
                as_of=as_of,
            )
            results.append(MDNSReconciledServiceSnapshot(
                snapshot=snapshot,
                cross_message_records=tuple(
                    r for key, r in added.items()
                    if merged.get(key) is r and r.is_fresh(as_of)
                ),
            ))
        return tuple(results)
