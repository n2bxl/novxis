"""Per-message DNS-SD advertisement projection, with no inferred host identity.

A service type is the native DNS-SD owner (e.g. _sample._tcp.local).
The related records are asserted *in this one mDNS response message*.
No response/query matching, historical cache, or inter-packet fusion exists.
"""

from dataclasses import dataclass

from novxis.events.mdns import MDNSMessageObserved
from novxis.protocols.dns import DNSName, read_dns_name_rdata
from novxis.protocols.dnssd import (
    DNSSDSRV, DNSSDTXT, parse_dnssd_srv, parse_dnssd_txt,
)
from novxis.protocols.mdns import MDNSRecord


@dataclass(frozen=True, slots=True)
class DNSSDTargetClaim:
    srv_record: MDNSRecord
    srv: DNSSDSRV
    address_records: tuple[MDNSRecord, ...]


@dataclass(frozen=True, slots=True)
class DNSSDTXTClaim:
    txt_record: MDNSRecord
    txt: DNSSDTXT


@dataclass(frozen=True, slots=True)
class DNSSDServiceAdvertisement:
    """Evidence relating one PTR assertion to records in the same response."""

    service_type: DNSName
    instance: DNSName
    ptr_record: MDNSRecord
    targets: tuple[DNSSDTargetClaim, ...]
    txt_records: tuple[DNSSDTXTClaim, ...]


def _labels(name: DNSName) -> tuple[bytes, ...]:
    # DNS names match ASCII case-insensitively; never normalize display labels.
    return tuple(label.lower() for label in name.labels)


def _is_service_type(name: DNSName) -> bool:
    labels = _labels(name)
    return (
        len(labels) == 3
        and labels[0].startswith(b"_")
        and len(labels[0]) > 1
        and labels[1] in (b"_tcp", b"_udp")
        and labels[2] == b"local"
    )


def project_dnssd_advertisements(
    observed: MDNSMessageObserved,
) -> tuple[DNSSDServiceAdvertisement, ...]:
    """Project typed relationships in one response only, preserving RR evidence.

    Known answers on queries MUST NOT become service advertisements.
    PTR-owner and PTR-target semantics are checked using raw DNS label
    boundaries, never splitting a string representation on dots.
    """
    message = observed.message
    if not message.is_response:
        return ()

    wire = observed.udp.payload
    records = tuple(r for r in message.records if r.record_class == 1)
    srvs = tuple(r for r in records if r.wire.rtype == 33)
    txts = tuple(r for r in records if r.wire.rtype == 16)
    addresses = tuple(r for r in records if r.wire.rtype in (1, 28))
    result: list[DNSSDServiceAdvertisement] = []
    for ptr in records:
        if ptr.wire.rtype != 12 or not _is_service_type(ptr.wire.name):
            continue

        instance = read_dns_name_rdata(
            wire,
            start=ptr.wire.rdata_offset,
            end=ptr.wire.rdata_offset + len(ptr.wire.rdata),
        )
        # A DNS-SD instance adds *one* label in front of the service type.
        # Generic reverse PTR or service-type enumeration is not an instance.
        if (
            len(instance.labels) != len(ptr.wire.name.labels) + 1
            or _labels(instance)[1:] != _labels(ptr.wire.name)
        ):
            continue

        matching_targets: list[DNSSDTargetClaim] = []
        for record in srvs:
            if _labels(record.wire.name) != _labels(instance):
                continue
            srv = parse_dnssd_srv(wire, record.wire)
            matching_addresses = tuple(
                addr for addr in addresses
                if _labels(addr.wire.name) == _labels(srv.target)
                and addr.wire.decoded_data is not None
            )
            matching_targets.append(DNSSDTargetClaim(
                srv_record=record, srv=srv,
                address_records=matching_addresses,
            ))
        matching_txt = tuple(
            DNSSDTXTClaim(txt_record=record, txt=parse_dnssd_txt(record.wire))
            for record in txts
            if _labels(record.wire.name) == _labels(instance)
        )
        result.append(
            DNSSDServiceAdvertisement(
                service_type=ptr.wire.name,
                instance=instance,
                ptr_record=ptr,
                targets=tuple(matching_targets),
                txt_records=matching_txt,
            )
        )
    return tuple(result)
