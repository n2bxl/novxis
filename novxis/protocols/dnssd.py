"""Capture-independent DNS-SD SRV/TXT RDATA interpretation.

The parser preserves native DNS-SD identifiers and original bytes. It never
identifies an application, verifies service reachability, or queries network
endpoints. RFC 6763 reuses DNS PTR, SRV, TXT, A and AAAA records.
"""

from dataclasses import dataclass

from novxis.protocols.dns import (
    DNSName, DNSResourceRecord, read_dns_name_rdata,
)


class DNSSDParseError(ValueError):
    """SRV/TXT bytes are incomplete or do not match their parent DNS message."""


@dataclass(frozen=True, slots=True)
class DNSSDSRV:
    """The *advertised* target and port, not verified host availability."""

    priority: int
    weight: int
    port: int
    target: DNSName


@dataclass(frozen=True, slots=True)
class DNSSDTXTEntry:
    """Lossless DNS-SD TXT string, including key/value bytes when present."""

    raw: bytes
    key: bytes
    value: bytes | None


@dataclass(frozen=True, slots=True)
class DNSSDTXT:
    """Length-prefixed TXT character-strings, without guessed text encodings."""

    entries: tuple[DNSSDTXTEntry, ...]


def parse_dnssd_srv(message: bytes, rr: DNSResourceRecord) -> DNSSDSRV:
    """Parse RFC 2782 SRV: priority/weight/port + compressed target name.

    DNS compression offsets are relative to the complete message, not to the
    SRV RDATA slice. The wire RR is never mutated.
    """
    if rr.rtype != 33:
        raise DNSSDParseError("Expected SRV resource record (type 33).")
    if rr.rclass & 0x7FFF != 1:
        raise DNSSDParseError("SRV class is not IN.")
    if len(rr.rdata) < 7:
        raise DNSSDParseError("SRV record needs six fixed bytes and a target name.")
    start = rr.rdata_offset
    end = start + len(rr.rdata)
    if not (0 <= start <= end <= len(message)):
        raise DNSSDParseError("SRV offset lies outside the DNS message.")
    if message[start:end] != rr.rdata:
        raise DNSSDParseError("SRV RDATA does not match message at recorded offset.")
    target = read_dns_name_rdata(message, start=start + 6, end=end)
    return DNSSDSRV(
        priority=int.from_bytes(rr.rdata[0:2], "big"),
        weight=int.from_bytes(rr.rdata[2:4], "big"),
        port=int.from_bytes(rr.rdata[4:6], "big"),
        target=target,
    )


def parse_dnssd_txt(rr: DNSResourceRecord) -> DNSSDTXT:
    """Preserve DNS-SD TXT bytes as individually length-prefixed strings.

    An entry without '=' has no value, whereas 'key=' has an empty value.
    Malformed RDATA is rejected without discarding the wire record.
    """
    if rr.rtype != 16:
        raise DNSSDParseError("Expected TXT resource record (type 16).")
    if rr.rclass & 0x7FFF != 1:
        raise DNSSDParseError("TXT class is not IN.")

    raw = rr.rdata
    pos = 0
    entries: list[DNSSDTXTEntry] = []
    while pos < len(raw):
        length = raw[pos]
        pos += 1
        end = pos + length
        if end > len(raw):
            raise DNSSDParseError("TXT string extends beyond RDATA length.")
        item = raw[pos:end]
        key, sep, value = item.partition(b"=")
        entries.append(
            DNSSDTXTEntry(
                raw=item,
                key=key,
                value=value if sep else None,
            )
        )
        pos = end
    return DNSSDTXT(tuple(entries))
