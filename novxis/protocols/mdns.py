"""Passive mDNS message semantics over the existing bounded DNS wire decoder.

This module is capture-independent. It never sends multicast requests,
performs name registration, models a DNS cache, or claims device identity.

mDNS uses the high CLASS bit differently in questions and resource records:
- question QCLASS high bit: QU (unicast-response requested), vs QM
- RRCLASS high bit in *responses*: cache-flush flag
- Answer RRs in *queries*: known-answer hints, NOT advertisements

The original DNSQuestion/DNSResourceRecord objects, including raw class
fields and RDATA, remain accessible for provenance.
"""

from dataclasses import dataclass
from typing import Literal

from novxis.protocols.dns import (
    DNSMessage,
    DNSQuestion,
    DNSResourceRecord,
    parse_dns,
)

MDNS_UDP_PORT = 5353
MDNS_IPV4_MULTICAST = "224.0.0.251"
MDNS_IPV6_MULTICAST = "ff02::fb"
MDNS_CLASS_HIGH_BIT = 0x8000
MDNS_CLASS_MASK = 0x7FFF

MDNSSection = Literal["answer", "authority", "additional"]
MDNSRecordRole = Literal[
    "known_answer",
    "query_authority",
    "query_additional",
    "response_answer",
    "response_authority",
    "response_additional",
]


@dataclass(frozen=True, slots=True)
class MDNSQuestion:
    """A DNS question with the mDNS-specific QU/QM class bit interpreted."""

    wire: DNSQuestion
    question_class: int
    unicast_response_requested: bool

    @property
    def response_mode(self) -> Literal["QU", "QM"]:
        return "QU" if self.unicast_response_requested else "QM"


@dataclass(frozen=True, slots=True)
class MDNSRecord:
    """Preserve a wire RR and distinguish what its containing section means."""

    wire: DNSResourceRecord
    section: MDNSSection
    role: MDNSRecordRole
    record_class: int
    class_high_bit_set: bool
    cache_flush: bool
    goodbye_candidate: bool

    @property
    def is_known_answer(self) -> bool:
        return self.role == "known_answer"


@dataclass(frozen=True, slots=True)
class MDNSMessage:
    """Contextual interpretation of a single mDNS DNS-format payload."""

    dns: DNSMessage
    questions: tuple[MDNSQuestion, ...]
    answers: tuple[MDNSRecord, ...]
    authorities: tuple[MDNSRecord, ...]
    additionals: tuple[MDNSRecord, ...]

    @property
    def is_response(self) -> bool:
        return self.dns.header.is_response

    @property
    def records(self) -> tuple[MDNSRecord, ...]:
        """Every resource record once, in original DNS section order."""
        return self.answers + self.authorities + self.additionals

    @property
    def known_answers(self) -> tuple[MDNSRecord, ...]:
        """Querier's prior knowledge, not asserted authoritative answers."""
        return self.answers if not self.is_response else ()

    @property
    def has_probe_authority_records(self) -> bool:
        """An observed query Authority Section; not proof of completed probing."""
        return not self.is_response and bool(self.authorities)


def _interpret_record(
    record: DNSResourceRecord, *,
    section: MDNSSection,
    is_response: bool,
) -> MDNSRecord:
    if is_response:
        role: MDNSRecordRole = {
            "answer": "response_answer",
            "authority": "response_authority",
            "additional": "response_additional",
        }[section]
    else:
        role = {
            "answer": "known_answer",
            "authority": "query_authority",
            "additional": "query_additional",
        }[section]

    high_bit_set = bool(record.rclass & MDNS_CLASS_HIGH_BIT)
    return MDNSRecord(
        wire=record,
        section=section,
        role=role,
        record_class=record.rclass & MDNS_CLASS_MASK,
        class_high_bit_set=high_bit_set,
        # The high bit means cache-flush only for response RRs. On a query
        # it is preserved but never promoted into authoritative evidence.
        cache_flush=is_response and high_bit_set,
        # A TTL=0 response is a possible goodbye; avoid assuming this is
        # an authenticated, accepted cache removal.
        goodbye_candidate=is_response and record.ttl == 0,
    )


def parse_mdns(data: bytes) -> MDNSMessage:
    """Decode an mDNS payload without transport- or network-state inferences.

    Caller must first establish UDP/5353 provenance. Multicast/unicast,
    IPv4/IPv6, hop-limit and sender information belong to later observation
    objects rather than the message decoder. Malformed DNS raises DNSParseError.
    """
    wire = parse_dns(data, interpret_mdns_class_bit=True)
    is_response = wire.header.is_response
    questions = tuple(
        MDNSQuestion(
            wire=question,
            question_class=question.qclass & MDNS_CLASS_MASK,
            unicast_response_requested=(
                not is_response and bool(question.qclass & MDNS_CLASS_HIGH_BIT)
            ),
        )
        for question in wire.questions
    )

    def section_records(
        section: MDNSSection, records: tuple[DNSResourceRecord, ...]
    ) -> tuple[MDNSRecord, ...]:
        return tuple(
            _interpret_record(record, section=section, is_response=is_response)
            for record in records
        )

    return MDNSMessage(
        dns=wire,
        questions=questions,
        answers=section_records("answer", wire.answers),
        authorities=section_records("authority", wire.authorities),
        additionals=section_records("additional", wire.additionals),
    )
