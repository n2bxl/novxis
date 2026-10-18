"""Bounded DNS wire-message decoder (RFC 1035), independent of transport.

All offsets are relative to the start of a DNS message. DNS compression
pointers are followed only backwards and must remain within the message.
Unknown resource record data remains opaque rather than being guessed.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

DNS_HEADER_LENGTH = 12
DNS_CLASS_IN = 1


class DNSParseError(ValueError):
    """Raised when a DNS message is truncated or structurally malformed."""


@dataclass(frozen=True, slots=True)
class DNSName:
    """Domain labels as observed on the wire, without case normalization."""

    labels: tuple[bytes, ...]

    @property
    def text(self) -> str:
        if not self.labels:
            return "."

        def printable(label: bytes) -> str:
            return "".join(
                chr(byte)
                if 33 <= byte <= 126 and byte not in (46, 92)
                else rf"\x{byte:02x}"
                for byte in label
            )

        return ".".join(printable(label) for label in self.labels)


@dataclass(frozen=True, slots=True)
class DNSHeader:
    transaction_id: int
    flags: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def response_code(self) -> int:
        """Only the four-bit header RCODE; EDNS extensions are not decoded."""
        return self.flags & 0xF


@dataclass(frozen=True, slots=True)
class DNSQuestion:
    name: DNSName
    qtype: int
    qclass: int


@dataclass(frozen=True, slots=True)
class DNSResourceRecord:
    name: DNSName
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    rdata_offset: int
    decoded_data: str | None = None


@dataclass(frozen=True, slots=True)
class DNSMessage:
    header: DNSHeader
    questions: tuple[DNSQuestion, ...]
    answers: tuple[DNSResourceRecord, ...]
    authorities: tuple[DNSResourceRecord, ...]
    additionals: tuple[DNSResourceRecord, ...]
    trailing_bytes: bytes


def _u16(data: bytes, position: int) -> int:
    return int.from_bytes(data[position : position + 2], "big")


def _read_name(
    data: bytes, start: int, *, wire_limit: int | None = None
) -> tuple[DNSName, int]:
    """Return a DNS name and its end position in the original wire stream.

    wire_limit limits only bytes consumed from the original stream, e.g.
    the RDLENGTH boundary. Backward compression references can resolve to
    names elsewhere in the DNS message without consuming additional RDATA.
    """
    position = start
    end_on_wire: int | None = None
    visited: set[int] = set()
    labels: list[bytes] = []
    expanded_length = 1  # Include the terminal root label.

    while True:
        if position >= len(data):
            raise DNSParseError("DNS name extends beyond the message.")
        if position in visited:
            raise DNSParseError("DNS compression pointer loop detected.")
        visited.add(position)

        length = data[position]
        if length & 0xC0 == 0xC0:
            if position + 2 > len(data):
                raise DNSParseError("Truncated DNS compression pointer.")
            if (
                end_on_wire is None
                and wire_limit is not None
                and position + 2 > wire_limit
            ):
                raise DNSParseError("DNS name crosses its RDATA boundary.")
            target = ((length & 0x3F) << 8) | data[position + 1]
            if target >= position:
                raise DNSParseError("DNS compression pointer is not backward.")
            if target < DNS_HEADER_LENGTH:
                raise DNSParseError("DNS compression pointer targets the header.")
            if end_on_wire is None:
                end_on_wire = position + 2
            position = target
            continue

        if length & 0xC0:
            raise DNSParseError("Reserved DNS label encoding.")

        end = position + 1 + length
        if end > len(data):
            raise DNSParseError("Truncated DNS label.")
        if end_on_wire is None and wire_limit is not None and end > wire_limit:
            raise DNSParseError("DNS name crosses its RDATA boundary.")
        if length == 0:
            return DNSName(tuple(labels)), end_on_wire or end

        expanded_length += length + 1
        if expanded_length > 255:
            raise DNSParseError("Expanded DNS name exceeds 255 octets.")
        labels.append(data[position + 1 : end])
        position = end


def _read_question(data: bytes, position: int) -> tuple[DNSQuestion, int]:
    name, position = _read_name(data, position)
    if position + 4 > len(data):
        raise DNSParseError("Truncated DNS question fields.")
    result = DNSQuestion(name, _u16(data, position), _u16(data, position + 2))
    return result, position + 4


def _read_rr(
    data: bytes, position: int, *, interpret_mdns_class_bit: bool = False
) -> tuple[DNSResourceRecord, int]:
    name, position = _read_name(data, position)
    if position + 10 > len(data):
        raise DNSParseError("Truncated DNS resource-record fields.")

    rtype = _u16(data, position)
    rclass = _u16(data, position + 2)
    ttl = int.from_bytes(data[position + 4 : position + 8], "big")
    rdlength = _u16(data, position + 8)
    rdata_offset = position + 10
    end = rdata_offset + rdlength
    if end > len(data):
        raise DNSParseError("DNS RDLENGTH extends beyond the message.")
    rdata = data[rdata_offset:end]
    decoded: str | None = None

    # mDNS reuses the high bit of RRCLASS for its cache-flush indication.
    # Keep rclass unchanged as wire evidence; only its *interpretation* differs.
    # Classic DNS must not silently mask this bit.
    effective_class = rclass & 0x7FFF if interpret_mdns_class_bit else rclass
    if effective_class == DNS_CLASS_IN:
        if rtype == 1:  # A
            if rdlength != 4:
                raise DNSParseError("DNS A record must contain four octets.")
            decoded = str(IPv4Address(rdata))
        elif rtype == 28:  # AAAA
            if rdlength != 16:
                raise DNSParseError("DNS AAAA record must contain 16 octets.")
            decoded = str(IPv6Address(rdata))
        elif rtype in (2, 5, 12):  # NS, CNAME, PTR
            target, consumed = _read_name(data, rdata_offset, wire_limit=end)
            if consumed != end:
                raise DNSParseError("DNS name RDATA has unexpected extra bytes.")
            decoded = target.text

    return DNSResourceRecord(
        name=name,
        rtype=rtype,
        rclass=rclass,
        ttl=ttl,
        rdata=rdata,
        rdata_offset=rdata_offset,
        decoded_data=decoded,
    ), end



def read_dns_name_rdata(
    message: bytes, *, start: int, end: int
) -> DNSName:
    """Decode exactly one bounded RDATA name using message-wide compression.

    SRV targets, like PTR targets, may use DNS compression pointers into
    earlier sections. Decoding record.rdata alone would lose pointer context.
    The returned name preserves original label bytes and spelling.
    """
    if not (DNS_HEADER_LENGTH <= start < end <= len(message)):
        raise DNSParseError("Invalid DNS RDATA name boundaries.")
    name, consumed = _read_name(message, start, wire_limit=end)
    if consumed != end:
        raise DNSParseError("DNS name RDATA has unexpected extra bytes.")
    return name


def parse_dns(
    data: bytes, *, interpret_mdns_class_bit: bool = False
) -> DNSMessage:
    """Decode bounded DNS questions and resource records from raw bytes.

    The caller must already have isolated the DNS payload from UDP. This
    decoder makes no claim about response authenticity, active cache entries,
    current host identity, or DNS-over-TCP stream framing. When called by the
    separate mDNS interpreter, interpret_mdns_class_bit allows the mDNS
    cache-flush bit on resource-record classes while preserving raw RRCLASS.
    """
    if len(data) < DNS_HEADER_LENGTH:
        raise DNSParseError(
            f"DNS header requires {DNS_HEADER_LENGTH} bytes; got {len(data)}."
        )

    header = DNSHeader(
        transaction_id=_u16(data, 0),
        flags=_u16(data, 2),
        question_count=_u16(data, 4),
        answer_count=_u16(data, 6),
        authority_count=_u16(data, 8),
        additional_count=_u16(data, 10),
    )

    position = DNS_HEADER_LENGTH
    questions: list[DNSQuestion] = []
    for _ in range(header.question_count):
        question, position = _read_question(data, position)
        questions.append(question)

    sections: list[tuple[DNSResourceRecord, ...]] = []
    for count in (
        header.answer_count,
        header.authority_count,
        header.additional_count,
    ):
        records: list[DNSResourceRecord] = []
        for _ in range(count):
            record, position = _read_rr(
                data, position,
                interpret_mdns_class_bit=interpret_mdns_class_bit,
            )
            records.append(record)
        sections.append(tuple(records))

    return DNSMessage(
        header=header,
        questions=tuple(questions),
        answers=sections[0],
        authorities=sections[1],
        additionals=sections[2],
        trailing_bytes=data[position:],
    )
