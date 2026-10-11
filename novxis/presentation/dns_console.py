"""Conservative text presentation of DNS observations, not host identity."""

from novxis.events.dns import DNSMessageObserved
from novxis.presentation.ipv4_console import format_ipv4_address, format_timestamp

_RECORD_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 28: "AAAA", 41: "OPT"}
_MAX_DISPLAY_RECORDS = 4


def _type_name(record_type: int) -> str:
    return _RECORD_TYPES.get(record_type, f"TYPE{record_type}")


def format_dns_observation(observation: DNSMessageObserved) -> str:
    """Display bounded DNS evidence without claiming a completed lookup."""
    message = observation.message
    header = message.header
    ip = observation.ipv4
    udp = observation.udp

    parts = [
        f"[{format_timestamp(observation.timestamp)}]",
        f"DNSMessageObserved interface={observation.interface}",
        "response" if header.is_response else "query",
        f"{format_ipv4_address(ip.source)}:{udp.source_port} → "
        f"{format_ipv4_address(ip.destination)}:{udp.destination_port}",
        f"id=0x{header.transaction_id:04x}",
        f"opcode={header.opcode}",
        f"rcode={header.response_code}",
        f"tc={int(header.truncated)}",
        f"questions={len(message.questions)}",
        f"answers={len(message.answers)}",
        f"authority={len(message.authorities)}",
        f"additional={len(message.additionals)}",
    ]

    for question in message.questions[:_MAX_DISPLAY_RECORDS]:
        parts.append(f"q={question.name.text}/{_type_name(question.qtype)}/class{question.qclass}")
    if len(message.questions) > _MAX_DISPLAY_RECORDS:
        parts.append(f"other_questions={len(message.questions) - _MAX_DISPLAY_RECORDS}")

    for record in message.answers[:_MAX_DISPLAY_RECORDS]:
        details = f"{record.name.text}/{_type_name(record.rtype)}/class{record.rclass}"
        if record.decoded_data is not None:
            details += f"={record.decoded_data}"
        details += f"(ttl={record.ttl}s)"
        parts.append(f"answer={details}")
    if len(message.answers) > _MAX_DISPLAY_RECORDS:
        parts.append(f"other_answers={len(message.answers) - _MAX_DISPLAY_RECORDS}")

    if message.trailing_bytes:
        parts.append(f"trailing={len(message.trailing_bytes)}bytes")

    return " ".join(parts)


def print_dns_observation(observation: DNSMessageObserved) -> None:
    print(format_dns_observation(observation))
