"""Bounded, evidence-first terminal representation of mDNS packets."""

from ipaddress import ip_address

from novxis.events.mdns import MDNSMessageObserved
from novxis.presentation.ipv4_console import format_timestamp

_TYPES = {1: "A", 5: "CNAME", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV"}
_MAX_PER_SECTION = 3


def _kind(number: int) -> str:
    return _TYPES.get(number, f"TYPE{number}")


def format_mdns_observation(observation: MDNSMessageObserved) -> str:
    """Describe an observed packet without promoting its contents to a device."""
    message = observation.message
    dns = message.dns
    udp = observation.udp
    ip = observation.ip
    parts = [
        f"[{format_timestamp(observation.timestamp)}]",
        f"MDNSMessageObserved interface={observation.interface}",
        f"ipv{observation.ip_version}",
        "response" if message.is_response else "query",
        f"{ip_address(ip.source)}:{udp.source_port} → "
        f"{ip_address(ip.destination)}:{udp.destination_port}",
        f"id=0x{dns.header.transaction_id:04x}",
        f"questions={len(message.questions)}",
        f"answers={len(message.answers)}",
        f"authority={len(message.authorities)}",
        f"additional={len(message.additionals)}",
    ]
    for question in message.questions[:_MAX_PER_SECTION]:
        qu = f"/{question.response_mode}" if not message.is_response else ""
        parts.append(
            f"q={question.wire.name.text}/{_kind(question.wire.qtype)}"
            f"/class{question.question_class}{qu}"
        )
    if len(message.questions) > _MAX_PER_SECTION:
        parts.append(f"other_questions={len(message.questions) - _MAX_PER_SECTION}")

    for section_name, records in (
        ("answer", message.answers),
        ("authority", message.authorities),
        ("additional", message.additionals),
    ):
        for record in records[:_MAX_PER_SECTION]:
            wire = record.wire
            target = f"={wire.decoded_data}" if wire.decoded_data is not None else ""
            flags = (" cache-flush" if record.cache_flush else "") + (
                " goodbye-candidate" if record.goodbye_candidate else ""
            )
            parts.append(
                f"{record.role}={wire.name.text}/{_kind(wire.rtype)}"
                f"/class{record.record_class}{target}"
                f"(ttl={wire.ttl}s{flags})"
            )
        if len(records) > _MAX_PER_SECTION:
            parts.append(f"other_{section_name}={len(records) - _MAX_PER_SECTION}")

    if dns.trailing_bytes:
        parts.append(f"trailing={len(dns.trailing_bytes)}bytes")
    return " ".join(parts)


def print_mdns_observation(observation: MDNSMessageObserved) -> None:
    print(format_mdns_observation(observation))
