"""Readable, observational DNS pairing output; never a trust assertion."""

from novxis.events.dns_correlator import DNSExchangeCorrelated
from novxis.presentation.ipv4_console import format_timestamp


def format_dns_exchange(exchange: DNSExchangeCorrelated) -> str:
    """Summarize one conservative pairing without inferring host state."""
    request = exchange.request
    message = exchange.response.message
    question = request.message.questions[0]
    duration_ms = exchange.duration * 1000
    return (
        f"[{format_timestamp(exchange.response.timestamp)}] "
        f"DNSExchangeCorrelated interface={request.interface} "
        f"id=0x{request.message.header.transaction_id:04x} "
        f"q={question.name.text}/TYPE{question.qtype}/class{question.qclass} "
        f"rcode={message.header.response_code} "
        f"answers={len(message.answers)} "
        f"duration={duration_ms:.3f}ms "
        f"evidence=observed-only"
    )


def print_dns_exchange(exchange: DNSExchangeCorrelated) -> None:
    print(format_dns_exchange(exchange))
