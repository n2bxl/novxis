"""Console presentation for normalized ARP processing results."""

from datetime import datetime
from decimal import Decimal

from novxis.events import (
    ARPMessageObserved,
    ARPReplyObserved,
    ARPRequestObserved,
)
from novxis.pipeline import ARPProcessingResult


def format_timestamp(timestamp: Decimal) -> str:
    return datetime.fromtimestamp(float(timestamp)).astimezone().isoformat(
        timespec="milliseconds"
    )


def format_hardware_address(value: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in value)


def format_protocol_address(protocol_type: int, value: bytes) -> str:
    if protocol_type == 0x0800 and len(value) == 4:
        return ".".join(str(octet) for octet in value)
    return value.hex()


def _observation_name(observation: ARPMessageObserved) -> str:
    if isinstance(observation, ARPRequestObserved):
        return "ARPRequestObserved"
    if isinstance(observation, ARPReplyObserved):
        return "ARPReplyObserved"
    return "ARPMessageObserved"


def print_arp_result(result: ARPProcessingResult) -> None:
    observation = result.observation
    message = observation.message

    print(
        f"[{format_timestamp(observation.timestamp)}] "
        f"{_observation_name(observation)} "
        f"interface={observation.interface} "
        f"sender={format_protocol_address(message.protocol_type, message.sender_protocol)} "
        f"sender_hw={format_hardware_address(message.sender_hardware)} "
        f"target={format_protocol_address(message.protocol_type, message.target_protocol)} "
        f"target_hw={format_hardware_address(message.target_hardware)} "
        f"trailing={len(message.trailing_bytes)}"
    )

    if result.exchange is None:
        return

    request_message = result.exchange.request.message
    reply_message = result.exchange.reply.message
    duration_ms = result.exchange.duration * Decimal("1000")

    print(
        "  ARPExchangeCompleted "
        f"{format_protocol_address(request_message.protocol_type, request_message.sender_protocol)} "
        "→ "
        f"{format_protocol_address(request_message.protocol_type, request_message.target_protocol)} "
        f"reply_sender_hw={format_hardware_address(reply_message.sender_hardware)} "
        f"duration={duration_ms:.3f}ms"
    )
