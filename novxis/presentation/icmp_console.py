"""Console presentation for normalized ICMPv4 processing results."""

from novxis.events.icmp import (
    ICMPEchoReplyObserved,
    ICMPEchoRequestObserved,
    ICMPMessageObserved,
)
from novxis.pipeline.icmp import ICMPProcessingResult
from novxis.presentation.ipv4_console import format_ipv4_address, format_timestamp


def _observation_name(observation: ICMPMessageObserved) -> str:
    if isinstance(observation, ICMPEchoRequestObserved):
        return "ICMPEchoRequestObserved"
    if isinstance(observation, ICMPEchoReplyObserved):
        return "ICMPEchoReplyObserved"
    return "ICMPMessageObserved"


def _type_name(type_value: int) -> str:
    return {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
        12: "Parameter Problem",
    }.get(type_value, "unknown")


def print_icmp_result(result: ICMPProcessingResult) -> None:
    observation = result.observation
    message = observation.message
    ipv4 = observation.ipv4

    echo_details = ""
    if message.echo_identifier is not None and message.echo_sequence is not None:
        echo_details = (
            f" id=0x{message.echo_identifier:04x}"
            f" seq={message.echo_sequence}"
        )

    print(
        f"[{format_timestamp(observation.timestamp)}] "
        f"{_observation_name(observation)} "
        f"interface={observation.interface} "
        f"{format_ipv4_address(ipv4.source)} → "
        f"{format_ipv4_address(ipv4.destination)} "
        f"type={message.type} ({_type_name(message.type)}) "
        f"code={message.code} "
        f"checksum=0x{message.checksum:04x}"
        f"{echo_details} "
        f"payload={len(message.payload)} bytes"
    )

    if result.exchange is None:
        return

    request = result.exchange.request
    duration_ms = result.exchange.duration * 1000

    print(
        "  ICMPEchoExchangeCompleted "
        f"{format_ipv4_address(request.ipv4.source)} → "
        f"{format_ipv4_address(request.ipv4.destination)} → "
        f"{format_ipv4_address(request.ipv4.source)} "
        f"id=0x{request.message.echo_identifier:04x} "
        f"seq={request.message.echo_sequence} "
        f"duration={duration_ms:.3f}ms"
    )
