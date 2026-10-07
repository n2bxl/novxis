"""Console presentation for normalized ICMPv4 processing results."""

from novxis.events.icmp import (
    ICMPDestinationUnreachableObserved,
    ICMPEchoReplyObserved,
    ICMPEchoRequestObserved,
    ICMPErrorObserved,
    ICMPMessageObserved,
    ICMPTimeExceededObserved,
)
from novxis.pipeline.icmp import ICMPProcessingResult
from novxis.presentation.ipv4_console import format_ipv4_address, format_timestamp


def _observation_name(observation: ICMPMessageObserved) -> str:
    if isinstance(observation, ICMPEchoRequestObserved):
        return "ICMPEchoRequestObserved"
    if isinstance(observation, ICMPEchoReplyObserved):
        return "ICMPEchoReplyObserved"
    if isinstance(observation, ICMPDestinationUnreachableObserved):
        return "ICMPDestinationUnreachableObserved"
    if isinstance(observation, ICMPTimeExceededObserved):
        return "ICMPTimeExceededObserved"
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


def _code_name(type_value: int, code: int) -> str | None:
    if type_value == 3:
        return {
            0: "Network Unreachable",
            1: "Host Unreachable",
            2: "Protocol Unreachable",
            3: "Port Unreachable",
            4: "Fragmentation Needed",
            5: "Source Route Failed",
            6: "Destination Network Unknown",
            7: "Destination Host Unknown",
            8: "Source Host Isolated",
            9: "Network Administratively Prohibited",
            10: "Host Administratively Prohibited",
            11: "Network Unreachable for TOS",
            12: "Host Unreachable for TOS",
            13: "Communication Administratively Prohibited",
            14: "Host Precedence Violation",
            15: "Precedence Cutoff",
        }.get(code)

    if type_value == 11:
        return {
            0: "TTL Exceeded in Transit",
            1: "Fragment Reassembly Time Exceeded",
        }.get(code)

    return None


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

    code_name = _code_name(message.type, message.code)
    code_details = f"code={message.code}"
    if code_name is not None:
        code_details += f" ({code_name})"

    mtu_details = ""
    if message.next_hop_mtu is not None:
        mtu_details = f" next_hop_mtu={message.next_hop_mtu}"

    print(
        f"[{format_timestamp(observation.timestamp)}] "
        f"{_observation_name(observation)} "
        f"interface={observation.interface} "
        f"{format_ipv4_address(ipv4.source)} → "
        f"{format_ipv4_address(ipv4.destination)} "
        f"type={message.type} ({_type_name(message.type)}) "
        f"{code_details} "
        f"checksum=0x{message.checksum:04x}"
        f"{echo_details}"
        f"{mtu_details} "
        f"payload={len(message.payload)} bytes"
    )

    if isinstance(observation, ICMPErrorObserved):
        quoted = observation.quoted_ipv4
        print(
            "  QuotedIPv4 "
            f"{format_ipv4_address(quoted.source)} → "
            f"{format_ipv4_address(quoted.destination)} "
            f"protocol={quoted.protocol} "
            f"ttl={quoted.ttl} "
            f"id=0x{quoted.identification:04x} "
            f"header={quoted.header_length} "
            f"declared_total={quoted.total_length} "
            f"available={quoted.available_length} "
            f"payload_prefix={len(quoted.payload_prefix)} bytes "
            f"trailing={len(quoted.trailing_bytes)} bytes "
            f"truncated={str(quoted.is_truncated).lower()}"
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
