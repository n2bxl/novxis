"""Console presentation for decoded IPv4 evidence."""

from datetime import datetime
from decimal import Decimal

from novxis.pipeline.ipv4 import IPv4ProcessingResult


def format_timestamp(timestamp: Decimal) -> str:
    return datetime.fromtimestamp(float(timestamp)).astimezone().isoformat(
        timespec="milliseconds"
    )


def format_hardware_address(value: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in value)


def format_ipv4_address(value: bytes) -> str:
    if len(value) == 4:
        return ".".join(str(octet) for octet in value)
    return value.hex()


def _protocol_name(protocol: int) -> str:
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "unknown")


def _flags_name(flags: int) -> str:
    names: list[str] = []

    if flags & 0b100:
        names.append("reserved")
    if flags & 0b010:
        names.append("DF")
    if flags & 0b001:
        names.append("MF")

    return ",".join(names) if names else "-"


def print_ipv4_result(result: IPv4ProcessingResult) -> None:
    captured = result.captured
    ethernet = result.ethernet
    datagram = result.datagram

    print(
        f"[{format_timestamp(captured.timestamp)}] "
        f"{captured.interface} captured={captured.captured_length} bytes"
    )
    print(
        "  Ethernet "
        f"dst={format_hardware_address(ethernet.destination)} "
        f"src={format_hardware_address(ethernet.source)} "
        f"type=0x{ethernet.ether_type:04x}"
    )
    print(
        "  IPv4 "
        f"src={format_ipv4_address(datagram.source)} "
        f"dst={format_ipv4_address(datagram.destination)} "
        f"version={datagram.version} "
        f"ihl={datagram.ihl} "
        f"header={datagram.header_length} "
        f"total={datagram.total_length} "
        f"dscp={datagram.dscp} "
        f"ecn={datagram.ecn} "
        f"id=0x{datagram.identification:04x} "
        f"flags={_flags_name(datagram.flags)} "
        f"fragment_offset={datagram.fragment_offset} "
        f"ttl={datagram.ttl} "
        f"protocol={datagram.protocol} ({_protocol_name(datagram.protocol)}) "
        f"checksum=0x{datagram.header_checksum:04x}"
    )
    print(
        f"    options={len(datagram.options)} bytes "
        f"payload={len(datagram.payload)} bytes "
        f"trailing={len(datagram.trailing_bytes)} bytes"
    )
    print()
