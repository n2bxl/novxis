"""Live ARP evidence decoding for the Phase 0 vertical slice."""

import argparse
from datetime import datetime
from decimal import Decimal
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.protocols.arp import ARPParseError, ARPMessage, parse_arp
from novxis.protocols.ethernet import (
    ETHERTYPE_ARP,
    EthernetFrame,
    EthernetParseError,
    parse_ethernet,
)


def _format_timestamp(timestamp: Decimal) -> str:
    return datetime.fromtimestamp(float(timestamp)).astimezone().isoformat(
        timespec="milliseconds"
    )


def _format_hardware_address(value: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in value)


def _format_protocol_address(protocol_type: int, value: bytes) -> str:
    if protocol_type == 0x0800 and len(value) == 4:
        return ".".join(str(octet) for octet in value)
    return value.hex()


def _opcode_name(opcode: int) -> str:
    return {1: "request", 2: "reply"}.get(opcode, "unknown")


def _print_evidence(
    captured: CapturedFrame,
    ethernet: EthernetFrame,
    arp: ARPMessage,
) -> None:
    print(
        f"[{_format_timestamp(captured.timestamp)}] "
        f"{captured.interface} captured={captured.captured_length} bytes"
    )
    print(
        "  Ethernet "
        f"dst={_format_hardware_address(ethernet.destination)} "
        f"src={_format_hardware_address(ethernet.source)} "
        f"type=0x{ethernet.ether_type:04x}"
    )
    print(
        "  ARP "
        f"htype={arp.hardware_type} "
        f"ptype=0x{arp.protocol_type:04x} "
        f"hlen={arp.hardware_length} "
        f"plen={arp.protocol_length} "
        f"opcode={arp.opcode} ({_opcode_name(arp.opcode)})"
    )
    print(
        "    sender "
        f"hardware={_format_hardware_address(arp.sender_hardware)} "
        "protocol="
        f"{_format_protocol_address(arp.protocol_type, arp.sender_protocol)}"
    )
    print(
        "    target "
        f"hardware={_format_hardware_address(arp.target_hardware)} "
        "protocol="
        f"{_format_protocol_address(arp.protocol_type, arp.target_protocol)}"
    )
    print(
        f"    trailing={len(arp.trailing_bytes)} bytes "
        f"hex={arp.trailing_bytes.hex() or '-'}"
    )
    print()


def _handle_frame(frame: CapturedFrame) -> None:
    try:
        ethernet = parse_ethernet(frame.data)

        if ethernet.ether_type != ETHERTYPE_ARP:
            print(
                f"[{_format_timestamp(frame.timestamp)}] "
                f"{frame.interface} skipped non-ARP EtherType "
                f"0x{ethernet.ether_type:04x}",
                file=sys.stderr,
            )
            return

        arp = parse_arp(ethernet.payload)
    except (EthernetParseError, ARPParseError) as exc:
        print(
            f"[{_format_timestamp(frame.timestamp)}] "
            f"{frame.interface} decode failed: {exc}",
            file=sys.stderr,
        )
        return

    _print_evidence(frame, ethernet, arp)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture and decode raw ARP evidence through NOVXIS."
    )
    parser.add_argument("interface", help="Interface to capture from, such as en5.")
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Stop after this many ARP frames. Use 0 for no packet limit.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Stop after this many seconds.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count must be zero or greater")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    provider = ScapyCaptureProvider()

    print("NOVXIS ARP evidence capture")
    print(
        f"interface={args.interface} filter=arp "
        f"count={args.count} timeout={args.timeout}s"
    )
    print()

    try:
        provider.start(
            args.interface,
            _handle_frame,
            bpf_filter="arp",
            count=args.count,
            timeout=args.timeout,
        )
        provider.wait()
    except KeyboardInterrupt:
        provider.stop()
        print("\nCapture stopped.")
        return 130
    except Exception as exc:
        provider.stop()
        print(f"Capture failed: {exc}", file=sys.stderr)
        return 1

    print("Capture complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
