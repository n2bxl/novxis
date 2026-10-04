"""Live ARP observation and exchange correlation for Phase 0."""

import argparse
from datetime import datetime
from decimal import Decimal
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.events import (
    ARPCorrelator,
    ARPMessageObserved,
    ARPReplyObserved,
    ARPRequestObserved,
    observe_arp,
)
from novxis.protocols.arp import ARPParseError, parse_arp
from novxis.protocols.ethernet import (
    ETHERTYPE_ARP,
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


def _observation_name(observation: ARPMessageObserved) -> str:
    if isinstance(observation, ARPRequestObserved):
        return "ARPRequestObserved"
    if isinstance(observation, ARPReplyObserved):
        return "ARPReplyObserved"
    return "ARPMessageObserved"


def _print_observation(observation: ARPMessageObserved) -> None:
    message = observation.message
    print(
        f"[{_format_timestamp(observation.timestamp)}] "
        f"{_observation_name(observation)} "
        f"interface={observation.interface} "
        f"sender={_format_protocol_address(message.protocol_type, message.sender_protocol)} "
        f"sender_hw={_format_hardware_address(message.sender_hardware)} "
        f"target={_format_protocol_address(message.protocol_type, message.target_protocol)} "
        f"target_hw={_format_hardware_address(message.target_hardware)} "
        f"trailing={len(message.trailing_bytes)}"
    )


def _build_handler(correlator: ARPCorrelator):
    def handle(frame: CapturedFrame) -> None:
        try:
            ethernet = parse_ethernet(frame.data)

            if ethernet.ether_type != ETHERTYPE_ARP:
                return

            message = parse_arp(ethernet.payload)
        except (EthernetParseError, ARPParseError) as exc:
            print(
                f"[{_format_timestamp(frame.timestamp)}] "
                f"{frame.interface} decode failed: {exc}",
                file=sys.stderr,
            )
            return

        observation = observe_arp(frame, ethernet, message)
        _print_observation(observation)

        exchange = correlator.observe(observation)
        if exchange is None:
            return

        request_message = exchange.request.message
        reply_message = exchange.reply.message
        duration_ms = exchange.duration * Decimal("1000")

        print(
            "  ARPExchangeCompleted "
            f"{_format_protocol_address(request_message.protocol_type, request_message.sender_protocol)} "
            "→ "
            f"{_format_protocol_address(request_message.protocol_type, request_message.target_protocol)} "
            f"reply_sender_hw={_format_hardware_address(reply_message.sender_hardware)} "
            f"duration={duration_ms}ms"
        )

    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture ARP observations and correlate request/reply exchanges."
    )
    parser.add_argument("interface", help="Interface to capture from, such as en5.")
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Stop after this many ARP frames. Use 0 for no packet limit.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Stop after this many seconds.",
    )
    parser.add_argument(
        "--correlation-window",
        type=Decimal,
        default=Decimal("5"),
        help="Maximum seconds between a request and matching reply.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count must be zero or greater")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.correlation_window <= 0:
        parser.error("--correlation-window must be greater than zero")

    provider = ScapyCaptureProvider()
    correlator = ARPCorrelator(max_age=args.correlation_window)

    print("NOVXIS ARP event capture")
    print(
        f"interface={args.interface} filter=arp "
        f"count={args.count} timeout={args.timeout}s "
        f"correlation_window={args.correlation_window}s"
    )
    print()

    try:
        provider.start(
            args.interface,
            _build_handler(correlator),
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

    print("\nCapture complete.")
    print(f"Pending unmatched requests: {len(correlator.pending_requests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
