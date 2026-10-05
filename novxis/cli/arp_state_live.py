"""Live ARP capture with derived NOVXIS network state."""

import argparse
from decimal import Decimal
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.pipeline import ARPStatePipeline, UnsupportedLinkTypeError
from novxis.presentation.arp_console import format_timestamp, print_arp_result
from novxis.presentation.arp_state_console import (
    print_arp_state_change,
    print_arp_state_snapshot,
)
from novxis.protocols.arp import ARPParseError
from novxis.protocols.ethernet import EthernetParseError


def _build_handler(pipeline: ARPStatePipeline):
    def handle(frame: CapturedFrame) -> None:
        try:
            result = pipeline.process(frame)
        except (
            EthernetParseError,
            ARPParseError,
            UnsupportedLinkTypeError,
        ) as exc:
            print(
                f"[{format_timestamp(frame.timestamp)}] "
                f"{frame.interface} decode failed: {exc}",
                file=sys.stderr,
            )
            return

        if result is None:
            return

        print_arp_result(result.event)

        if result.state_change is not None:
            print_arp_state_change(result.state_change)

    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture live ARP traffic and build derived NOVXIS network state."
    )
    parser.add_argument("interface", help="Interface to capture from, such as en0.")
    parser.add_argument(
        "--count",
        type=int,
        default=20,
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
    pipeline = ARPStatePipeline(correlation_window=args.correlation_window)

    print("NOVXIS live ARP network state")
    print(
        f"interface={args.interface} filter=arp "
        f"count={args.count} timeout={args.timeout}s "
        f"correlation_window={args.correlation_window}s"
    )
    print()

    try:
        provider.start(
            args.interface,
            _build_handler(pipeline),
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
    print_arp_state_snapshot(pipeline.state.arp_bindings)
    print()
    print(f"Current ARP bindings: {len(pipeline.state.arp_bindings)}")
    print(f"Pending unmatched requests: {len(pipeline.pending_requests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
