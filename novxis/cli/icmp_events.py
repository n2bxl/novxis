"""Live ICMPv4 event and Echo-correlation view for NOVXIS."""

import argparse
from decimal import Decimal
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.pipeline import ICMPEventPipeline, UnsupportedLinkTypeError
from novxis.presentation.icmp_console import print_icmp_result
from novxis.presentation.ipv4_console import format_timestamp
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.icmp import ICMPParseError
from novxis.protocols.ipv4 import IPv4ParseError


def _build_handler(pipeline: ICMPEventPipeline):
    def handle(frame: CapturedFrame) -> None:
        try:
            result = pipeline.process(frame)
        except (
            EthernetParseError,
            IPv4ParseError,
            ICMPParseError,
            UnsupportedLinkTypeError,
        ) as exc:
            print(
                f"[{format_timestamp(frame.timestamp)}] "
                f"{frame.interface} decode failed: {exc}",
                file=sys.stderr,
            )
            return

        if result is not None:
            print_icmp_result(result)

    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture ICMPv4 events and correlate Echo request/reply exchanges."
    )
    parser.add_argument("interface", help="Interface to capture from, such as en0.")
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Stop after this many ICMP frames. Use 0 for no packet limit.",
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
        help="Maximum seconds between an Echo Request and matching Echo Reply.",
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
    pipeline = ICMPEventPipeline(correlation_window=args.correlation_window)

    print("NOVXIS live ICMP events")
    print(
        f"interface={args.interface} filter=icmp "
        f"count={args.count} timeout={args.timeout}s "
        f"correlation_window={args.correlation_window}s"
    )
    print()

    try:
        provider.start(
            args.interface,
            _build_handler(pipeline),
            bpf_filter="icmp",
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
    print(f"Pending unmatched Echo Requests: {len(pipeline.pending_requests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
