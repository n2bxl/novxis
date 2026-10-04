"""CLI smoke test for the Scapy live-capture provider."""

import argparse
from datetime import datetime
from decimal import Decimal
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider


def _format_timestamp(timestamp: Decimal) -> str:
    return datetime.fromtimestamp(float(timestamp)).astimezone().isoformat(
        timespec="milliseconds"
    )


def _print_frame(frame: CapturedFrame) -> None:
    original = (
        str(frame.original_length)
        if frame.original_length is not None
        else "unknown"
    )
    print(
        f"[{_format_timestamp(frame.timestamp)}] "
        f"{frame.interface} "
        f"captured={frame.captured_length} bytes "
        f"original={original}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture raw frames through the NOVXIS Scapy provider."
    )
    parser.add_argument("interface", help="Interface to capture from, such as en5.")
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        help='Optional BPF filter, such as "arp".',
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Stop after this many frames. Use 0 for no packet limit.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
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

    print("NOVXIS live capture")
    print(
        f"interface={args.interface} "
        f"filter={args.bpf_filter or 'none'} "
        f"count={args.count} "
        f"timeout={args.timeout}s"
    )
    print()

    try:
        provider.start(
            args.interface,
            _print_frame,
            bpf_filter=args.bpf_filter,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
