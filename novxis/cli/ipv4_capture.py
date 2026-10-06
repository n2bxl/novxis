"""Live IPv4 evidence decoding for NOVXIS."""

import argparse
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.pipeline import IPv4EvidencePipeline, UnsupportedLinkTypeError
from novxis.presentation.ipv4_console import format_timestamp, print_ipv4_result
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.ipv4 import IPv4ParseError


def _build_handler(pipeline: IPv4EvidencePipeline):
    def handle(frame: CapturedFrame) -> None:
        try:
            result = pipeline.process(frame)
        except (
            EthernetParseError,
            IPv4ParseError,
            UnsupportedLinkTypeError,
        ) as exc:
            print(
                f"[{format_timestamp(frame.timestamp)}] "
                f"{frame.interface} decode failed: {exc}",
                file=sys.stderr,
            )
            return

        if result is not None:
            print_ipv4_result(result)

    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture and decode raw IPv4 evidence through NOVXIS."
    )
    parser.add_argument("interface", help="Interface to capture from, such as en0.")
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Stop after this many IPv4 frames. Use 0 for no packet limit.",
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
    pipeline = IPv4EvidencePipeline()

    print("NOVXIS IPv4 evidence capture")
    print(
        f"interface={args.interface} filter=ip "
        f"count={args.count} timeout={args.timeout}s"
    )
    print()

    try:
        provider.start(
            args.interface,
            _build_handler(pipeline),
            bpf_filter="ip",
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
