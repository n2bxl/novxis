"""Replay PCAP/PCAPNG through the Phase 0 ARP event pipeline."""

import argparse
from decimal import Decimal
from pathlib import Path
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.pipeline import ARPEventPipeline, UnsupportedLinkTypeError
from novxis.presentation.arp_console import format_timestamp, print_arp_result
from novxis.protocols.arp import ARPParseError
from novxis.protocols.ethernet import EthernetParseError


def _build_handler(pipeline: ARPEventPipeline):
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

        if result is not None:
            print_arp_result(result)

    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay PCAP/PCAPNG through the NOVXIS ARP event pipeline."
    )
    parser.add_argument("path", type=Path, help="Capture file to replay.")
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Replay at most this many captured frames. Use 0 for all frames.",
    )
    parser.add_argument(
        "--interface-label",
        default="replay",
        help="Fallback interface label when the capture format does not provide one.",
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
    if not args.interface_label:
        parser.error("--interface-label must not be empty")
    if args.correlation_window <= 0:
        parser.error("--correlation-window must be greater than zero")

    provider = PcapReplayProvider()
    pipeline = ARPEventPipeline(correlation_window=args.correlation_window)

    print("NOVXIS ARP replay")
    print(
        f"path={args.path} count={args.count or 'all'} "
        f"fallback_interface={args.interface_label} "
        f"correlation_window={args.correlation_window}s"
    )
    print()

    try:
        replayed = provider.replay(
            args.path,
            _build_handler(pipeline),
            interface_label=args.interface_label,
            count=args.count,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1

    print("\nReplay complete.")
    print(f"Frames replayed: {replayed}")
    print(f"Pending unmatched requests: {len(pipeline.pending_requests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
