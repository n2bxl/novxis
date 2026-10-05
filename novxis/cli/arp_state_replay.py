"""Replay capture files through ARP events and derived network state."""

import argparse
from decimal import Decimal
from pathlib import Path
import sys

from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.pipeline import (
    ARPStatePipeline,
    UnsupportedLinkTypeError,
)
from novxis.presentation.arp_console import print_arp_result
from novxis.presentation.arp_state_console import (
    print_arp_state_change,
    print_arp_state_snapshot,
)
from novxis.protocols.arp import ARPParseError
from novxis.protocols.ethernet import EthernetParseError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay ARP traffic and build derived NOVXIS network state."
    )
    parser.add_argument("path", type=Path, help="Capture file to replay.")
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

    if not args.interface_label:
        parser.error("--interface-label must not be empty")
    if args.correlation_window <= 0:
        parser.error("--correlation-window must be greater than zero")

    pipeline = ARPStatePipeline(correlation_window=args.correlation_window)
    provider = PcapReplayProvider()

    print("NOVXIS ARP state replay")
    print(
        f"path={args.path} fallback_interface={args.interface_label} "
        f"correlation_window={args.correlation_window}s"
    )
    print()

    def handle(frame):
        try:
            result = pipeline.process(frame)
        except (
            EthernetParseError,
            ARPParseError,
            UnsupportedLinkTypeError,
        ) as exc:
            print(f"decode failed: {exc}", file=sys.stderr)
            return

        if result is None:
            return

        print_arp_result(result.event)

        if result.state_change is not None:
            print_arp_state_change(result.state_change)

    try:
        replayed = provider.replay(
            args.path,
            handle,
            interface_label=args.interface_label,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1

    print()
    print_arp_state_snapshot(pipeline.state.arp_bindings)
    print()
    print(f"Frames replayed: {replayed}")
    print(f"Current ARP bindings: {len(pipeline.state.arp_bindings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
