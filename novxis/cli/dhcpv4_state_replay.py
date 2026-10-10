"""Replay DHCPv4 messages with correlation and ACK-derived configuration."""

import argparse
from decimal import Decimal
from pathlib import Path
import sys

from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.pipeline import DHCPv4StatePipeline, UnsupportedLinkTypeError
from novxis.presentation.dhcpv4_console import print_dhcpv4_observation
from novxis.presentation.dhcpv4_exchange_console import (
    format_dhcpv4_exchange,
    print_dhcpv4_state_change,
    print_dhcpv4_state_snapshot,
)
from novxis.presentation.ipv4_console import format_timestamp
from novxis.protocols.dhcpv4 import DHCPv4ParseError
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.ipv4 import IPv4ParseError
from novxis.protocols.udp import UDPParseError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay DHCPv4 observations, correlate responses, and show ACK evidence."
    )
    parser.add_argument("path", type=Path, help="Local capture file (PCAP/PCAPNG).")
    parser.add_argument(
        "--count", type=int, default=0,
        help="Read at most this many captured frames (0 means all).",
    )
    parser.add_argument(
        "--interface-label", default="replay",
        help="Fallback name when the capture has no interface metadata.",
    )
    parser.add_argument(
        "--correlation-window", type=Decimal, default=Decimal("10"),
        help="Maximum seconds from request to response (default 10).",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be zero or greater")
    if not args.interface_label:
        parser.error("--interface-label must not be empty")
    if not args.correlation_window.is_finite() or args.correlation_window <= 0:
        parser.error("--correlation-window must be a finite positive value")

    pipeline = DHCPv4StatePipeline(correlation_window=args.correlation_window)
    counts = {"observations": 0, "exchanges": 0, "errors": 0}

    print("NOVXIS DHCPv4 exchange and ACK-state replay")
    print(
        f"path={args.path} count={args.count or 'all'} "
        f"fallback_interface={args.interface_label} "
        f"correlation_window={args.correlation_window}s"
    )
    print()

    def handle(frame):
        try:
            result = pipeline.process(frame)
        except (
            DHCPv4ParseError,
            EthernetParseError,
            IPv4ParseError,
            UDPParseError,
            UnsupportedLinkTypeError,
        ) as exc:
            counts["errors"] += 1
            print(
                f"[{format_timestamp(frame.timestamp)}] "
                f"{frame.interface} decode failed: {exc}",
                file=sys.stderr,
            )
            return
        if result is None:
            return
        counts["observations"] += 1
        print_dhcpv4_observation(result.observation)
        if result.exchange is not None:
            counts["exchanges"] += 1
            print(format_dhcpv4_exchange(result.exchange))
        if result.state_change is not None:
            print_dhcpv4_state_change(result.state_change)

    try:
        replayed = PcapReplayProvider().replay(
            args.path,
            handle,
            interface_label=args.interface_label,
            count=args.count,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1

    print()
    print_dhcpv4_state_snapshot(pipeline.state.dhcpv4_acknowledgments)
    print()
    print(
        f"Replay complete. Frames: {replayed}; DHCPv4 observations: "
        f"{counts['observations']}; correlated exchanges: {counts['exchanges']}; "
        f"decode errors: {counts['errors']}; "
        f"pending requests/discovers: {len(pipeline.pending_requests)}"
    )
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
