"""Replay DHCPv4 messages through the NOVXIS UDP evidence pipeline."""

import argparse
from pathlib import Path
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.pipeline import DHCPv4EventPipeline, UnsupportedLinkTypeError
from novxis.presentation.dhcpv4_console import print_dhcpv4_observation
from novxis.presentation.ipv4_console import format_timestamp
from novxis.protocols.dhcpv4 import DHCPv4ParseError
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.ipv4 import IPv4ParseError
from novxis.protocols.udp import UDPParseError


def _build_handler(pipeline: DHCPv4EventPipeline, counts: dict[str, int]):
    def handle(frame: CapturedFrame) -> None:
        try:
            observation = pipeline.process(frame)
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

        if observation is not None:
            counts["observations"] += 1
            print_dhcpv4_observation(observation)

    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay a PCAP/PCAPNG and display observed DHCPv4 messages."
    )
    parser.add_argument("path", type=Path, help="Capture file to replay.")
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Maximum captured frames to read (0 replays all frames).",
    )
    parser.add_argument(
        "--interface-label",
        default="replay",
        help="Fallback interface when capture metadata does not identify one.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be zero or greater")
    if not args.interface_label:
        parser.error("--interface-label must not be empty")

    counts = {"observations": 0, "errors": 0}
    pipeline = DHCPv4EventPipeline()
    provider = PcapReplayProvider()

    print("NOVXIS DHCPv4 replay")
    print(
        f"path={args.path} count={args.count or 'all'} "
        f"fallback_interface={args.interface_label}"
    )
    print()
    try:
        replayed = provider.replay(
            args.path,
            _build_handler(pipeline, counts),
            interface_label=args.interface_label,
            count=args.count,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1

    print()
    print(
        f"Replay complete. Frames replayed: {replayed}; "
        f"DHCPv4 observations: {counts['observations']}; "
        f"decode errors: {counts['errors']}"
    )
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
