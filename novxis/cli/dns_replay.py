"""Replay classic DNS-over-UDP observations from local PCAP/PCAPNG files."""

import argparse
from pathlib import Path
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.events.dns_correlator import DNSCorrelator
from novxis.pipeline import DNSEventPipeline, UnsupportedLinkTypeError
from novxis.presentation.dns_console import print_dns_observation
from novxis.presentation.dns_exchange_console import print_dns_exchange
from novxis.presentation.ipv4_console import format_timestamp
from novxis.protocols.dns import DNSParseError
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.ipv4 import IPv4ParseError
from novxis.protocols.udp import UDPParseError

_DECODE_ERRORS = (
    DNSParseError,
    EthernetParseError,
    IPv4ParseError,
    UDPParseError,
    UnsupportedLinkTypeError,
)


def _build_handler(
    pipeline: DNSEventPipeline, counts: dict[str, int],
    correlator: DNSCorrelator | None = None,
):
    def handle(frame: CapturedFrame) -> None:
        try:
            observation = pipeline.process(frame)
        except _DECODE_ERRORS as exc:
            counts["errors"] += 1
            print(
                f"[{format_timestamp(frame.timestamp)}] "
                f"{frame.interface} decode failed: {exc}",
                file=sys.stderr,
            )
            return

        if observation is not None:
            counts["observations"] += 1
            print_dns_observation(observation)
            if correlator is not None:
                exchange = correlator.observe(observation)
                if exchange is not None:
                    counts["exchanges"] += 1
                    print_dns_exchange(exchange)

    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay and display observed classic DNS-over-UDP messages."
    )
    parser.add_argument("path", type=Path, help="PCAP/PCAPNG file to replay.")
    parser.add_argument(
        "--count", type=int, default=0,
        help="Maximum captured frames to read (0 replays all).",
    )
    parser.add_argument(
        "--interface-label", default="replay",
        help="Fallback interface label if the capture does not identify one.",
    )
    parser.add_argument(
        "--correlate", action="store_true",
        help="Display conservative DNS query/response pairings in addition to raw observations.",
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
    pipeline = DNSEventPipeline()
    correlator = DNSCorrelator() if args.correlate else None
    if args.correlate:
        counts["exchanges"] = 0
    provider = PcapReplayProvider()

    print("NOVXIS DNS UDP replay")
    print(
        f"path={args.path} count={args.count or 'all'} "
        f"fallback_interface={args.interface_label}"
    )
    print()
    try:
        replayed = provider.replay(
            args.path,
            _build_handler(pipeline, counts, correlator),
            interface_label=args.interface_label,
            count=args.count,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1

    print()
    print(
        f"Replay complete. Frames replayed: {replayed}; "
        f"DNS observations: {counts['observations']}; "
        f"decode errors: {counts['errors']}"
    )
    if correlator is not None:
        print(f"Correlated exchanges: {counts['exchanges']}; "
              f"pending requests: {len(correlator.pending_requests)}")
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
