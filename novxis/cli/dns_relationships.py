"""Aggregated, passive DNS relationship evidence from live capture or PCAP.

Capture/parse/correlate/state -> immutable view snapshot -> console formatting.
No UI rendering concerns enter capture, event interpretation, or NetworkState.
"""

import argparse
import math
from decimal import Decimal
from pathlib import Path
import sys

from novxis.capture.pcap_replay import PcapReplayProvider
from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.pipeline.dns_state import DNSStatePipeline
from novxis.pipeline.link import UnsupportedLinkTypeError
from novxis.presentation.dns_group_console import print_dns_grouped_snapshot
from novxis.presentation.dns_relationship_console import (
    print_dns_relationship_snapshot,
)
from novxis.protocols.dns import DNSParseError
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.ipv4 import IPv4ParseError
from novxis.protocols.udp import UDPParseError
from novxis.views.dns_groups import group_dns_relationships
from novxis.views.dns_relationships import project_dns_relationships

_ERRORS = (
    DNSParseError,
    EthernetParseError,
    IPv4ParseError,
    UDPParseError,
    UnsupportedLinkTypeError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Show aggregated, read-only DNS relationship evidence.",
    )
    sources = parser.add_subparsers(dest="source", required=True)

    live = sources.add_parser("live", help="Passively observe classic UDP/53 DNS.")
    live.add_argument("interface", help="Active capture interface (e.g. en0).")
    live.add_argument("--count", type=int, default=40,
                      help="Capture frame limit; 0 means run until timeout.")
    live.add_argument("--timeout", type=float, default=60.0,
                      help="Capture timeout in seconds.")

    replay = sources.add_parser("replay", help="Read a local PCAP/PCAPNG.")
    replay.add_argument("path", type=Path, help="Local capture file.")
    replay.add_argument("--count", type=int, default=0,
                        help="Frame limit; 0 means all frames.")
    replay.add_argument("--interface-label", default="replay",
                        help="Fallback label if absent in the capture.")

    for sub in (live, replay):
        sub.add_argument(
            "--group", action="store_true",
            help="Group forward CNAME/A/AAAA relationships and separate reverse PTR evidence.",
        )
        sub.add_argument(
            "--history", action="store_true",
            help="Display each retained observation, not just the latest per record.",
        )
        sub.add_argument(
            "--as-of", type=Decimal,
            help="View at this Unix timestamp (seconds); otherwise use the "
                 "latest captured frame timestamp.",
        )
        sub.add_argument(
            "--correlation-window", type=Decimal, default=Decimal("10"),
            help="Max query-to-response interval in seconds.",
        )

    return parser


def _validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.count < 0:
        parser.error("--count must be zero or greater")
    if not args.correlation_window.is_finite() or args.correlation_window <= 0:
        parser.error("--correlation-window must be finite and positive")
    if args.as_of is not None and not args.as_of.is_finite():
        parser.error("--as-of must be a finite Unix timestamp")
    if args.source == "live" and (not math.isfinite(args.timeout) or args.timeout <= 0):
        parser.error("--timeout must be greater than zero")
    if args.source == "replay" and not args.interface_label:
        parser.error("--interface-label must not be empty")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    _validate(parser, args)
    pipeline = DNSStatePipeline(correlation_window=args.correlation_window)
    stats = {"frames": 0, "observations": 0, "exchanges": 0, "records": 0, "errors": 0}
    latest_timestamp: Decimal | None = None

    def handle(frame) -> None:
        nonlocal latest_timestamp
        stats["frames"] += 1
        if latest_timestamp is None or frame.timestamp > latest_timestamp:
            latest_timestamp = frame.timestamp
        try:
            result = pipeline.process(frame)
        except _ERRORS as exc:
            stats["errors"] += 1
            print(f"DNS decode failed on {frame.interface}: {exc}", file=sys.stderr)
            return
        if result is None:
            return
        stats["observations"] += 1
        if result.exchange is not None:
            stats["exchanges"] += 1
        stats["records"] += len(result.records)

    print("NOVXIS aggregated DNS relationships (passive observation)")
    try:
        if args.source == "live":
            provider = ScapyCaptureProvider()
            try:
                provider.start(
                    args.interface,
                    handle,
                    bpf_filter="udp port 53",
                    count=args.count,
                    timeout=args.timeout,
                )
                provider.wait()
            except KeyboardInterrupt:
                provider.stop()
                print("Capture interrupted; showing evidence observed so far.")
            except Exception:
                provider.stop()
                raise
        else:
            PcapReplayProvider().replay(
                args.path,
                handle,
                interface_label=args.interface_label,
                count=args.count,
            )
    except Exception as exc:
        # Display a clear error in this boundary only; never swallow
        # unexpected application failures as successful captures.
        print(f"DNS relationship capture/replay failed: {exc}", file=sys.stderr)
        return 1

    as_of = args.as_of if args.as_of is not None else latest_timestamp
    if as_of is None:
        print("No capture timestamp available; no freshness view can be calculated.")
    else:
        snapshot = project_dns_relationships(
            pipeline.state.dns_relationships,
            as_of=as_of,
            mode="history" if args.history else "latest",
        )
        print()
        if args.group:
            print_dns_grouped_snapshot(group_dns_relationships(snapshot))
        else:
            print_dns_relationship_snapshot(snapshot)
    print()
    print(
        f"Frames processed: {stats['frames']}; "
        f"DNS observations: {stats['observations']}; "
        f"correlated exchanges: {stats['exchanges']}; "
        f"DNS records observed: {stats['records']}; "
        f"pending requests: {len(pipeline.pending_requests)}; "
        f"decode errors: {stats['errors']}"
    )
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
