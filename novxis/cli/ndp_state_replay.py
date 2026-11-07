"""Offline, read-only interface-scoped IPv6 Neighbor Discovery evidence.

This is not the OS neighbor cache or a verified IPv6-to-MAC inventory.
The default view shows packet-claimed addresses; use --summary-only
to avoid displaying private address or MAC data.
"""

import argparse
from collections import Counter
from ipaddress import IPv6Address
from pathlib import Path
import sys

from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.cli.ndp_replay import _DECODE_ERRORS
from novxis.pipeline.ndp_state import NDStatePipeline
from novxis.state.ndp import NDAddressClaim, NDUnlinkedObservation


def _mac(value: bytes) -> str:
    return ":".join(f"{part:02x}" for part in value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay NDP claims without asserting IPv6 host identity."
    )
    parser.add_argument("path", type=Path, help="Local PCAP/PCAPNG file.")
    parser.add_argument("--count", type=int, default=0,
                        help="Maximum frames to replay (0 = all).")
    parser.add_argument("--interface-label", default="replay",
                        help="Fallback interface for captures without names.")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print counts only, without private IPv6/MAC data.")
    parser.add_argument("--limit", type=int, default=40,
                        help="Maximum claims and unresolved entries printed each.")
    parser.add_argument("--max-claims", type=int, default=256)
    parser.add_argument("--max-unlinked", type=int, default=256)
    parser.add_argument("--max-history", type=int, default=512)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.count < 0 or args.limit < 0:
        parser.error("--count and --limit must not be negative")
    if not args.interface_label:
        parser.error("--interface-label cannot be empty")
    for name in ("max_claims", "max_unlinked", "max_history"):
        value = getattr(args, name)
        if not 1 <= value <= 4096:
            parser.error(
                f"--{name.replace('_', '-')} must be within 1..4096"
            )

    pipeline = NDStatePipeline(
        max_claims=args.max_claims,
        max_unlinked=args.max_unlinked,
        max_history=args.max_history,
    )
    decode_errors = 0

    def handle(frame):
        nonlocal decode_errors
        try:
            pipeline.process(frame)
        except _DECODE_ERRORS as exc:
            decode_errors += 1
            if not args.summary_only:
                print(f"NDP decode failed: {exc}", file=sys.stderr)

    print("NOVXIS passive IPv6 Neighbor Discovery evidence state")
    try:
        frames = PcapReplayProvider().replay(
            args.path, handle, count=args.count,
            interface_label=args.interface_label,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1

    snapshot = pipeline.state.snapshot()
    print(
        f"Replay complete: frames={frames}; messages={snapshot.messages}; "
        f"NS={snapshot.solicitations}; NA={snapshot.advertisements}; "
        f"DAD={snapshot.dad_probes}; decode errors={decode_errors}"
    )
    print(
        f"Retained packet claims={len(snapshot.claims)} "
        f"(NS source SLLA={sum(x.kind == 'ns_source_slla' for x in snapshot.claims)}, "
        f"NA target TLLA={sum(x.kind == 'na_target_tlla' for x in snapshot.claims)}); "
        f"address targets={snapshot.distinct_claim_addresses}; "
        f"multiple-LLA addresses={snapshot.multiple_link_layer_addresses}; "
        f"unlinked evidence={len(snapshot.unlinked)}; "
        f"omitted claims={snapshot.omitted_claims}; "
        f"omitted unlinked={snapshot.omitted_unlinked}; "
        f"history truncated={snapshot.history_truncated}"
    )
    reason_counts = Counter(item.reason for item in snapshot.unlinked)
    for reason, count in sorted(reason_counts.items()):
        print(f"  unlinked {reason}: {count}")

    if not args.summary_only:
        print("Claims below are unverified packet assertions, not live hosts.")
        for item in snapshot.claims[:args.limit or None]:
            assert isinstance(item, NDAddressClaim)
            print(
                f"  {item.interface} {item.kind} "
                f"{IPv6Address(item.ipv6_address)} -> "
                f"{_mac(item.link_layer_address)} "
                f"observed={item.observation_count} "
                f"first={item.first_seen} last={item.last_seen}"
            )
        if args.limit and len(snapshot.claims) > args.limit:
            print(f"  Other claims omitted from display: "
                  f"{len(snapshot.claims) - args.limit}")
        print("Unlinked observations below do not imply address ownership.")
        for item in snapshot.unlinked[:args.limit or None]:
            assert isinstance(item, NDUnlinkedObservation)
            print(
                f"  {item.interface} {item.reason} "
                f"source={IPv6Address(item.source_address)} "
                f"target={IPv6Address(item.target_address)} "
                f"observed={item.observation_count} "
                f"last={item.last_seen}"
            )
        if args.limit and len(snapshot.unlinked) > args.limit:
            print(f"  Other unlinked entries omitted from display: "
                  f"{len(snapshot.unlinked) - args.limit}")
    return 0 if decode_errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
