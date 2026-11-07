"""Replay passive IPv6 Neighbor Solicitations/Advertisements from a PCAP.

This is Stage 1 packet evidence, not an IPv6 neighbor cache or a claim
that any target address belongs to the Ethernet sender. DAD especially
represents an *unverified tentative* target address.
"""

import argparse
from ipaddress import IPv6Address
from pathlib import Path
import sys

from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.pipeline.ndp import NeighborDiscoveryPipeline
from novxis.pipeline.link import UnsupportedLinkTypeError
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.ipv6 import IPv6ParseError
from novxis.protocols.icmpv6_nd import (
    NeighborDiscoveryParseError, NeighborSolicitation,
)
from novxis.presentation.ipv4_console import format_timestamp

_DECODE_ERRORS = (
    UnsupportedLinkTypeError, EthernetParseError, IPv6ParseError,
    NeighborDiscoveryParseError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay passive ICMPv6 NS/NA evidence (no active probing)."
    )
    parser.add_argument("path", type=Path, help="Local PCAP or PCAPNG file.")
    parser.add_argument("--count", type=int, default=0,
                        help="Max file frames; zero replays all.")
    parser.add_argument("--interface-label", default="replay",
                        help="Fallback interface when PCAP lacks metadata.")
    parser.add_argument("--summary-only", action="store_true",
                        help="Do not print individual observed private addresses.")
    return parser


def build_handler(pipeline, counts: dict[str, int], *, summary_only=False):
    def handle(frame) -> None:
        try:
            observed = pipeline.process(frame)
        except _DECODE_ERRORS as exc:
            counts["errors"] += 1
            if not summary_only:
                print(
                    f"[{format_timestamp(frame.timestamp)}] {frame.interface}"
                    f" ND decode failed: {exc}", file=sys.stderr,
                )
            return
        if observed is None:
            return
        msg = observed.message
        if isinstance(msg, NeighborSolicitation):
            counts["ns"] += 1
            counts["dad"] += int(msg.is_dad_probe)
            kind = "NS (DAD tentative target)" if msg.is_dad_probe else "NS"
            ll = msg.source_link_layer
            ll_label = "source LLA"
        else:
            counts["na"] += 1
            kind = "NA"
            ll = msg.target_link_layer
            ll_label = "advertised target LLA"
        if not summary_only:
            target = str(IPv6Address(msg.target))
            src = str(IPv6Address(msg.source))
            dst = str(IPv6Address(msg.destination))
            ll_text = ":".join(f"{b:02x}" for b in ll) if ll else "not observed"
            print(
                f"[{format_timestamp(frame.timestamp)}] {frame.interface} "
                f"{kind} {src} -> {dst} target={target} "
                f"{ll_label}={ll_text}"
            )
    return handle


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be zero or greater")
    if not args.interface_label:
        parser.error("--interface-label must not be empty")

    counts = {"ns": 0, "na": 0, "dad": 0, "errors": 0}
    print("NOVXIS passive ICMPv6 Neighbor Discovery replay")
    print(f"file={args.path} count={args.count or 'all'}")
    try:
        frames = PcapReplayProvider().replay(
            args.path, build_handler(
                NeighborDiscoveryPipeline(), counts,
                summary_only=args.summary_only,
            ),
            count=args.count, interface_label=args.interface_label,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Replay complete: frames={frames}, NS={counts['ns']}, "
        f"NA={counts['na']}, DAD probes={counts['dad']}, "
        f"decode errors={counts['errors']}"
    )
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
