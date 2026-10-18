"""Passive PCAP/PCAPNG replay of IPv4 and IPv6 UDP/5353 mDNS messages."""

import argparse
from pathlib import Path
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.pipeline.link import UnsupportedLinkTypeError
from novxis.presentation.mdns_console import print_mdns_observation
from novxis.presentation.mdns_service_console import print_dnssd_advertisement
from novxis.protocols.dnssd import DNSSDParseError
from novxis.views.mdns_services import project_dnssd_advertisements
from novxis.presentation.ipv4_console import format_timestamp
from novxis.protocols.dns import DNSParseError
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.ipv4 import IPv4ParseError
from novxis.protocols.ipv6 import IPv6ParseError
from novxis.protocols.udp import UDPParseError

_DECODE_ERRORS = (
    DNSParseError, EthernetParseError, IPv4ParseError, IPv6ParseError,
    UDPParseError, UnsupportedLinkTypeError, DNSSDParseError,
)


def _make_counts() -> dict[str, int]:
    return {
        "observations": 0, "ipv4": 0, "ipv6": 0,
        "queries": 0, "responses": 0, "service_ads": 0, "errors": 0,
    }


def _build_handler(
    pipeline: MDNSEventPipeline,
    counts: dict[str, int],
    *,
    summary_only: bool = False,
    show_services: bool = False,
):
    def handle(frame: CapturedFrame) -> None:
        try:
            observed = pipeline.process(frame)
            service_ads = (
                project_dnssd_advertisements(observed)
                if show_services and observed is not None else ()
            )
        except _DECODE_ERRORS as exc:
            counts["errors"] += 1
            print(
                f"[{format_timestamp(frame.timestamp)}] "
                f"{frame.interface} mDNS decode failed: {exc}",
                file=sys.stderr,
            )
            return
        if observed is None:
            return
        counts["observations"] += 1
        counts["ipv4" if observed.ip_version == 4 else "ipv6"] += 1
        counts["responses" if observed.message.is_response else "queries"] += 1
        if show_services:
            counts["service_ads"] += len(service_ads)
            if not summary_only:
                for ad in service_ads:
                    print_dnssd_advertisement(observed, ad)
        elif not summary_only:
            print_mdns_observation(observed)
    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay passive IPv4/IPv6 mDNS observations from PCAP/PCAPNG."
    )
    parser.add_argument("path", type=Path, help="Local PCAP or PCAPNG path.")
    parser.add_argument("--count", type=int, default=0,
                        help="Maximum file frames (0 replays all frames).")
    parser.add_argument("--interface-label", default="replay",
                        help="Fallback name if file metadata lacks interface.")
    parser.add_argument("--summary-only", action="store_true",
                        help="Count observations without printing individual packets.")
    parser.add_argument("--services", action="store_true",
                        help="Show only raw DNS-SD service advertisements (no fingerprint names).")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be zero or greater")
    if not args.interface_label:
        parser.error("--interface-label must not be empty")

    counts = _make_counts()
    print("NOVXIS passive mDNS replay")
    print(f"path={args.path} count={args.count or 'all'} "
          f"fallback_interface={args.interface_label}")
    print()
    try:
        emitted = PcapReplayProvider().replay(
            args.path,
            _build_handler(MDNSEventPipeline(), counts,
                           summary_only=args.summary_only,
                           show_services=args.services),
            count=args.count, interface_label=args.interface_label,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1
    print()
    print(
        f"Replay complete. Frames replayed: {emitted}; "
        f"mDNS observations: {counts['observations']} "
        f"(IPv4={counts['ipv4']}, IPv6={counts['ipv6']}; "
        f"queries={counts['queries']}, responses={counts['responses']}); "
        + (f"DNS-SD advertised PTRs: {counts['service_ads']}; "
           if args.services else "")
        + f"decode errors: {counts['errors']}"
    )
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
