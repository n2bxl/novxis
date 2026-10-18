"""Finite, passive dual-stack mDNS live capture over UDP/5353."""

import argparse
import sys

from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.cli.mdns_replay import _build_handler, _make_counts
from novxis.pipeline.mdns import MDNSEventPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passively observe IPv4/IPv6 mDNS on one interface."
    )
    parser.add_argument("interface", help="Capture interface, such as en0.")
    parser.add_argument("--count", type=int, default=40,
                        help="Maximum UDP/5353 matching frames; 0 means until timeout.")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="Maximum capture duration in seconds.")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print aggregate counts without individual packets.")
    parser.add_argument("--services", action="store_true",
                        help="Show only raw DNS-SD service advertisements.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be zero or greater")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    provider = ScapyCaptureProvider()
    counts = _make_counts()
    print("NOVXIS passive live mDNS")
    print(
        f"interface={args.interface} filter=udp port 5353 "
        f"count={args.count or 'unlimited'} timeout={args.timeout}s"
    )
    print()
    try:
        provider.start(
            args.interface,
            _build_handler(MDNSEventPipeline(), counts,
                           summary_only=args.summary_only,
                           show_services=args.services),
            bpf_filter="udp port 5353",
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

    print(
        f"\nCapture complete. mDNS observations: {counts['observations']} "
        f"(IPv4={counts['ipv4']}, IPv6={counts['ipv6']}; "
        f"queries={counts['queries']}, responses={counts['responses']}); "
        + (f"DNS-SD advertised PTRs: {counts['service_ads']}; "
           if args.services else "")
        + f"decode errors: {counts['errors']}"
    )
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
