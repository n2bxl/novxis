"""Finite, passive live view of classic DNS over UDP port 53."""

import argparse
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider
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
        description="Passively capture classic DNS-over-UDP observations."
    )
    parser.add_argument("interface", help="Capture interface, such as en0.")
    parser.add_argument(
        "--count", type=int, default=20,
        help="Maximum captured port-53 frames (0 means until timeout).",
    )
    parser.add_argument(
        "--timeout", type=float, default=45.0,
        help="Capture timeout in seconds.",
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
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    counts = {"observations": 0, "errors": 0}
    correlator = DNSCorrelator() if args.correlate else None
    if args.correlate:
        counts["exchanges"] = 0
    provider = ScapyCaptureProvider()
    pipeline = DNSEventPipeline()

    print("NOVXIS live DNS UDP events")
    print(
        f"interface={args.interface} filter=udp port 53 "
        f"count={args.count or 'unlimited'} timeout={args.timeout}s"
    )
    print()
    try:
        provider.start(
            args.interface,
            _build_handler(pipeline, counts, correlator),
            bpf_filter="udp port 53",
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
        f"\nCapture complete. DNS observations: {counts['observations']}; "
        f"decode errors: {counts['errors']}"
    )
    if correlator is not None:
        print(f"Correlated exchanges: {counts['exchanges']}; "
              f"pending requests: {len(correlator.pending_requests)}")
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
