"""Live UDP observation view for NOVXIS."""

import argparse
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.pipeline import UDPEventPipeline, UnsupportedLinkTypeError
from novxis.presentation.ipv4_console import format_timestamp
from novxis.presentation.udp_console import print_udp_observation
from novxis.protocols.ethernet import EthernetParseError
from novxis.protocols.ipv4 import IPv4ParseError
from novxis.protocols.udp import UDPParseError


def _build_handler(pipeline: UDPEventPipeline):
    def handle(frame: CapturedFrame) -> None:
        try:
            observation = pipeline.process(frame)
        except (
            EthernetParseError,
            IPv4ParseError,
            UDPParseError,
            UnsupportedLinkTypeError,
        ) as exc:
            print(
                f"[{format_timestamp(frame.timestamp)}] "
                f"{frame.interface} decode failed: {exc}",
                file=sys.stderr,
            )
            return

        if observation is not None:
            print_udp_observation(observation)

    return handle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture and display individual UDP datagram observations."
    )
    parser.add_argument("interface", help="Capture interface, such as en0.")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count must be zero or greater")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    provider = ScapyCaptureProvider()
    pipeline = UDPEventPipeline()

    print("NOVXIS live UDP events")
    print(
        f"interface={args.interface} filter=udp "
        f"count={args.count} timeout={args.timeout}s"
    )
    print()

    try:
        provider.start(
            args.interface,
            _build_handler(pipeline),
            bpf_filter="udp",
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

    print("\nCapture complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
