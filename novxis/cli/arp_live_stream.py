"""Privileged capture-only producer: emit bounded ARP binding NDJSON to stdout.

Run this process separately from the unprivileged localhost browser server.
No raw frame bytes or arbitrary packet payloads are sent over the pipe.
"""

import argparse
import json
import sys

from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.pipeline import ARPStatePipeline, UnsupportedLinkTypeError
from novxis.protocols.arp import ARPParseError
from novxis.protocols.ethernet import EthernetParseError


_DECODE_ERRORS = (ARPParseError, EthernetParseError, UnsupportedLinkTypeError)


def binding_message(binding) -> dict:
    """Serialize the existing state model without projecting physical hosts."""
    return {
        "type": "binding",
        "interface": binding.interface,
        "hardware_type": binding.hardware_type,
        "protocol_type": binding.protocol_type,
        "protocol_hex": binding.protocol_address.hex(),
        "hardware_hex": binding.hardware_address.hex(),
        "first_seen": str(binding.first_seen),
        "last_seen": str(binding.last_seen),
        "observation_count": binding.observation_count,
    }


def build_handler(pipeline: ARPStatePipeline, emit):
    """Produce one message per sender-binding state transition."""
    def handle(frame):
        try:
            result = pipeline.process(frame)
        except _DECODE_ERRORS:
            return
        if result is None or result.state_change is None:
            return
        change = result.state_change
        binding = getattr(change, "current", None)
        if binding is None:
            binding = change.binding
        emit(binding_message(binding))
    return handle


def build_parser():
    parser = argparse.ArgumentParser(
        description="Capture bounded live ARP observations as local NDJSON."
    )
    parser.add_argument("interface", help="Authorized capture interface, such as en0.")
    parser.add_argument(
        "--count", type=int, default=2000,
        help="Maximum captured ARP frames (default 2000).",
    )
    parser.add_argument(
        "--timeout", type=float, default=120.0,
        help="Maximum capture duration in seconds (default 120).",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.interface:
        parser.error("interface cannot be empty")
    if not 1 <= args.count <= 100000:
        parser.error("--count must be between 1 and 100000")
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be between 1 and 3600 seconds")

    def emit(message):
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    provider = ScapyCaptureProvider()
    pipeline = ARPStatePipeline()
    try:
        emit({"type": "session", "interface": args.interface})
        provider.start(
            args.interface, build_handler(pipeline, emit),
            bpf_filter="arp", count=args.count, timeout=args.timeout,
        )
        provider.wait()
        emit({"type": "completed"})
    except (BrokenPipeError, KeyboardInterrupt):
        provider.stop()
        return 130
    except Exception as exc:
        provider.stop()
        # Do not send capture exception internals to the browser.
        print(f"Live ARP capture failed: {exc}", file=sys.stderr)
        try:
            emit({"type": "error", "message": "Capture helper failed; see terminal."})
        except BrokenPipeError:
            pass
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
