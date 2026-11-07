"""Finite passive ARP + dual-stack mDNS capture for the local 2D debugger.

Only normalized binding/service metadata crosses stdout into the
unprivileged web process. Do not send raw frames, TXT data or payloads.
"""

import argparse
import json
import sys

from novxis.capture.scapy_provider import ScapyCaptureProvider
from novxis.cli.arp_live_stream import build_handler as build_arp_handler
from novxis.cli.mdns_replay import _DECODE_ERRORS as _MDNS_ERRORS
from novxis.pipeline import ARPStatePipeline
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.views.mdns_services import project_dnssd_advertisements

MAX_ADS_PER_MESSAGE = 6
MAX_NAME_LENGTH = 180


def mdns_message(observed, advertisements) -> dict:
    """Bound, preserve and label PTR-backed *response* service evidence."""
    candidates = []
    if observed.message.is_response:
        for item in advertisements:
            service_type = item.service_type.text
            instance = item.instance.text
            if not (
                1 <= len(service_type) <= MAX_NAME_LENGTH
                and 1 <= len(instance) <= MAX_NAME_LENGTH
            ):
                continue
            if len(candidates) == MAX_ADS_PER_MESSAGE:
                break
            candidates.append({
                "service_type": service_type,
                "instance": instance,
                "ttl": item.ptr_record.wire.ttl,
            })
    total = len(advertisements) if observed.message.is_response else 0
    return {
        "type": "mdns",
        "interface": observed.interface,
        "observed_at": str(observed.timestamp),
        "ip_version": observed.ip_version,
        "role": "response" if observed.message.is_response else "query",
        "advertisement_count": total,
        "advertisements": candidates,
    }


def build_handler(emit):
    """Demultiplex one capture stream into existing ARP/mDNS interpreters."""
    arp_handler = build_arp_handler(ARPStatePipeline(), emit)
    mdns_pipeline = MDNSEventPipeline()

    def on_frame(frame):
        arp_handler(frame)
        try:
            observed = mdns_pipeline.process(frame)
            if observed is None:
                return
            advertisements = project_dnssd_advertisements(observed)
            emit(mdns_message(observed, advertisements))
        except _MDNS_ERRORS:
            # A malformed mDNS candidate must not abort the ARP session.
            emit({"type": "mdns_decode_error", "interface": frame.interface})
    return on_frame


def build_parser():
    parser = argparse.ArgumentParser(
        description="Capture finite passive ARP and IPv4/IPv6 UDP/5353 evidence."
    )
    parser.add_argument("interface", help="Authorized interface such as en0.")
    parser.add_argument("--count", type=int, default=2000,
                        help="Combined matching frame limit (default 2000).")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="Maximum duration in seconds (default 120).")
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
    try:
        emit({
            "type": "session", "interface": args.interface,
            "protocols": ["arp", "mdns"],
        })
        provider.start(
            args.interface, build_handler(emit),
            bpf_filter="arp or udp port 5353",
            count=args.count, timeout=args.timeout,
        )
        provider.wait()
        emit({"type": "completed"})
    except (KeyboardInterrupt, BrokenPipeError):
        provider.stop()
        return 130
    except Exception as exc:
        provider.stop()
        print(f"Passive network capture failed: {exc}", file=sys.stderr)
        try:
            emit({"type": "error", "message": "Capture failed; see terminal."})
        except BrokenPipeError:
            pass
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
