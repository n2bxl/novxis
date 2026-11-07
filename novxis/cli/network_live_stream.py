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


MAX_SERVICE_TARGETS = 2
MAX_TARGET_ADDRESSES = 3
MAX_ENCODED_EVENT = 3700  # leave space under consumer MAX_LINE=4096


def _safe_name(value: str) -> bool:
    return 1 <= len(value) <= MAX_NAME_LENGTH and value.isprintable()


def _target_details(claim) -> dict | None:
    """One same-message SRV assertion with its exact owner-matched A/AAAA."""
    target = claim.srv.target.text
    if not _safe_name(target):
        return None
    addresses = []
    for rr in claim.address_records[:MAX_TARGET_ADDRESSES]:
        wire = rr.wire
        if wire.rtype not in (1, 28) or wire.decoded_data is None:
            continue
        addresses.append({
            "address": wire.decoded_data,
            "family": 4 if wire.rtype == 1 else 6,
            "ttl": wire.ttl,
        })
    return {
        "target": target,
        "port": claim.srv.port,
        "ttl": claim.srv_record.wire.ttl,
        "addresses": addresses,
    }


def mdns_message(observed, advertisements) -> dict:
    """Bound same-response PTR -> SRV -> A/AAAA evidence, never a device."""
    total = len(advertisements) if observed.message.is_response else 0
    result = {
        "type": "mdns",
        "interface": observed.interface,
        "observed_at": str(observed.timestamp),
        "ip_version": observed.ip_version,
        "role": "response" if observed.message.is_response else "query",
        "advertisement_count": total,
        "advertisements": [],
        "relationships_omitted": False,
    }
    if not observed.message.is_response:
        return result

    for item in advertisements:
        service_type = item.service_type.text
        instance = item.instance.text
        if not (_safe_name(service_type) and _safe_name(instance)):
            continue
        if len(result["advertisements"]) >= MAX_ADS_PER_MESSAGE:
            break
        record = {
            "service_type": service_type, "instance": instance,
            "ttl": item.ptr_record.wire.ttl,
            "targets": [],
        }
        for claim in item.targets[:MAX_SERVICE_TARGETS]:
            target = _target_details(claim)
            if target is None:
                result["relationships_omitted"] = True
                continue
            # Keep a bounded message even with long DNS names and IPv6 RRs.
            record["targets"].append(target)
            candidate = [*result["advertisements"], record]
            encoded = {**result, "advertisements": candidate}
            if len(json.dumps(encoded, ensure_ascii=True)) > MAX_ENCODED_EVENT:
                record["targets"].pop()
                result["relationships_omitted"] = True
                break
        if len(item.targets) > MAX_SERVICE_TARGETS or any(
            len(target.address_records) > MAX_TARGET_ADDRESSES
            for target in item.targets
        ):
            result["relationships_omitted"] = True
        candidate = [*result["advertisements"], record]
        if len(json.dumps({**result, "advertisements": candidate},
                          ensure_ascii=True)) > MAX_ENCODED_EVENT:
            # No room even for the existing PTR-only observation.
            result["relationships_omitted"] = True
            continue
        result["advertisements"].append(record)
    if len(result["advertisements"]) < total:
        result["relationships_omitted"] = True
    return result

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
