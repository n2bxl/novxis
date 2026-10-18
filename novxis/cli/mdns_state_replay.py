"""Offline-only bounded mDNS/DNS-SD service-instance state summary."""

import argparse
from decimal import Decimal, InvalidOperation
from pathlib import Path
import sys

from novxis.capture.frame import CapturedFrame
from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider
from novxis.cli.mdns_replay import _DECODE_ERRORS
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.presentation.ipv4_console import format_timestamp
from novxis.presentation.mdns_state_console import format_mdns_service_snapshot
from novxis.state.mdns_services import MDNSServiceEvidenceState
from novxis.views.mdns_services import project_dnssd_advertisements


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Replay passive mDNS into bounded native DNS-SD service state."
    )
    p.add_argument("path", type=Path, help="Local PCAP/PCAPNG to replay.")
    p.add_argument("--count", type=int, default=0,
                   help="File frames read (0 means entire file).")
    p.add_argument("--interface-label", default="replay",
                   help="Fallback name if capture metadata has no interface.")
    p.add_argument("--after", type=str, default="0",
                   help="Snapshot seconds after last replay frame (>=0).")
    p.add_argument("--limit", type=int, default=40,
                   help="Max instances printed (0 means all).")
    p.add_argument("--max-instances", type=int, default=256,
                   help="Maximum retained service identities.")
    p.add_argument("--max-records-per-instance", type=int, default=128,
                   help="Maximum retained typed record variants per instance.")
    p.add_argument("--max-history", type=int, default=4096,
                   help="Maximum original advertisement observations retained.")
    return p


def main() -> int:
    args = build_parser().parse_args()
    parser = build_parser()
    if args.count < 0 or args.limit < 0:
        parser.error("--count and --limit must be zero or greater")
    if not args.interface_label:
        parser.error("--interface-label must not be empty")
    try:
        after = Decimal(args.after)
    except InvalidOperation:
        parser.error("--after must be a finite nonnegative number")
    if not after.is_finite() or after < 0:
        parser.error("--after must be a finite nonnegative number")
    for name in ("max_instances", "max_records_per_instance", "max_history"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")

    state = MDNSServiceEvidenceState(
        max_instances=args.max_instances,
        max_records_per_instance=args.max_records_per_instance,
        max_history=args.max_history,
    )
    pipeline = MDNSEventPipeline()
    counts = {"mdns": 0, "ads": 0, "errors": 0}
    last_frame: Decimal | None = None

    def handle(frame: CapturedFrame) -> None:
        nonlocal last_frame
        if last_frame is None or frame.timestamp > last_frame:
            last_frame = frame.timestamp
        try:
            observed = pipeline.process(frame)
            if observed is None:
                return
            advertisements = project_dnssd_advertisements(observed)
        except _DECODE_ERRORS as exc:
            counts["errors"] += 1
            print(
                f"[{format_timestamp(frame.timestamp)}] "
                f"{frame.interface} mDNS state decode failed: {exc}",
                file=sys.stderr,
            )
            return
        counts["mdns"] += 1
        for advertisement in advertisements:
            state.observe(observed, advertisement)
        counts["ads"] += len(advertisements)

    print("NOVXIS passive mDNS service state replay")
    print(f"path={args.path} count={args.count or 'all'} "
          f"snapshot_offset={after}s")
    try:
        frames = PcapReplayProvider().replay(
            args.path, handle,
            count=args.count, interface_label=args.interface_label,
        )
    except (OSError, PcapReplayError, ValueError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1

    # Use the last replay frame's timestamp, not today's wall clock. Real
    # PCAPs are historic, so wall-clock evaluation would expire everything.
    as_of = (last_frame if last_frame is not None else Decimal(0)) + after
    snapshots = state.snapshots(as_of)
    fresh = sum(1 for s in snapshots if s.has_fresh_ptr)
    print(
        f"\nFrames replayed: {frames}; mDNS messages: {counts['mdns']}; "
        f"DNS-SD PTR observations: {counts['ads']}; "
        f"instances retained: {len(snapshots)}; "
        f"fresh PTR instances: {fresh}; "
        f"no-fresh-PTR: {len(snapshots) - fresh}; "
        f"decode errors: {counts['errors']}"
    )
    print(f"Snapshot as_of={as_of} (capture time, not wall clock)")
    for snapshot in snapshots[:args.limit or None]:
        print(format_mdns_service_snapshot(snapshot))
    if args.limit and len(snapshots) > args.limit:
        print(f"Other retained instances: {len(snapshots) - args.limit}")
    return 0 if counts["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
