"""Serve a minimal browser-based 2D ARP evidence map on localhost only."""

import argparse
from pathlib import Path

from novxis.capture.pcap_replay import PcapReplayError
from novxis.web.graph_data import DEFAULT_FIXTURE, build_arp_graph
from novxis.web.server import create_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="View a passive, replay-backed ARP address map in a browser."
    )
    parser.add_argument(
        "--pcap", type=Path, default=DEFAULT_FIXTURE,
        help="Local PCAP/PCAPNG (defaults to the public sanitized ARP fixture).",
    )
    parser.add_argument(
        "--interface-label", default="fixture",
        help="Fallback interface for captures without an embedded name.",
    )
    parser.add_argument(
        "--port", type=int, default=8765,
        help="Loopback HTTP port (default: 8765).",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.interface_label:
        parser.error("--interface-label must not be empty")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    try:
        graph = build_arp_graph(args.pcap, interface_label=args.interface_label)
        server = create_server(graph, args.port)
    except (OSError, PcapReplayError, ValueError) as exc:
        parser.exit(1, f"NOVXIS preview failed: {exc}\n")

    url = f"http://127.0.0.1:{server.server_port}/"
    print("NOVXIS 2D evidence preview (offline ARP replay)", flush=True)
    print(f"Open {url} in your browser", flush=True)
    print(
        f"Capture: {graph['source']['capture_name']}; "
        f"{len(graph['nodes'])} address nodes; "
        f"{len(graph['claims'])} sender claims",
        flush=True,
    )
    print("Read-only; bound to localhost. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NOVXIS preview.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
