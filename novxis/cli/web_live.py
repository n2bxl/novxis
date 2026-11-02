"""Serve a read-only local 2D view driven by stdin from ARP capture helper.

Recommended:
  sudo .venv/bin/python -m novxis.cli.arp_live_stream en0 |
    .venv/bin/python -m novxis.cli.web_live

The web process is the non-privileged right side of the pipeline.
"""

import argparse
import sys
from threading import Thread

from novxis.web.live_state import LiveARPGraphState, consume_stream
from novxis.web.server import create_server


def build_parser():
    parser = argparse.ArgumentParser(
        description="Local, read-only ARP map receiving bounded NDJSON over stdin."
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--max-bindings", type=int, default=256)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 1 <= args.max_bindings <= 4096:
        parser.error("--max-bindings must be between 1 and 4096")
    state = LiveARPGraphState(max_bindings=args.max_bindings)
    try:
        server = create_server(state.snapshot, args.port)
    except OSError as exc:
        parser.exit(1, f"Local server could not start: {exc}\n")

    # The producer (potentially root) never runs the HTTP server.
    consumer = Thread(target=consume_stream, args=(sys.stdin, state), daemon=True)
    consumer.start()
    print(f"NOVXIS Live ARP 2D Debugger: http://127.0.0.1:{server.server_port}/",
          flush=True)
    print("Read-only localhost. Capture source is stdin. Ctrl+C stops the view.",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        # stdin reading ends when the producer closes its pipe. The daemon
        # cannot keep the web application running after Ctrl+C.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
