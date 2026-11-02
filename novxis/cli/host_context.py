"""Inspect read-only macOS IPv4 host configuration without packet capture."""

import argparse
import json

from novxis.host_context import collect_host_ipv4_context
from novxis.host_context.macos import valid_interface_name


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show the selected interface's reported IPv4 configuration and OS default route."
    )
    parser.add_argument("interface", help="Local interface name, such as en0 or en5.")
    args = parser.parse_args()
    if not valid_interface_name(args.interface):
        parser.error("invalid interface name")
    result = collect_host_ipv4_context(args.interface)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in ("reported", "partial") else 1


if __name__ == "__main__":
    raise SystemExit(main())
