"""CLI entry point for the Phase 0 interface-enumeration spike."""

from novxis.capture.interfaces import list_interfaces


def main() -> int:
    """Print the network interfaces currently visible to Scapy."""
    interfaces = list_interfaces()

    if not interfaces:
        print("No network interfaces were reported by Scapy.")
        return 1

    print("NOVXIS capture interfaces:")
    for index, interface in enumerate(interfaces, start=1):
        print(f"{index:>2}. {interface}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
