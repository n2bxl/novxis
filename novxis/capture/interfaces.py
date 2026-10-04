"""Network-interface discovery for the capture layer."""

from scapy.all import get_if_list


def list_interfaces() -> tuple[str, ...]:
    """Return interface names reported by Scapy in Scapy's native order."""
    return tuple(get_if_list())
