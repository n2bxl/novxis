"""Console view of normalized UDP evidence."""

from novxis.events.udp import UDPDatagramObserved
from novxis.presentation.ipv4_console import format_ipv4_address, format_timestamp


def print_udp_observation(observation: UDPDatagramObserved) -> None:
    ipv4 = observation.ipv4
    udp = observation.datagram
    print(
        f"[{format_timestamp(observation.timestamp)}] "
        f"UDPDatagramObserved interface={observation.interface} "
        f"{format_ipv4_address(ipv4.source)}:{udp.source_port} → "
        f"{format_ipv4_address(ipv4.destination)}:{udp.destination_port} "
        f"length={udp.length} payload={udp.payload_length} bytes "
        f"checksum=0x{udp.checksum:04x} "
        f"trailing={len(udp.trailing_bytes)} bytes"
    )
