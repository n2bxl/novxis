"""Readable presentation of an individual observed DHCPv4 message."""

from novxis.events.dhcpv4 import DHCPv4MessageObserved
from novxis.presentation.ipv4_console import format_ipv4_address, format_timestamp

DHCPV4_MESSAGE_TYPES = {
    1: "DHCPDISCOVER",
    2: "DHCPOFFER",
    3: "DHCPREQUEST",
    4: "DHCPDECLINE",
    5: "DHCPACK",
    6: "DHCPNAK",
    7: "DHCPRELEASE",
    8: "DHCPINFORM",
}


def _single_option(message, code: int, expected_length: int) -> bytes | None:
    values = message.option_values(code)
    if len(values) != 1 or len(values[0]) != expected_length:
        return None
    return values[0]


def _human_duration(seconds: int) -> str:
    if seconds > 0 and seconds % 86400 == 0:
        unit = "day" if seconds == 86400 else "days"
        return f"{seconds // 86400} {unit}"
    if seconds > 0 and seconds % 3600 == 0:
        unit = "hour" if seconds == 3600 else "hours"
        return f"{seconds // 3600} {unit}"
    return f"{seconds} seconds"


def format_dhcpv4_observation(observation: DHCPv4MessageObserved) -> str:
    """Format packet evidence without making DHCP state or reachability claims."""
    udp = observation.udp
    ip = observation.ipv4
    msg = observation.message
    kind = DHCPV4_MESSAGE_TYPES.get(
        msg.message_type, f"DHCP_TYPE_{msg.message_type}"
    ) if msg.message_type is not None else "DHCP_TYPE_UNKNOWN"
    parts = [
        f"[{format_timestamp(observation.timestamp)}]",
        f"DHCPv4MessageObserved interface={observation.interface}",
        f"{kind}",
        f"{format_ipv4_address(ip.source)}:{udp.source_port} → "
        f"{format_ipv4_address(ip.destination)}:{udp.destination_port}",
        f"xid=0x{msg.xid:08x}",
    ]

    requested = _single_option(msg, 50, 4)
    if requested is not None:
        parts.append(f"requested_ip={format_ipv4_address(requested)}")
    if msg.yiaddr != bytes(4):
        parts.append(f"yiaddr={format_ipv4_address(msg.yiaddr)}")
    server = _single_option(msg, 54, 4)
    if server is not None:
        parts.append(f"server_identifier={format_ipv4_address(server)}")

    lease = _single_option(msg, 51, 4)
    if lease is not None:
        duration = int.from_bytes(lease, "big")
        label = {
            3: "requested_lease",
            2: "offered_lease",
            5: "granted_lease",
        }.get(msg.message_type, "lease_option")
        parts.append(f"{label}={_human_duration(duration)} ({duration}s)")
    return " ".join(parts)


def print_dhcpv4_observation(observation: DHCPv4MessageObserved) -> None:
    print(format_dhcpv4_observation(observation))
