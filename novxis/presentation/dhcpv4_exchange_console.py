"""DHCPv4 correlation and ACK-derived snapshot presentation."""

from novxis.events.dhcpv4_correlator import DHCPv4ExchangeCompleted
from novxis.presentation.ipv4_console import format_ipv4_address
from novxis.state.dhcpv4 import (
    DHCPv4Acknowledgment,
    DHCPv4AcknowledgmentRecorded,
    DHCPv4AcknowledgmentUpdated,
    DHCPv4StateChange,
)


def format_dhcpv4_exchange(exchange: DHCPv4ExchangeCompleted) -> str:
    duration_ms = exchange.duration * 1000
    return (
        f"  DHCPv4ExchangeCompleted result={exchange.result} "
        f"request_pattern={exchange.request_pattern} "
        f"xid=0x{exchange.request.message.xid:08x} "
        f"response_interval={duration_ms:.3f}ms"
    )


def _format_address(value: bytes | None) -> str:
    return format_ipv4_address(value) if value is not None else "not_observed"


def format_dhcpv4_acknowledgment(value: DHCPv4Acknowledgment) -> str:
    client = ":".join(f"{part:02x}" for part in value.hardware_address)
    lease = (
        "infinite" if value.lease_seconds == 0xFFFFFFFF
        else f"{value.lease_seconds}s"
    )
    routers = ",".join(format_ipv4_address(ip) for ip in value.routers) or "-"
    dns = ",".join(format_ipv4_address(ip) for ip in value.dns_servers) or "-"
    return (
        f"interface={value.interface} client_hw={client} "
        f"acknowledged_address={format_ipv4_address(value.address)} "
        f"server_identifier={_format_address(value.server_identifier)} "
        f"acknowledged_lease={lease} "
        f"mask={_format_address(value.subnet_mask)} "
        f"routers={routers} dns={dns} "
        f"request_pattern={value.request_pattern} "
        f"ack_count={value.acknowledgment_count}"
    )


def print_dhcpv4_state_change(change: DHCPv4StateChange) -> None:
    label = (
        "DHCPv4AcknowledgmentRecorded"
        if isinstance(change, DHCPv4AcknowledgmentRecorded)
        else "DHCPv4AcknowledgmentUpdated"
    )
    print(f"  {label} {format_dhcpv4_acknowledgment(change.current)}")


def print_dhcpv4_state_snapshot(records: tuple[DHCPv4Acknowledgment, ...]) -> None:
    print("DHCPv4 latest ACK-derived configuration evidence (not live lease state)")
    if not records:
        print("  No matched DHCPREQUEST/DHCPACK with usable lease data.")
    for record in records:
        print(f"  {format_dhcpv4_acknowledgment(record)}")
