"""DHCPv4 ACK-derived configuration snapshots, not verified live leases."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.events.dhcpv4_correlator import DHCPv4ExchangeCompleted


@dataclass(frozen=True, slots=True)
class DHCPv4Acknowledgment:
    """Most recently observed matched DHCPACK for one client on one interface."""

    interface: str
    hardware_type: int
    hardware_address: bytes
    client_identifier: bytes | None
    address: bytes
    server_identifier: bytes | None
    lease_seconds: int
    subnet_mask: bytes | None
    routers: tuple[bytes, ...]
    dns_servers: tuple[bytes, ...]
    request_pattern: str
    first_seen: Decimal
    last_seen: Decimal
    acknowledgment_count: int

    # This record never asserts a host installed its address or remains online.


@dataclass(frozen=True, slots=True)
class DHCPv4AcknowledgmentRecorded:
    current: DHCPv4Acknowledgment
    source: DHCPv4ExchangeCompleted


@dataclass(frozen=True, slots=True)
class DHCPv4AcknowledgmentUpdated:
    previous: DHCPv4Acknowledgment
    current: DHCPv4Acknowledgment
    source: DHCPv4ExchangeCompleted


DHCPv4StateChange = DHCPv4AcknowledgmentRecorded | DHCPv4AcknowledgmentUpdated
DHCPv4ClientKey = tuple[str, int, bytes, bytes | None]


def _option(message, code: int, length: int | None = None) -> bytes | None:
    values = message.option_values(code)
    if len(values) != 1 or (length is not None and len(values[0]) != length):
        return None
    return values[0]


def _ipv4_list(message, code: int) -> tuple[bytes, ...]:
    value = _option(message, code)
    if value is None or not value or len(value) % 4:
        return ()
    return tuple(value[offset:offset + 4] for offset in range(0, len(value), 4))


class DHCPv4AcknowledgmentState:
    """Maintain latest matched DHCPACK evidence without declaring reachability."""

    def __init__(self) -> None:
        self._acknowledgments: dict[DHCPv4ClientKey, DHCPv4Acknowledgment] = {}

    @property
    def acknowledgments(self) -> tuple[DHCPv4Acknowledgment, ...]:
        return tuple(self._acknowledgments.values())

    def observe_exchange(
        self, exchange: DHCPv4ExchangeCompleted
    ) -> DHCPv4StateChange | None:
        if exchange.result != "ack" or exchange.request.message.message_type != 3:
            # OFFER, NAK and INFORM ACK never establish a DHCP lease.
            return None
        request = exchange.request.message
        reply = exchange.reply.message
        lease = _option(reply, 51, 4)
        if (
            reply.yiaddr == bytes(4) or lease is None
            or request.hlen == 0 or not any(request.chaddr)
        ):
            return None

        identity = _option(request, 61)
        key: DHCPv4ClientKey = (
            exchange.request.interface,
            request.htype,
            request.chaddr,
            identity,
        )
        previous = self._acknowledgments.get(key)
        current = DHCPv4Acknowledgment(
            interface=exchange.request.interface,
            hardware_type=request.htype,
            hardware_address=request.chaddr,
            client_identifier=identity,
            address=reply.yiaddr,
            server_identifier=_option(reply, 54, 4),
            lease_seconds=int.from_bytes(lease, "big"),
            subnet_mask=_option(reply, 1, 4),
            routers=_ipv4_list(reply, 3),
            dns_servers=_ipv4_list(reply, 6),
            request_pattern=exchange.request_pattern,
            first_seen=previous.first_seen if previous is not None else exchange.reply.timestamp,
            last_seen=exchange.reply.timestamp,
            acknowledgment_count=(
                previous.acknowledgment_count + 1 if previous is not None else 1
            ),
        )
        self._acknowledgments[key] = current
        if previous is None:
            return DHCPv4AcknowledgmentRecorded(current, exchange)
        return DHCPv4AcknowledgmentUpdated(previous, current, exchange)
