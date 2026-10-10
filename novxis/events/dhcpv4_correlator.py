"""Conservative DHCPv4 request/response correlation and request-pattern evidence."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.events.dhcpv4 import DHCPv4MessageObserved


@dataclass(frozen=True, slots=True)
class DHCPv4ExchangeCompleted:
    """Related DHCP messages on one interface; not proof of client configuration."""

    request: DHCPv4MessageObserved
    reply: DHCPv4MessageObserved
    result: str  # "offer", "ack", "nak" or "inform-ack"
    request_pattern: str  # Evidence-based, never an OS-state assertion.

    @property
    def duration(self) -> Decimal:
        return self.reply.timestamp - self.request.timestamp


def _unique_option(message, code: int, length: int | None = None) -> bytes | None:
    values = message.option_values(code)
    if len(values) != 1 or (length is not None and len(values[0]) != length):
        return None
    return values[0]


def classify_dhcpv4_request(observation: DHCPv4MessageObserved) -> str:
    """Recognize RFC 2131 patterns without asserting a client's internal state."""
    message = observation.message
    if message.message_type == 1 and message.op == 1:
        return "DISCOVER"
    if message.message_type == 8 and message.op == 1:
        return "INFORM"
    if message.message_type != 3 or message.op != 1:
        return "UNKNOWN"

    ciaddr_zero = message.ciaddr == bytes(4)
    requested = _unique_option(message, 50, 4)
    server = _unique_option(message, 54, 4)
    server_absent = not message.option_values(54)
    requested_absent = not message.option_values(50)
    if ciaddr_zero and requested is not None and server is not None:
        return "SELECTING"
    if (
        ciaddr_zero and requested is not None and server_absent
        and observation.ipv4.source == bytes(4)
        and observation.ipv4.destination == b"\xff" * 4
    ):
        return "INIT-REBOOT"
    if not ciaddr_zero and requested_absent and server_absent:
        if observation.ipv4.destination == b"\xff" * 4:
            return "REBINDING"
        return "RENEWING"
    return "UNKNOWN"


class DHCPv4Correlator:
    """Correlate DHCP messages by xid, client identity, interface, and time.

    A DISCOVER may receive more than one OFFER; retain it until expiry.
    Completion of a REQUEST/ACK or REQUEST/NAK consumes that pending request.
    """

    def __init__(self, max_age: Decimal = Decimal("10")) -> None:
        if max_age <= 0:
            raise ValueError("max_age must be greater than zero")
        self._max_age = max_age
        self._pending: list[DHCPv4MessageObserved] = []

    @property
    def pending_requests(self) -> tuple[DHCPv4MessageObserved, ...]:
        return tuple(self._pending)

    def observe(self, observation: DHCPv4MessageObserved) -> DHCPv4ExchangeCompleted | None:
        self._pending = [
            event for event in self._pending
            if observation.timestamp < event.timestamp
            or observation.timestamp - event.timestamp <= self._max_age
        ]

        message = observation.message
        if message.op == 1 and message.message_type in (1, 3, 8):
            # Retransmissions may be observed more than once, but retain the
            # most recent copy to avoid synthesizing duplicate completions.
            for index, previous in enumerate(self._pending):
                if (
                    previous.message.message_type == message.message_type
                    and self._same_client(previous, observation)
                    and previous.message.xid == message.xid
                ):
                    self._pending.pop(index)
                    break
            self._pending.append(observation)
            return None

        if message.op != 2 or message.message_type not in (2, 5, 6):
            return None

        for index in range(len(self._pending) - 1, -1, -1):
            request = self._pending[index]
            expected = {
                (1, 2): "offer",
                (3, 5): "ack",
                (3, 6): "nak",
                (8, 5): "inform-ack",
            }.get((request.message.message_type, message.message_type))
            if expected is None or not self._matches(request, observation):
                continue
            # DISCOVER may receive separate offers from multiple servers.
            if expected != "offer":
                self._pending.pop(index)
            return DHCPv4ExchangeCompleted(
                request=request,
                reply=observation,
                result=expected,
                request_pattern=classify_dhcpv4_request(request),
            )
        return None

    @staticmethod
    def _same_client(
        request: DHCPv4MessageObserved, reply: DHCPv4MessageObserved
    ) -> bool:
        a, b = request.message, reply.message
        if (
            request.interface != reply.interface
            or a.htype != b.htype
            or a.hlen == 0
            or a.hlen != b.hlen
            or a.chaddr != b.chaddr
            or not any(a.chaddr)
        ):
            return False
        # Option 61 is opaque identity evidence, not necessarily an Ethernet MAC.
        # Repeated or malformed client IDs are ambiguous: do not match them.
        ids_a = a.option_values(61)
        ids_b = b.option_values(61)
        if len(ids_a) > 1 or len(ids_b) > 1:
            return False
        if any(len(identifier) < 2 for identifier in (*ids_a, *ids_b)):
            return False
        return not ids_a or not ids_b or ids_a[0] == ids_b[0]

    @classmethod
    def _matches(
        cls, request: DHCPv4MessageObserved, reply: DHCPv4MessageObserved
    ) -> bool:
        if (
            not cls._same_client(request, reply)
            or reply.timestamp < request.timestamp
            or request.message.xid != reply.message.xid
        ):
            return False
        if reply.message.message_type == 5:
            # If both sides identify an address, they must agree. INFORM ACK
            # does not assign an address and normally leaves yiaddr zero.
            requested = _unique_option(request.message, 50, 4)
            if requested is not None and reply.message.yiaddr not in (requested, bytes(4)):
                return False
            if (
                request.message.ciaddr != bytes(4)
                and reply.message.yiaddr not in (request.message.ciaddr, bytes(4))
            ):
                return False
        selected_server = _unique_option(request.message, 54, 4)
        replying_server = _unique_option(reply.message, 54, 4)
        if selected_server is not None and replying_server is not None:
            if selected_server != replying_server:
                return False
        return True
