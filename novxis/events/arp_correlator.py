"""Conservative request/reply correlation for ARP observations."""

from decimal import Decimal

from novxis.events.arp import (
    ARPExchangeCompleted,
    ARPMessageObserved,
    ARPReplyObserved,
    ARPRequestObserved,
)


class ARPCorrelator:
    """Correlate ARP replies with recent requests while preserving uncertainty."""

    def __init__(self, max_age: Decimal = Decimal("5")) -> None:
        if max_age <= 0:
            raise ValueError("max_age must be greater than zero")
        self._max_age = max_age
        self._pending_requests: list[ARPRequestObserved] = []

    @property
    def pending_requests(self) -> tuple[ARPRequestObserved, ...]:
        """Return a snapshot of requests still awaiting a matching reply."""
        return tuple(self._pending_requests)

    def observe(
        self,
        observation: ARPMessageObserved,
    ) -> ARPExchangeCompleted | None:
        """Process one observation and return an exchange only on a strong match."""
        self._expire_requests(observation.timestamp)

        if isinstance(observation, ARPRequestObserved):
            self._pending_requests.append(observation)
            return None

        if not isinstance(observation, ARPReplyObserved):
            return None

        for index in range(len(self._pending_requests) - 1, -1, -1):
            request = self._pending_requests[index]

            if self._matches(request, observation):
                self._pending_requests.pop(index)
                return ARPExchangeCompleted(
                    request=request,
                    reply=observation,
                )

        return None

    def _expire_requests(self, timestamp: Decimal) -> None:
        self._pending_requests = [
            request
            for request in self._pending_requests
            if timestamp < request.timestamp
            or timestamp - request.timestamp <= self._max_age
        ]

    @staticmethod
    def _matches(
        request: ARPRequestObserved,
        reply: ARPReplyObserved,
    ) -> bool:
        request_message = request.message
        reply_message = reply.message

        if request.interface != reply.interface:
            return False

        if reply.timestamp < request.timestamp:
            return False

        return (
            request_message.hardware_type == reply_message.hardware_type
            and request_message.protocol_type == reply_message.protocol_type
            and request_message.hardware_length == reply_message.hardware_length
            and request_message.protocol_length == reply_message.protocol_length
            and request_message.sender_protocol == reply_message.target_protocol
            and request_message.target_protocol == reply_message.sender_protocol
            and request_message.sender_hardware == reply_message.target_hardware
        )
