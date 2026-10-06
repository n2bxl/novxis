"""Conservative request/reply correlation for ICMP Echo observations."""

from decimal import Decimal

from novxis.events.icmp import (
    ICMPEchoExchangeCompleted,
    ICMPEchoReplyObserved,
    ICMPEchoRequestObserved,
    ICMPMessageObserved,
)


class ICMPEchoCorrelator:
    """Correlate recent Echo Requests with strongly matching Echo Replies."""

    def __init__(self, max_age: Decimal = Decimal("5")) -> None:
        if max_age <= 0:
            raise ValueError("max_age must be greater than zero")
        self._max_age = max_age
        self._pending_requests: list[ICMPEchoRequestObserved] = []

    @property
    def pending_requests(self) -> tuple[ICMPEchoRequestObserved, ...]:
        """Return a snapshot of Echo Requests still awaiting a matching reply."""
        return tuple(self._pending_requests)

    def observe(
        self,
        observation: ICMPMessageObserved,
    ) -> ICMPEchoExchangeCompleted | None:
        """Process one observation and complete only a strongly matched exchange."""
        self._expire_requests(observation.timestamp)

        if isinstance(observation, ICMPEchoRequestObserved):
            self._pending_requests.append(observation)
            return None

        if not isinstance(observation, ICMPEchoReplyObserved):
            return None

        for index in range(len(self._pending_requests) - 1, -1, -1):
            request = self._pending_requests[index]

            if self._matches(request, observation):
                self._pending_requests.pop(index)
                return ICMPEchoExchangeCompleted(
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
        request: ICMPEchoRequestObserved,
        reply: ICMPEchoReplyObserved,
    ) -> bool:
        if request.interface != reply.interface:
            return False

        if reply.timestamp < request.timestamp:
            return False

        return (
            request.ipv4.source == reply.ipv4.destination
            and request.ipv4.destination == reply.ipv4.source
            and request.message.rest_of_header == reply.message.rest_of_header
            and request.message.payload == reply.message.payload
        )
