"""Conservative DNS query/response correlation over observed IPv4 UDP/53 traffic.

This correlator observes candidate related messages, not DNS correctness,
response authenticity, cache state, or physical host identity. Repeated
indistinguishable requests are quarantined instead of arbitrarily paired.
"""

from dataclasses import dataclass
from decimal import Decimal

from novxis.events.dns import DNSMessageObserved

type DNSQuestionIdentity = tuple[tuple[bytes, ...], int, int]
type DNSExchangeKey = tuple[
    str, bytes, bytes, int, int, int, int, tuple[DNSQuestionIdentity, ...]
]


@dataclass(frozen=True, slots=True)
class DNSExchangeCorrelated:
    """One unambiguous observed request/response pair, not a trusted answer."""

    request: DNSMessageObserved
    response: DNSMessageObserved

    @property
    def duration(self) -> Decimal:
        """Observed response timestamp minus request timestamp in seconds."""
        return self.response.timestamp - self.request.timestamp


def _question_identity(observation: DNSMessageObserved) -> tuple[DNSQuestionIdentity, ...]:
    """ASCII case-insensitive names, retaining question order, type and class."""
    return tuple(
        (tuple(label.lower() for label in question.name.labels),
         question.qtype, question.qclass)
        for question in observation.message.questions
    )


def _key(observation: DNSMessageObserved, *, is_response: bool) -> DNSExchangeKey:
    """Canonical request-direction key; reverse endpoints for a response."""
    ip = observation.ipv4
    udp = observation.udp
    source, destination = ip.source, ip.destination
    source_port, destination_port = udp.source_port, udp.destination_port
    if is_response:
        source, destination = destination, source
        source_port, destination_port = destination_port, source_port
    return (
        observation.interface, source, destination, source_port, destination_port,
        observation.message.header.transaction_id,
        observation.message.header.opcode,
        _question_identity(observation),
    )


def _eligible(observation: DNSMessageObserved) -> bool:
    """Only well-formed standard queries with question identity may correlate."""
    header = observation.message.header
    if header.opcode != 0 or not observation.message.questions:
        return False
    if header.is_response:
        return observation.udp.source_port == 53
    return observation.udp.destination_port == 53


class DNSCorrelator:
    """Pair exact DNS request/response evidence within a bounded time window.

    Key components: interface, reversed IPv4 endpoints and UDP ports,
    transaction ID, opcode, and each question's ASCII-insensitive QNAME,
    QTYPE and QCLASS. Identical outstanding queries may be retransmissions
    or separate requests; quarantine their shared key until the ambiguity
    window expires rather than choosing a candidate.

    An unmatched response remains available to the caller as its original
    DNSMessageObserved; this class never modifies or discards input evidence.
    The pending state is explicitly bounded in memory.
    """

    def __init__(
        self,
        max_age: Decimal = Decimal("10"),
        max_pending: int = 1024,
    ) -> None:
        if not max_age.is_finite() or max_age <= 0:
            raise ValueError("max_age must be finite and greater than zero")
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) or max_pending <= 0:
            raise ValueError("max_pending must be a positive integer")
        self._max_age = max_age
        self._max_pending = max_pending
        self._pending: list[DNSMessageObserved] = []
        self._ambiguous_until: dict[DNSExchangeKey, Decimal] = {}
        self._watermark: Decimal | None = None

    @property
    def pending_requests(self) -> tuple[DNSMessageObserved, ...]:
        return tuple(self._pending)

    def _expire(self, timestamp: Decimal) -> None:
        if self._watermark is None or timestamp > self._watermark:
            self._watermark = timestamp
        cutoff = self._watermark - self._max_age
        self._pending = [
            request for request in self._pending
            if request.timestamp >= cutoff
        ]
        self._ambiguous_until = {
            key: deadline for key, deadline in self._ambiguous_until.items()
            if deadline >= self._watermark
        }

    def observe(self, observation: DNSMessageObserved) -> DNSExchangeCorrelated | None:
        """Process one message; return a pairing only when unambiguous."""
        self._expire(observation.timestamp)
        if not _eligible(observation):
            return None

        is_response = observation.message.header.is_response
        key = _key(observation, is_response=is_response)

        if is_response:
            if key in self._ambiguous_until:
                return None
            matches = [
                (index, request)
                for index, request in enumerate(self._pending)
                if _key(request, is_response=False) == key
                and request.timestamp <= observation.timestamp
                and observation.timestamp - request.timestamp <= self._max_age
            ]
            if len(matches) != 1:
                return None
            index, request = matches[0]
            self._pending.pop(index)
            return DNSExchangeCorrelated(request=request, response=observation)

        # Don't resurrect an already expired request from an out-of-order
        # capture file; allow bounded timestamp jitter without a false match.
        if self._watermark - observation.timestamp > self._max_age:
            return None

        if key in self._ambiguous_until:
            self._ambiguous_until[key] = max(
                self._ambiguous_until[key], observation.timestamp + self._max_age
            )
            return None

        duplicates = [
            request for request in self._pending
            if _key(request, is_response=False) == key
        ]
        if duplicates:
            # Multiple plausible requests are indistinguishable on the wire
            # with the evidence currently available. None may be paired.
            self._pending = [
                request for request in self._pending
                if _key(request, is_response=False) != key
            ]
            self._ambiguous_until[key] = max(
                [observation.timestamp, *(item.timestamp for item in duplicates)]
            ) + self._max_age
            return None

        self._pending.append(observation)
        if len(self._pending) > self._max_pending:
            self._pending.pop(0)
        return None
