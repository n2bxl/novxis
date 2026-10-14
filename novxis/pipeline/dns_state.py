"""Composition of DNS decoding, conservative correlation, and RR evidence."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events.dns import DNSMessageObserved
from novxis.events.dns_correlator import DNSCorrelator, DNSExchangeCorrelated
from novxis.pipeline.dns import DNSEventPipeline
from novxis.state import DNSRecordEvidence, NetworkState


@dataclass(frozen=True, slots=True)
class DNSStateProcessingResult:
    """Decoded message, optional pairing, and zero-or-more recorded answers."""

    observation: DNSMessageObserved
    exchange: DNSExchangeCorrelated | None
    records: tuple[DNSRecordEvidence, ...]


class DNSStatePipeline:
    """Build evidence without declaring DNS responses trustworthy or hosts alive."""

    def __init__(self, correlation_window: Decimal = Decimal("10")) -> None:
        self._events = DNSEventPipeline()
        self._correlator = DNSCorrelator(max_age=correlation_window)
        self.state = NetworkState()

    @property
    def pending_requests(self) -> tuple[DNSMessageObserved, ...]:
        return self._correlator.pending_requests

    def process(self, frame: CapturedFrame) -> DNSStateProcessingResult | None:
        observation = self._events.process(frame)
        if observation is None:
            return None
        exchange = self._correlator.observe(observation)
        records = (
            self.state.observe_dns_exchange(exchange)
            if exchange is not None else ()
        )
        return DNSStateProcessingResult(observation, exchange, records)
