"""Composition of DHCPv4 evidence, exchange correlation, and ACK-derived state."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events.dhcpv4 import DHCPv4MessageObserved
from novxis.events.dhcpv4_correlator import DHCPv4Correlator, DHCPv4ExchangeCompleted
from novxis.pipeline.dhcpv4 import DHCPv4EventPipeline
from novxis.state import DHCPv4StateChange, NetworkState


@dataclass(frozen=True, slots=True)
class DHCPv4StateProcessingResult:
    observation: DHCPv4MessageObserved
    exchange: DHCPv4ExchangeCompleted | None
    state_change: DHCPv4StateChange | None


class DHCPv4StatePipeline:
    """Track DHCP messages, completed exchanges, and latest ACK evidence."""

    def __init__(self, correlation_window: Decimal = Decimal("10")) -> None:
        self._events = DHCPv4EventPipeline()
        self._correlator = DHCPv4Correlator(max_age=correlation_window)
        self.state = NetworkState()

    @property
    def pending_requests(self) -> tuple[DHCPv4MessageObserved, ...]:
        return self._correlator.pending_requests

    def process(self, frame: CapturedFrame) -> DHCPv4StateProcessingResult | None:
        observation = self._events.process(frame)
        if observation is None:
            return None
        exchange = self._correlator.observe(observation)
        change = (
            self.state.observe_dhcpv4_exchange(exchange)
            if exchange is not None else None
        )
        return DHCPv4StateProcessingResult(observation, exchange, change)
