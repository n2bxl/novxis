"""Composition of ARP event processing with derived network state."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.arp import ARPEventPipeline, ARPProcessingResult
from novxis.state import ARPStateChange, NetworkState


@dataclass(frozen=True, slots=True)
class ARPStateProcessingResult:
    """ARP event result plus any state change produced by its observation."""

    event: ARPProcessingResult
    state_change: ARPStateChange | None


class ARPStatePipeline:
    """Run captured frames through events and then derived network state."""

    def __init__(self, correlation_window: Decimal = Decimal("5")) -> None:
        self._events = ARPEventPipeline(correlation_window=correlation_window)
        self.state = NetworkState()

    @property
    def pending_requests(self):
        return self._events.pending_requests

    def process(self, frame: CapturedFrame) -> ARPStateProcessingResult | None:
        event_result = self._events.process(frame)

        if event_result is None:
            return None

        state_change = self.state.observe_arp(event_result.observation)

        return ARPStateProcessingResult(
            event=event_result,
            state_change=state_change,
        )
