"""Shared ARP decode, observation, and correlation pipeline."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events import (
    ARPCorrelator,
    ARPExchangeCompleted,
    ARPMessageObserved,
    observe_arp,
)
from novxis.pipeline.link import UnsupportedLinkTypeError, validate_ethernet_link_type
from novxis.protocols.arp import parse_arp
from novxis.protocols.ethernet import ETHERTYPE_ARP, parse_ethernet


@dataclass(frozen=True, slots=True)
class ARPProcessingResult:
    """One normalized ARP observation and any exchange it completed."""

    observation: ARPMessageObserved
    exchange: ARPExchangeCompleted | None


class ARPEventPipeline:
    """Process captured frames through the Phase 0 ARP event path."""

    def __init__(self, correlation_window: Decimal = Decimal("5")) -> None:
        self._correlator = ARPCorrelator(max_age=correlation_window)

    @property
    def pending_requests(self):
        """Return requests still awaiting a matching reply."""
        return self._correlator.pending_requests

    def process(self, frame: CapturedFrame) -> ARPProcessingResult | None:
        """Decode one Ethernet/ARP frame and update correlation state."""
        validate_ethernet_link_type(frame.link_type)

        ethernet = parse_ethernet(frame.data)

        if ethernet.ether_type != ETHERTYPE_ARP:
            return None

        message = parse_arp(ethernet.payload)
        observation = observe_arp(frame, ethernet, message)
        exchange = self._correlator.observe(observation)

        return ARPProcessingResult(
            observation=observation,
            exchange=exchange,
        )
