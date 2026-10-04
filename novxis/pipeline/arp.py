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
from novxis.protocols.arp import parse_arp
from novxis.protocols.ethernet import ETHERTYPE_ARP, parse_ethernet

DLT_EN10MB = 1


class UnsupportedLinkTypeError(ValueError):
    """Raised when a known capture link type is not Ethernet."""


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
        if frame.link_type not in (None, DLT_EN10MB):
            raise UnsupportedLinkTypeError(
                f"ARP Phase 0 supports Ethernet link type {DLT_EN10MB}; "
                f"got {frame.link_type}."
            )

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
