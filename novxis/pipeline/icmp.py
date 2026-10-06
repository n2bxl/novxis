"""Shared Ethernet/IPv4/ICMP Echo event pipeline."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events.icmp import ICMPEchoExchangeCompleted, ICMPMessageObserved, observe_icmp
from novxis.events.icmp_correlator import ICMPEchoCorrelator
from novxis.pipeline.ipv4 import IPv4EvidencePipeline
from novxis.protocols.icmp import parse_icmp

IP_PROTOCOL_ICMP = 1
IPV4_FLAG_MORE_FRAGMENTS = 0b001


@dataclass(frozen=True, slots=True)
class ICMPProcessingResult:
    """One normalized ICMP observation and any Echo exchange it completed."""

    observation: ICMPMessageObserved
    exchange: ICMPEchoExchangeCompleted | None


class ICMPEventPipeline:
    """Process captured frames through Ethernet, IPv4, and ICMP Echo events."""

    def __init__(self, correlation_window: Decimal = Decimal("5")) -> None:
        self._ipv4 = IPv4EvidencePipeline()
        self._correlator = ICMPEchoCorrelator(max_age=correlation_window)

    @property
    def pending_requests(self):
        """Return Echo Requests still awaiting a matching reply."""
        return self._correlator.pending_requests

    def process(self, frame: CapturedFrame) -> ICMPProcessingResult | None:
        """Decode one unfragmented IPv4/ICMP frame and update Echo correlation."""
        ipv4_result = self._ipv4.process(frame)

        if ipv4_result is None:
            return None

        datagram = ipv4_result.datagram

        if datagram.protocol != IP_PROTOCOL_ICMP:
            return None

        if (
            datagram.fragment_offset != 0
            or datagram.flags & IPV4_FLAG_MORE_FRAGMENTS
        ):
            return None

        message = parse_icmp(datagram.payload)
        observation = observe_icmp(
            ipv4_result.captured,
            ipv4_result.ethernet,
            datagram,
            message,
        )
        exchange = self._correlator.observe(observation)

        return ICMPProcessingResult(
            observation=observation,
            exchange=exchange,
        )
