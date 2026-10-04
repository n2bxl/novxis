"""Scapy-backed live capture provider."""

from collections.abc import Callable
from decimal import Decimal
from typing import Any

from scapy.sendrecv import AsyncSniffer

from novxis.capture.frame import CapturedFrame
from novxis.capture.provider import FrameHandler

SnifferFactory = Callable[..., Any]


class ScapyCaptureProvider:
    """Capture raw frames with Scapy without leaking Scapy packets downstream."""

    def __init__(self, sniffer_factory: SnifferFactory = AsyncSniffer) -> None:
        self._sniffer_factory = sniffer_factory
        self._sniffer: Any | None = None

    @property
    def is_running(self) -> bool:
        """Return whether the current Scapy sniffer is active."""
        return bool(self._sniffer is not None and self._sniffer.running)

    def start(
        self,
        interface: str,
        handler: FrameHandler,
        *,
        bpf_filter: str | None = None,
        count: int = 0,
        timeout: float | None = None,
    ) -> None:
        """Start asynchronous capture on one interface."""
        if self.is_running:
            raise RuntimeError("Capture is already running.")
        if not interface:
            raise ValueError("interface must not be empty")
        if count < 0:
            raise ValueError("count must be zero or greater")
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        def on_packet(packet: Any) -> None:
            handler(self._to_captured_frame(packet, interface))

        kwargs: dict[str, Any] = {
            "iface": interface,
            "prn": on_packet,
            "store": False,
            "count": count,
        }

        if bpf_filter:
            kwargs["filter"] = bpf_filter
        if timeout is not None:
            kwargs["timeout"] = timeout

        sniffer = self._sniffer_factory(**kwargs)
        self._sniffer = sniffer

        try:
            sniffer.start()
        except Exception:
            self._sniffer = None
            raise

    def stop(self) -> None:
        """Stop the active sniffer if it is still running."""
        if self._sniffer is not None and self._sniffer.running:
            self._sniffer.stop()

    def wait(self) -> None:
        """Block until the current sniffer exits."""
        if self._sniffer is not None:
            self._sniffer.join()

    @staticmethod
    def _to_captured_frame(packet: Any, interface: str) -> CapturedFrame:
        data = bytes(packet)
        wire_length = getattr(packet, "wirelen", None)

        return CapturedFrame(
            timestamp=Decimal(str(packet.time)),
            interface=interface,
            data=data,
            captured_length=len(data),
            original_length=int(wire_length) if wire_length is not None else None,
        )
