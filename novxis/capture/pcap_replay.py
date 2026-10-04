"""PCAP/PCAPNG replay provider for NOVXIS."""

from collections.abc import Callable
from decimal import Decimal
from os import PathLike
from typing import Any

from scapy.utils import RawPcapReader

from novxis.capture.frame import CapturedFrame
from novxis.capture.provider import FrameHandler

ReaderFactory = Callable[[str], Any]


class PcapReplayError(ValueError):
    """Raised when capture-file metadata cannot be represented safely."""


class PcapReplayProvider:
    """Replay raw packet bytes from PCAP or PCAPNG as CapturedFrame evidence."""

    def __init__(self, reader_factory: ReaderFactory = RawPcapReader) -> None:
        self._reader_factory = reader_factory

    def replay(
        self,
        path: str | PathLike[str],
        handler: FrameHandler,
        *,
        interface_label: str = "replay",
        count: int = 0,
    ) -> int:
        """Replay capture-file frames in file order and return the emitted count."""
        if not interface_label:
            raise ValueError("interface_label must not be empty")
        if count < 0:
            raise ValueError("count must be zero or greater")

        reader = self._reader_factory(str(path))
        emitted = 0

        try:
            for data, metadata in reader:
                handler(
                    self._to_captured_frame(
                        data,
                        metadata,
                        reader,
                        interface_label,
                    )
                )
                emitted += 1

                if count and emitted >= count:
                    break
        finally:
            reader.close()

        return emitted

    @classmethod
    def _to_captured_frame(
        cls,
        data: bytes,
        metadata: Any,
        reader: Any,
        interface_label: str,
    ) -> CapturedFrame:
        return CapturedFrame(
            timestamp=cls._timestamp(metadata, reader),
            interface=cls._interface(metadata, interface_label),
            data=bytes(data),
            captured_length=int(getattr(metadata, "caplen", len(data))),
            original_length=cls._optional_int(
                getattr(metadata, "wirelen", None)
            ),
            link_type=cls._link_type(metadata, reader),
        )

    @staticmethod
    def _timestamp(metadata: Any, reader: Any) -> Decimal:
        if hasattr(metadata, "sec") and hasattr(metadata, "usec"):
            resolution = Decimal(
                1_000_000_000 if getattr(reader, "nano", False) else 1_000_000
            )
            return Decimal(metadata.sec) + Decimal(metadata.usec) / resolution

        tshigh = getattr(metadata, "tshigh", None)
        tslow = getattr(metadata, "tslow", None)
        tsresol = getattr(metadata, "tsresol", None)

        if tshigh is None or tslow is None or not tsresol:
            raise PcapReplayError(
                "Capture frame does not include a replayable timestamp."
            )

        ticks = (int(tshigh) << 32) | int(tslow)
        return Decimal(ticks) / Decimal(int(tsresol))

    @staticmethod
    def _interface(metadata: Any, fallback: str) -> str:
        ifname = getattr(metadata, "ifname", None)

        if isinstance(ifname, bytes):
            return ifname.decode("utf-8", errors="replace")
        if isinstance(ifname, str) and ifname:
            return ifname

        return fallback

    @staticmethod
    def _link_type(metadata: Any, reader: Any) -> int | None:
        value = getattr(metadata, "linktype", None)

        if value is None:
            value = getattr(reader, "linktype", None)

        return PcapReplayProvider._optional_int(value)

    @staticmethod
    def _optional_int(value: Any) -> int | None:
        return int(value) if value is not None else None
