"""Capture-provider contract used by the NOVXIS core."""

from collections.abc import Callable
from typing import Protocol

from novxis.capture.frame import CapturedFrame

FrameHandler = Callable[[CapturedFrame], None]


class CaptureProvider(Protocol):
    """Backend-neutral contract for live packet capture."""

    @property
    def is_running(self) -> bool:
        """Return whether the provider is actively capturing."""
        ...

    def start(
        self,
        interface: str,
        handler: FrameHandler,
        *,
        bpf_filter: str | None = None,
        count: int = 0,
        timeout: float | None = None,
    ) -> None:
        """Start capturing frames from an interface."""
        ...

    def stop(self) -> None:
        """Stop an active capture."""
        ...

    def wait(self) -> None:
        """Wait until the active capture finishes."""
        ...
