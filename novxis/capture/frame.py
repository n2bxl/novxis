"""Capture-layer evidence types owned by NOVXIS."""

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True, slots=True)
class CapturedFrame:
    """Raw frame evidence produced by a capture or replay provider."""

    timestamp: Decimal
    interface: str
    data: bytes
    captured_length: int
    original_length: int | None = None
    link_type: int | None = None
