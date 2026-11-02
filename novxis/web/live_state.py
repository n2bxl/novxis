"""Bounded, thread-safe live ARP graph assembled from local producer messages.

Only scoped binding facts cross the privilege boundary via a local pipe.
The live snapshot uses the same projection and JSON schema as offline replay.
"""

import json
from decimal import Decimal, InvalidOperation
from threading import Lock
from typing import TextIO

from novxis.state.arp import ARPBinding
from novxis.views.arp_address_map import project_arp_address_map
from novxis.web.graph_data import serialize_arp_snapshot

MAX_LINE = 4096


class LiveARPGraphState:
    def __init__(self, *, max_bindings: int = 256):
        if not 1 <= max_bindings <= 4096:
            raise ValueError("max_bindings must be between 1 and 4096")
        self._lock = Lock()
        self._bindings = {}
        self._revision = 0
        self._updates = 0
        self._errors = 0
        self._truncated = False
        self._status = "waiting"
        self._interface = None
        self._max_bindings = max_bindings

    def ingest(self, message: dict) -> None:
        """Validate untrusted NDJSON; never interpret it as a command."""
        if not isinstance(message, dict):
            raise ValueError("expected a JSON object")
        kind = message.get("type")
        if kind == "session":
            interface = message.get("interface")
            if not isinstance(interface, str) or not (
                1 <= len(interface) <= 128 and interface.isprintable()
            ):
                raise ValueError("invalid capture interface")
            with self._lock:
                if self._interface is not None and self._interface != interface:
                    raise ValueError("unexpected interface change")
                self._interface = interface
                self._status = "capturing"
                self._revision += 1
            return
        if kind == "completed":
            self.finish()
            return
        if kind == "error":
            self.mark_error("Capture helper reported an error; see terminal.")
            return
        if kind != "binding":
            raise ValueError("unknown message type")

        interface = message.get("interface")
        if not isinstance(interface, str) or not (
            1 <= len(interface) <= 128 and interface.isprintable()
        ):
            raise ValueError("invalid interface")
        htype = message.get("hardware_type")
        ptype = message.get("protocol_type")
        count = message.get("observation_count")
        if not all(type(v) is int for v in (htype, ptype, count)):
            raise ValueError("invalid ARP type or count")
        if not (0 <= htype <= 65535 and 0 <= ptype <= 65535 and 1 <= count <= 100000):
            raise ValueError("ARP type or count out of range")

        def decode_hex(key):
            value = message.get(key)
            if not isinstance(value, str) or not (
                2 <= len(value) <= 64 and len(value) % 2 == 0
            ):
                raise ValueError(f"invalid {key}")
            try:
                return bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError(f"invalid {key}") from exc

        protocol = decode_hex("protocol_hex")
        hardware = decode_hex("hardware_hex")
        if not any(protocol) or not any(hardware):
            raise ValueError("zero sender address is not a usable claim")
        try:
            first = Decimal(message["first_seen"])
            last = Decimal(message["last_seen"])
        except (KeyError, InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError("invalid observation timestamps") from exc
        if (not first.is_finite() or not last.is_finite()
                or first < 0 or last < first or last > Decimal("10000000000000")):
            raise ValueError("invalid timestamp order")
        binding = ARPBinding(
            interface=interface, hardware_type=htype, protocol_type=ptype,
            protocol_address=protocol, hardware_address=hardware,
            first_seen=first, last_seen=last, observation_count=count,
        )
        key = (interface, htype, ptype, protocol)
        with self._lock:
            if self._interface != interface:
                raise ValueError("binding is outside the capture session")
            if key not in self._bindings and len(self._bindings) >= self._max_bindings:
                self._truncated = True
                self._revision += 1
                return
            previous = self._bindings.get(key)
            if previous is not None:
                if previous.hardware_address != binding.hardware_address:
                    # NetworkState begins a new observation epoch on MAC changes.
                    if count != 1:
                        raise ValueError("changed claim must reset count")
                elif count <= previous.observation_count:
                    raise ValueError("non-increasing observation count")
            self._bindings[key] = binding
            self._updates += 1
            self._revision += 1

    def mark_error(self, _reason: str) -> None:
        with self._lock:
            self._errors += 1
            self._status = "error"
            self._revision += 1

    def finish(self) -> None:
        with self._lock:
            if self._status != "error":
                self._status = "ended"
            self._revision += 1

    def snapshot(self) -> dict:
        with self._lock:
            bindings = tuple(self._bindings.values())
            metadata = {
                "capture_name": "Live ARP",
                "interface": self._interface,
                "updates_seen": self._updates,
                "stream_errors": self._errors,
                "truncated": self._truncated,
                "max_bindings": self._max_bindings,
            }
            revision = self._revision
            status = self._status
        snapshot = project_arp_address_map(bindings)
        return serialize_arp_snapshot(
            snapshot, mode="live-arp", source=metadata,
            revision=revision, capture_status=status,
        )


def consume_stream(stream: TextIO, state: LiveARPGraphState) -> None:
    """Consume a finite local pipe, enforcing an upper bound per message."""
    try:
        while True:
            line = stream.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE or not line.endswith("\n"):
                state.mark_error("oversized record")
                # Drain the remainder without allocating an unlimited line.
                while line and not line.endswith("\n"):
                    line = stream.readline(MAX_LINE + 1)
                continue
            try:
                state.ingest(json.loads(line))
            except (ValueError, TypeError, OverflowError):
                state.mark_error("invalid stream record")
    except (OSError, UnicodeError):
        state.mark_error("pipe read error")
    finally:
        state.finish()
