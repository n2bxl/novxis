"""Bounded, thread-safe live ARP graph assembled from local producer messages.

Only scoped binding facts cross the privilege boundary via a local pipe.
The live snapshot uses the same projection and JSON schema as offline replay.
"""

import json
import time
from uuid import uuid4
from decimal import Decimal, InvalidOperation
from threading import Lock
from typing import TextIO

from novxis.state.arp import ARPBinding
from novxis.views.arp_address_map import project_arp_address_map
from novxis.views.subnet_evidence import project_subnet_evidence
from novxis.views.mdns_arp_crossref import cross_reference_mdns_arp
from novxis.web.graph_data import serialize_arp_snapshot
from novxis.web.mdns_live import LiveMDNSState
from novxis.web.ndp_live import LiveNDPState
from novxis.web.unified_live import project_live_unified_address_graph
from novxis.web.dnssd_service_live import (
    build_live_dnssd_service_graph, serialize_dnssd_service_graph,
    service_graph_semantic_signature,
)
from novxis.views.mdns_ndp_crossref import cross_reference_mdns_ndp

MAX_LINE = 4096


class LiveARPGraphState:
    def __init__(self, *, max_bindings: int = 256, context_provider=None,
                 clock=time.time):
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
        self._context_provider = context_provider
        self._host_context = None
        self._context_attempted = False
        self._clock = clock
        self._mdns_enabled = False
        self._ndp_enabled = False
        self._mdns = LiveMDNSState()
        self._ndp = LiveNDPState()
        self._last_fresh_signature = ()
        self._graph_revision = 0
        self._unified_graph_revision = 0
        # A separate semantic revision for the full address + service view.
        # Deliberately excludes continuously advancing as_of timestamps.
        self._service_graph_revision = 0
        self._last_service_graph_signature = None
        # Opaque unprivileged session identity; not supplied by NDJSON.
        self._capture_scope = uuid4().hex

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
            protocols = message.get("protocols", ["arp"])
            if protocols not in (
                ["arp"], ["arp", "mdns"], ["arp", "mdns", "ndp"],
            ):
                raise ValueError("unsupported capture protocol set")
            needs_context = False
            with self._lock:
                if self._interface is not None and self._interface != interface:
                    raise ValueError("unexpected interface change")
                if self._interface is not None and (
                    self._mdns_enabled != ("mdns" in protocols)
                    or self._ndp_enabled != ("ndp" in protocols)
                ):
                    raise ValueError("unexpected capture protocol change")
                self._interface = interface
                self._mdns_enabled = "mdns" in protocols
                self._ndp_enabled = "ndp" in protocols
                # A previous malformed pipe record remains visible as error.
                if self._status != "error":
                    self._status = "capturing"
                self._revision += 1
                if self._context_provider is not None and not self._context_attempted:
                    self._context_attempted = True
                    needs_context = True
            if needs_context:
                # Subprocess-backed OS configuration queries must not run while
                # holding the ARP state lock or in the privileged producer.
                try:
                    context = self._context_provider(interface)
                except Exception:
                    # No raw subprocess errors or private command output
                    # should be transmitted to the browser.
                    context = {
                        "schema_version": 1, "origin": "local-os",
                        "status": "unavailable", "interface": interface,
                        "ipv4_addresses": [], "default_route": None,
                    }
                with self._lock:
                    self._host_context = context
                    self._revision += 1
            return
        if kind == "completed":
            self.finish()
            return
        if kind == "error":
            self.mark_error("Capture helper reported an error; see terminal.")
            return
        if kind in ("ndp", "ndp_decode_error"):
            with self._lock:
                if not self._ndp_enabled or message.get("interface") != self._interface:
                    raise ValueError("NDP event outside authorized capture session")
                if kind == "ndp":
                    self._ndp.observe(message, self._interface)
                    if message.get("claim_kind") is not None:
                        self._unified_graph_revision += 1
                else:
                    self._ndp.decode_error()
                self._revision += 1
            return
        if kind in (
            "mdns", "mdns_decode_error", "mdns_reconciliation",
            "mdns_reconciliation_clear", "mdns_reconciliation_omitted",
        ):
            with self._lock:
                if not self._mdns_enabled or message.get("interface") != self._interface:
                    raise ValueError("mDNS event outside authorized capture session")
                changed = True
                if kind == "mdns":
                    self._mdns.observe(message, self._interface)
                elif kind == "mdns_reconciliation":
                    changed = self._mdns.observe_reconciliation(message, self._interface)
                elif kind == "mdns_reconciliation_clear":
                    changed = self._mdns.clear_reconciliation(message, self._interface)
                elif kind == "mdns_reconciliation_omitted":
                    self._mdns.truncated = True
                else:
                    self._mdns.decode_error()
                if changed:
                    self._revision += 1
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
            self._graph_revision += 1
            self._unified_graph_revision += 1
            self._revision += 1

    def mark_error(self, _reason: str) -> None:
        with self._lock:
            self._errors += 1
            self._status = "error"
            self._revision += 1

    def finish(self) -> None:
        """Record a producer's explicit successful completion message."""
        with self._lock:
            if self._status != "error":
                self._status = "ended"
            self._revision += 1

    def close_input(self) -> None:
        """Unexpected pipe EOF is not evidence of a completed capture."""
        with self._lock:
            if self._status not in ("ended", "error"):
                self._errors += 1
                self._status = "error"
                self._revision += 1

    def snapshot(self) -> dict:
        with self._lock:
            bindings = tuple(self._bindings.values())
            mdns_evidence = None
            ndp_evidence = (
                self._ndp.snapshot(self._interface) if self._ndp_enabled else None
            )
            if self._mdns_enabled:
                mdns_evidence, signature = self._mdns.snapshot(
                    Decimal(str(self._clock())),
                )
                mdns_evidence["interface"] = self._interface
                if signature != self._last_fresh_signature:
                    self._last_fresh_signature = signature
                    self._revision += 1

            service_graph = None
            if mdns_evidence is not None and ndp_evidence is not None:
                # Build inside this same state lock so the projection, its
                # semantic revision, and all source snapshots are consistent.
                # No network/OS operation occurs in this pure projection.
                service_snapshot = build_live_dnssd_service_graph(
                    bindings, ndp_evidence, mdns_evidence,
                    interface=self._interface,
                    capture_scope=self._capture_scope,
                )
                service_signature = service_graph_semantic_signature(
                    service_snapshot,
                )
                if service_signature != self._last_service_graph_signature:
                    if (
                        self._last_service_graph_signature is not None
                        or service_snapshot.nodes or service_snapshot.edges
                        or service_snapshot.source_truncated
                        or service_snapshot.omitted_advertisements
                    ):
                        self._service_graph_revision += 1
                    self._last_service_graph_signature = service_signature
                service_graph = serialize_dnssd_service_graph(
                    service_snapshot, revision=self._service_graph_revision,
                    arp_truncated=self._truncated,
                    omitted_ndp_claims=ndp_evidence.get("omitted_claims", 0),
                    omitted_ndp_unlinked=ndp_evidence.get("omitted_unlinked", 0),
                )
            metadata = {
                "capture_name": (
                    "Live ARP + mDNS + NDP" if self._ndp_enabled else
                    "Live ARP + mDNS" if self._mdns_enabled else "Live ARP"
                ),
                "interface": self._interface,
                "updates_seen": self._updates,
                "stream_errors": self._errors,
                "truncated": self._truncated,
                "max_bindings": self._max_bindings,
            }
            revision = self._revision
            graph_revision = self._graph_revision
            unified_revision = self._unified_graph_revision
            capture_scope = self._capture_scope
            status = self._status
            context = self._host_context
        snapshot = project_arp_address_map(bindings)
        result = serialize_arp_snapshot(
            snapshot, mode="live-arp", source=metadata,
            revision=revision, capture_status=status,
        )
        result["graph_revision"] = graph_revision
        if ndp_evidence is not None:
            result["ndp_evidence"] = ndp_evidence
            # Separate payload; original ARP nodes/claims/graph_revision intact.
            result["unified_address_graph"] = project_live_unified_address_graph(
                bindings, ndp_evidence, interface=metadata["interface"],
                capture_scope=capture_scope, revision=unified_revision,
                arp_truncated=metadata["truncated"],
            )
        if mdns_evidence is not None:
            services = cross_reference_mdns_arp(
                mdns_evidence, result["nodes"],
            )
            if ndp_evidence is not None:
                services = cross_reference_mdns_ndp(services, ndp_evidence)
            result["mdns_evidence"] = services
        if service_graph is not None:
            # Additive sibling projection. Existing graph payloads and their
            # independently tracked revisions retain their exact semantics.
            result["unified_service_graph"] = service_graph
        if context is not None:
            result["host_context"] = context
            subnet = project_subnet_evidence(
                snapshot, context, capture_interface=metadata["interface"],
            )
            if subnet is not None:
                result["subnet_evidence"] = subnet
        return result


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
        state.close_input()
