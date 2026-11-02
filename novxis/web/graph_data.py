"""Project existing ARP state into safe, JSON-serializable 2D graph data.

No physical topology, live host status, or link connectivity is inferred.
Packet bytes never leave this module; only scoped address claims are returned.
"""

from ipaddress import IPv4Address
from pathlib import Path

from novxis.capture.pcap_replay import PcapReplayProvider
from novxis.pipeline import ARPStatePipeline, UnsupportedLinkTypeError
from novxis.protocols.arp import ARPParseError
from novxis.protocols.ethernet import EthernetParseError
from novxis.views.arp_address_map import project_arp_address_map


DEFAULT_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests" / "fixtures" / "arp_phase0_sanitized.pcap"
)

_DECODE_ERRORS = (
    EthernetParseError, ARPParseError, UnsupportedLinkTypeError,
)


def _display_address(kind: str, protocol_type: int, value: bytes) -> str:
    if kind == "hardware":
        return ":".join(f"{octet:02x}" for octet in value)
    if protocol_type == 0x0800 and len(value) == 4:
        return str(IPv4Address(value))
    return value.hex()


def serialize_arp_snapshot(
    snapshot, *, mode: str, source: dict,
    revision: int = 0, capture_status: str | None = None,
) -> dict:
    """Stable address-evidence API used for offline and live projections."""
    result = {
        "schema_version": 1,
        "mode": mode,
        "revision": revision,
        "source": source,
        "nodes": [
            {
                "id": node.key,
                "kind": node.kind,
                "interface": node.interface,
                "hardware_type": node.hardware_type,
                "protocol_type": node.protocol_type,
                "address_hex": node.address.hex(),
                "display_address": _display_address(
                    node.kind, node.protocol_type, node.address,
                ),
            }
            for node in snapshot.nodes
        ],
        "claims": [
            {
                "source": claim.protocol_node,
                "target": claim.hardware_node,
                "interface": claim.interface,
                "kind": claim.evidence_kind,
                "first_seen": str(claim.first_seen),
                "last_seen": str(claim.last_seen),
                "observation_count": claim.observation_count,
            }
            for claim in snapshot.claims
        ],
    }
    if capture_status is not None:
        result["capture_status"] = capture_status
    return result


def build_arp_graph(path: Path, *, interface_label: str = "fixture") -> dict:
    """Replay a local PCAP and emit address-only evidence from current state.

    The source path is only read at server startup. Captures are never
    uploaded, stored by the server, or returned as raw packet payloads.
    """
    if not interface_label:
        raise ValueError("interface_label must not be empty")
    if not path.is_file():
        raise FileNotFoundError(
            f"Capture not found: {path}. Pass --pcap PATH to select a local capture."
        )

    pipeline = ARPStatePipeline()
    decode_errors = 0

    def handle(frame):
        nonlocal decode_errors
        try:
            pipeline.process(frame)
        except _DECODE_ERRORS:
            decode_errors += 1

    frames = PcapReplayProvider().replay(
        path, handle, interface_label=interface_label,
    )
    snapshot = project_arp_address_map(pipeline.state.arp_bindings)
    return serialize_arp_snapshot(
        snapshot,
        mode="offline-replay",
        source={
            "capture_name": path.name,
            "frames_replayed": frames,
            "decode_errors": decode_errors,
            "scope": "ARP sender claims only",
        },
    )
