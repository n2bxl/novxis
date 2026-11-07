"""Stage 2: source vs target IPv6 claims, DAD, uncertainty and bounds.

Uses independently checksummed synthetic Ethernet/IPv6/ICMPv6 frames.
No real network activity and no MAC ownership or host identity inference.
"""

from dataclasses import replace
from decimal import Decimal
from ipaddress import IPv6Address

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.ndp import NeighborDiscoveryPipeline
from novxis.pipeline.ndp_state import NDStatePipeline
from novxis.state.ndp import (
    NDAddressClaim, NDNeighborEvidenceState, NDUnlinkedObservation,
)

SRC = IPv6Address("fe80::10").packed
TARGET = IPv6Address("2001:db8::20").packed
DEST = IPv6Address("fe80::21").packed
DAD_DEST = IPv6Address("ff02::1:ff00:20").packed
MAC_A = bytes.fromhex("02000000000a")
MAC_B = bytes.fromhex("02000000000b")
ETH_SRC = bytes.fromhex("0200000000cc")
SLLA = b"\x01\x01" + MAC_A
TLLA = b"\x02\x01" + MAC_A


def frame(*, kind=135, source=SRC, target=TARGET, destination=DEST,
          options=None, ethernet_source=ETH_SRC, interface="en0",
          timestamp="100", flags=0):
    if options is None:
        options = SLLA if kind == 135 else TLLA
    icmp = (
        bytes((kind, 0)) + bytes(2)
        + flags.to_bytes(4, "big") + target + options
    )
    pseudo = (
        source + destination + len(icmp).to_bytes(4, "big")
        + b"\x00\x00\x00\x3a"
    )
    data = pseudo + icmp
    if len(data) & 1:
        data += b"\x00"
    value = sum(
        int.from_bytes(data[i:i + 2], "big")
        for i in range(0, len(data), 2)
    )
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    icmp = icmp[:2] + ((~value) & 0xFFFF).to_bytes(2, "big") + icmp[4:]
    ipv6 = (
        bytes.fromhex("60000000") + len(icmp).to_bytes(2, "big")
        + bytes((58, 255)) + source + destination + icmp
    )
    data = (
        bytes.fromhex("333300000001") + ethernet_source
        + bytes.fromhex("86dd") + ipv6
    )
    return CapturedFrame(
        timestamp=Decimal(timestamp), interface=interface,
        data=data, captured_length=len(data),
        original_length=len(data), link_type=1,
    )


def observe(state: NDNeighborEvidenceState, **kwargs):
    decoded = NeighborDiscoveryPipeline().process(frame(**kwargs))
    assert decoded is not None
    return state.observe(decoded)


def test_ns_slla_is_a_source_claim_not_a_target_claim():
    state = NDNeighborEvidenceState()
    claim = observe(state)
    assert isinstance(claim, NDAddressClaim)
    assert claim.kind == "ns_source_slla"
    assert claim.interface == "en0"
    assert claim.ipv6_address == SRC
    assert claim.ipv6_address != TARGET
    assert claim.link_layer_address == MAC_A
    assert claim.link_layer_address != ETH_SRC
    assert claim.latest_observation.message.target == TARGET
    snap = state.snapshot()
    assert snap.solicitations == 1
    assert snap.distinct_claim_addresses == 1
    assert snap.unlinked == ()


def test_na_tlla_is_target_claim_even_when_sender_differs():
    state = NDNeighborEvidenceState()
    claim = observe(state, kind=136, flags=0xE0000000)
    assert isinstance(claim, NDAddressClaim)
    assert claim.kind == "na_target_tlla"
    assert claim.ipv6_address == TARGET
    assert claim.ipv6_address != SRC
    assert claim.link_layer_address == MAC_A
    assert claim.latest_observation.message.router
    assert claim.latest_observation.message.solicited
    assert claim.latest_observation.message.override


def test_na_without_tlla_does_not_use_ethernet_source_or_target():
    state = NDNeighborEvidenceState()
    result = observe(state, kind=136, options=b"")
    assert isinstance(result, NDUnlinkedObservation)
    assert result.reason == "na_missing_tlla"
    assert result.source_address == SRC
    assert result.target_address == TARGET
    assert state.snapshot().claims == ()
    assert len(state.snapshot().unlinked) == 1


def test_ns_without_slla_never_infers_mac_from_ethernet_source():
    state = NDNeighborEvidenceState()
    record = observe(state, kind=135, options=b"")
    assert record.reason == "ns_missing_slla"
    assert state.snapshot().claims == ()


def test_dad_probe_never_claims_tentative_ipv6_target():
    state = NDNeighborEvidenceState()
    record = observe(
        state, source=bytes(16), destination=DAD_DEST, options=b"",
    )
    assert isinstance(record, NDUnlinkedObservation)
    assert record.reason == "dad_tentative"
    assert record.target_address == TARGET
    snap = state.snapshot()
    assert snap.dad_probes == 1
    assert snap.claims == ()
    assert snap.solicitations == 1


@pytest.mark.parametrize("kind,options,reason", [
    (135, SLLA + SLLA, "ns_ambiguous_slla"),
    (136, TLLA + TLLA, "na_ambiguous_tlla"),
    (135, b"\x01\x02" + b"\x00" * 14, "ns_non_ethernet_slla"),
    (136, b"\x02\x02" + b"\x00" * 14, "na_non_ethernet_tlla"),
    (135, b"\x01\x01" + bytes(6), "ns_unusable_slla"),
    (136, b"\x02\x01" + bytes(6), "na_unusable_tlla"),
    (135, b"\x01\x01" + bytes.fromhex("01005e000001"), "ns_unusable_slla"),
])
def test_ambiguous_or_unusable_link_layer_options_are_not_claims(
    kind, options, reason
):
    state = NDNeighborEvidenceState()
    record = observe(state, kind=kind, options=options)
    assert record.reason == reason
    assert not state.snapshot().claims
    assert state.snapshot().unlinked[0].reason == reason


def test_unknown_tlv_does_not_create_binding():
    state = NDNeighborEvidenceState()
    record = observe(state, options=b"\xfa\x01" + MAC_A)
    assert record.reason == "ns_missing_slla"
    assert state.snapshot().claims == ()


def test_unlinked_na_with_different_ethernet_senders_remains_distinct():
    state = NDNeighborEvidenceState()
    observe(
        state, kind=136, options=b"", ethernet_source=MAC_A,
        timestamp="100",
    )
    observe(
        state, kind=136, options=b"", ethernet_source=MAC_B,
        timestamp="101",
    )
    snap = state.snapshot()
    assert not snap.claims
    assert len(snap.unlinked) == 2
    assert {x.latest_observation.ethernet.source for x in snap.unlinked} == {
        MAC_A, MAC_B,
    }


def test_conflicting_distinct_link_layers_remain_separate_evidence():
    state = NDNeighborEvidenceState()
    observe(state, options=b"\x01\x01" + MAC_A, timestamp="100")
    observe(state, options=b"\x01\x01" + MAC_B, timestamp="101")
    snap = state.snapshot()
    assert snap.messages == 2
    assert len(snap.claims) == 2
    assert {c.link_layer_address for c in snap.claims} == {MAC_A, MAC_B}
    assert snap.multiple_link_layer_addresses == 1
    # No confirmed duplicate device or verified address ownership.
    assert snap.distinct_claim_addresses == 1


def test_same_ipv6_on_different_capture_interfaces_is_not_fused():
    state = NDNeighborEvidenceState()
    observe(state, interface="en0", options=b"\x01\x01" + MAC_A)
    observe(state, interface="en5", options=b"\x01\x01" + MAC_B)
    snap = state.snapshot()
    assert len(snap.claims) == 2
    assert snap.distinct_claim_addresses == 2
    assert snap.multiple_link_layer_addresses == 0


def test_na_override_flag_does_not_silently_replace_other_mac_claim():
    state = NDNeighborEvidenceState()
    observe(state, kind=136, options=b"\x02\x01" + MAC_A, timestamp="100")
    observe(
        state, kind=136, options=b"\x02\x01" + MAC_B,
        flags=0x20000000, timestamp="101",
    )
    snap = state.snapshot()
    assert len(snap.claims) == 2
    assert snap.multiple_link_layer_addresses == 1


def test_same_mac_distinct_ns_na_provenance_is_not_a_false_conflict():
    state = NDNeighborEvidenceState()
    observe(state, source=TARGET, target=SRC, options=SLLA)
    observe(state, kind=136, target=TARGET, options=TLLA)
    snap = state.snapshot()
    assert {x.kind for x in snap.claims} == {
        "ns_source_slla", "na_target_tlla",
    }
    assert snap.distinct_claim_addresses == 1
    assert snap.multiple_link_layer_addresses == 0


def test_repeated_claim_updates_count_and_preserves_timestamp_bounds():
    state = NDNeighborEvidenceState()
    observe(state, timestamp="101")
    observe(state, timestamp="102")
    older = observe(state, timestamp="100")
    assert older.first_seen == Decimal("100")
    assert older.last_seen == Decimal("102")
    assert older.observation_count == 3
    assert older.latest_observation.captured.timestamp == Decimal("102")


def test_repeated_unlinked_observation_accumulates_without_becoming_claim():
    state = NDNeighborEvidenceState()
    observe(state, kind=136, options=b"", timestamp="100")
    record = observe(state, kind=136, options=b"", timestamp="101")
    assert record.observation_count == 2
    assert record.last_seen == Decimal("101")
    assert state.snapshot().claims == ()


def test_bounds_evict_oldest_evidence_and_label_incompleteness():
    state = NDNeighborEvidenceState(
        max_claims=1, max_unlinked=1, max_history=1,
    )
    observe(state, source=SRC, timestamp="100")
    observe(state, source=TARGET, timestamp="101")
    observe(state, kind=136, options=b"", timestamp="102")
    observe(state, kind=136, target=SRC, options=b"", timestamp="103")
    snap = state.snapshot()
    assert len(snap.claims) == 1
    assert len(snap.unlinked) == 1
    assert snap.messages == 4
    assert snap.omitted_claims == 1
    assert snap.omitted_unlinked == 1
    assert snap.history_truncated and snap.truncated
    assert len(state.history) == 1


@pytest.mark.parametrize("parameter", ["max_claims", "max_unlinked", "max_history"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_state_bounds_rejected(parameter, value):
    with pytest.raises(ValueError):
        NDNeighborEvidenceState(**{parameter: value})


def test_invalid_capture_timestamp_does_not_modify_state():
    state = NDNeighborEvidenceState()
    original = frame()
    fake = replace(original, timestamp=Decimal("NaN"))
    decoded = NeighborDiscoveryPipeline().process(fake)
    with pytest.raises(ValueError, match="timestamp"):
        state.observe(decoded)
    assert state.snapshot().messages == 0


def test_invalid_capture_interface_does_not_modify_state():
    state = NDNeighborEvidenceState()
    decoded = NeighborDiscoveryPipeline().process(
        replace(frame(), interface="")
    )
    with pytest.raises(ValueError, match="interface"):
        state.observe(decoded)
    assert state.snapshot().messages == 0


def test_pipeline_composes_decode_and_state_but_skips_unrelated_packets():
    pipeline = NDStatePipeline()
    result = pipeline.process(frame())
    assert result is not None
    assert result.observation.message.type == 135
    assert isinstance(result.evidence, NDAddressClaim)
    assert pipeline.state.snapshot().messages == 1
    unrelated = replace(
        frame(), data=frame().data[:12] + bytes.fromhex("0800") + frame().data[14:]
    )
    assert pipeline.process(unrelated) is None
    assert pipeline.state.snapshot().messages == 1


def test_state_and_pipeline_can_be_imported_in_either_order():
    # Package exports must not create a circular import in either direction.
    from novxis.state import NDNeighborEvidenceState as State
    from novxis.pipeline import NDStatePipeline as Pipeline
    assert State is NDNeighborEvidenceState
    assert Pipeline is NDStatePipeline
