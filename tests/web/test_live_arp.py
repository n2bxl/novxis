"""Live ARP producer/pipe/graph integration using the sanitized capture."""

import io
import json
from threading import Thread

import pytest

from novxis.capture.pcap_replay import PcapReplayProvider
from novxis.cli.arp_live_stream import build_handler
from novxis.pipeline import ARPStatePipeline
from novxis.web.graph_data import DEFAULT_FIXTURE, build_arp_graph
from novxis.web.live_state import LiveARPGraphState, MAX_LINE, consume_stream


def _published_messages():
    output = io.StringIO()
    output.write(json.dumps({"type": "session", "interface": "fixture"}) + "\n")
    pipeline = ARPStatePipeline()
    handler = build_handler(
        pipeline, lambda msg: output.write(json.dumps(msg) + "\n")
    )
    count = PcapReplayProvider().replay(
        DEFAULT_FIXTURE, handler, interface_label="fixture",
    )
    output.write(json.dumps({"type": "completed"}) + "\n")
    return count, output.getvalue()


def _binding():
    return {
        "type": "binding", "interface": "en0",
        "hardware_type": 1, "protocol_type": 0x0800,
        "protocol_hex": "c000020a", "hardware_hex": "02000000000a",
        "first_seen": "100", "last_seen": "100",
        "observation_count": 1,
    }


def test_sanitized_replay_through_producer_matches_offline_graph():
    frame_count, encoded = _published_messages()
    assert frame_count == 8
    state = LiveARPGraphState()
    consume_stream(io.StringIO(encoded), state)
    live = state.snapshot()
    offline = build_arp_graph(DEFAULT_FIXTURE, interface_label="fixture")
    assert live["mode"] == "live-arp"
    assert live["capture_status"] == "ended"
    assert live["source"]["interface"] == "fixture"
    assert live["source"]["updates_seen"] == 7
    assert live["nodes"] == offline["nodes"]
    assert live["claims"] == offline["claims"]
    assert len(live["nodes"]) == 12
    assert len(live["claims"]) == 6
    assert not live["source"]["truncated"]


def test_change_in_hardware_claim_replaces_latest_address_binding():
    state = LiveARPGraphState()
    state.ingest({"type": "session", "interface": "en0"})
    original = _binding()
    state.ingest(original)
    # A changed MAC resets the current NetworkState binding's count to 1.
    state.ingest({
        **original, "hardware_hex": "02000000000b",
        "first_seen": "101", "last_seen": "101",
        "observation_count": 1,
    })
    snap = state.snapshot()
    assert len(snap["claims"]) == 1
    assert any(n["address_hex"] == "02000000000b" for n in snap["nodes"])
    assert not any(n["address_hex"] == "02000000000a" for n in snap["nodes"])
    assert snap["claims"][0]["observation_count"] == 1


def test_binding_capacity_caps_unique_keys_but_allows_refresh():
    state = LiveARPGraphState(max_bindings=1)
    state.ingest({"type": "session", "interface": "en0"})
    message = _binding()
    state.ingest(message)
    state.ingest({**message, "protocol_hex": "c000020b"})
    state.ingest({**message, "last_seen": "101", "observation_count": 2})
    snap = state.snapshot()
    assert snap["source"]["truncated"]
    assert snap["source"]["updates_seen"] == 2
    assert len(snap["claims"]) == 1
    assert snap["claims"][0]["observation_count"] == 2


@pytest.mark.parametrize("change", [
    {"interface": "en5"},
    {"hardware_hex": "00"},
    {"protocol_hex": "0"},
    {"protocol_hex": "zz"},
    {"first_seen": "NaN"},
    {"last_seen": "99"},
    {"observation_count": True},
    {"observation_count": 0},
    {"protocol_type": 999999},
])
def test_rejects_bad_claims(change):
    state = LiveARPGraphState()
    state.ingest({"type": "session", "interface": "en0"})
    with pytest.raises(ValueError):
        state.ingest({**_binding(), **change})
    assert not state.snapshot()["claims"]


def test_oversized_pipe_record_rejected_and_stream_continues():
    state = LiveARPGraphState()
    content = "x" * (MAX_LINE + 50) + "\n"
    content += json.dumps({"type": "session", "interface": "en0"}) + "\n"
    consume_stream(io.StringIO(content), state)
    snap = state.snapshot()
    assert snap["capture_status"] == "error"
    assert snap["source"]["stream_errors"] == 1
    assert snap["source"]["interface"] == "en0"


def test_repeat_count_is_not_accepted_for_same_hardware_claim():
    state = LiveARPGraphState()
    state.ingest({"type": "session", "interface": "en0"})
    message = _binding()
    state.ingest(message)
    with pytest.raises(ValueError):
        state.ingest(message)


def test_snapshot_read_thread_safe_while_pipe_is_consumed():
    count, serialized = _published_messages()
    assert count == 8
    state = LiveARPGraphState()
    results = []
    consumer = Thread(target=consume_stream, args=(io.StringIO(serialized), state))
    consumer.start()
    for _ in range(20):
        results.append(state.snapshot())
    consumer.join(timeout=2)
    assert not consumer.is_alive()
    assert all(result["schema_version"] == 1 for result in results)
    assert state.snapshot()["capture_status"] == "ended"


def test_pipe_contains_binding_facts_not_raw_packet_payload():
    _, encoded = _published_messages()
    messages = [json.loads(line) for line in encoded.splitlines()]
    assert all(x["type"] in {"session", "binding", "completed"} for x in messages)
    assert all("payload" not in x and "data" not in x for x in messages)
    assert all("protocol_hex" in x and "hardware_hex" in x
               for x in messages if x["type"] == "binding")


def test_binding_without_session_is_rejected():
    state = LiveARPGraphState()
    with pytest.raises(ValueError):
        state.ingest(_binding())


def test_rejects_out_of_order_mac_change_count():
    state = LiveARPGraphState()
    state.ingest({"type": "session", "interface": "en0"})
    original = _binding()
    state.ingest(original)
    with pytest.raises(ValueError):
        state.ingest({**original, "hardware_hex": "02000000000b",
                      "observation_count": 2})


def test_live_metadata_remains_read_only_and_has_version():
    state = LiveARPGraphState()
    state.ingest({"type": "session", "interface": "en0"})
    snap = state.snapshot()
    assert snap["revision"] == 1
    assert snap["capture_status"] == "capturing"
    assert snap["schema_version"] == 1
    assert snap["source"]["max_bindings"] == 256
    assert snap["source"]["updates_seen"] == 0
