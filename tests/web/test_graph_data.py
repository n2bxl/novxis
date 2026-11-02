"""Acceptance tests for sanitized replay -> web graph projection."""

from novxis.web.graph_data import DEFAULT_FIXTURE, build_arp_graph


def test_sanitized_fixture_produces_actual_address_evidence():
    result = build_arp_graph(DEFAULT_FIXTURE)
    assert result["schema_version"] == 1
    assert result["mode"] == "offline-replay"
    assert result["source"]["frames_replayed"] == 8
    assert result["source"]["decode_errors"] == 0
    assert len(result["nodes"]) == 12
    assert len(result["claims"]) == 6
    assert {n["kind"] for n in result["nodes"]} == {"protocol", "hardware"}
    assert not any(
        n["display_address"] == "0.0.0.0"
        for n in result["nodes"]
    )


def test_each_claim_points_to_existing_scoped_nodes():
    result = build_arp_graph(DEFAULT_FIXTURE)
    nodes = {item["id"]: item for item in result["nodes"]}
    assert len(nodes) == 12
    for claim in result["claims"]:
        assert claim["kind"] == "arp_sender"
        assert nodes[claim["source"]]["kind"] == "protocol"
        assert nodes[claim["target"]]["kind"] == "hardware"
        assert claim["interface"] == "fixture"
        assert claim["observation_count"] >= 1


def test_repeated_sender_claim_retains_observation_count():
    result = build_arp_graph(DEFAULT_FIXTURE)
    by_id = {n["id"]: n for n in result["nodes"]}
    assert any(
        by_id[c["source"]]["display_address"] == "192.0.2.70"
        and c["observation_count"] == 2
        for c in result["claims"]
    )


def test_missing_capture_fails_without_fabricated_map(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        build_arp_graph(tmp_path / "missing.pcap")
