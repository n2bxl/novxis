"""CLI behavior for read-only DNS relationship snapshots."""

from decimal import Decimal
from types import SimpleNamespace
import sys

import pytest

from novxis.cli import dns_relationships


class FakePipeline:
    last = None

    def __init__(self, correlation_window):
        self.window = correlation_window
        self.pending_requests = ("one",)
        self.state = SimpleNamespace(dns_relationships=object())
        FakePipeline.last = self

    def process(self, frame):
        return SimpleNamespace(
            observation=object(),
            exchange=object() if frame.timestamp > Decimal("101") else None,
            records=(object(), object()) if frame.timestamp > Decimal("101") else (),
        )


class FakeLiveProvider:
    last = None
    frames = (
        SimpleNamespace(timestamp=Decimal("102"), interface="en0"),
        SimpleNamespace(timestamp=Decimal("100"), interface="en0"),
    )

    def __init__(self):
        self.capture_args = None
        FakeLiveProvider.last = self

    def start(self, interface, handler, *, bpf_filter, count, timeout):
        self.capture_args = (interface, bpf_filter, count, timeout)
        for frame in self.frames:
            handler(frame)

    def wait(self):
        pass

    def stop(self):
        pass


class FakeReplayProvider:
    last = None
    frames = FakeLiveProvider.frames

    def __init__(self):
        FakeReplayProvider.last = self

    def replay(self, path, handler, *, interface_label, count):
        for frame in self.frames:
            handler(frame)
        return len(self.frames)


def _patch(monkeypatch):
    views = []
    projections = []

    def project(state, *, as_of, mode):
        projections.append((state, as_of, mode))
        return SimpleNamespace(marker="snapshot")

    monkeypatch.setattr(dns_relationships, "DNSStatePipeline", FakePipeline)
    monkeypatch.setattr(dns_relationships, "ScapyCaptureProvider", FakeLiveProvider)
    monkeypatch.setattr(dns_relationships, "PcapReplayProvider", FakeReplayProvider)
    monkeypatch.setattr(dns_relationships, "project_dns_relationships", project)
    monkeypatch.setattr(
        dns_relationships, "print_dns_relationship_snapshot", views.append
    )
    return projections, views


def test_live_aggregates_without_printing_every_message(monkeypatch, capsys):
    projections, views = _patch(monkeypatch)
    monkeypatch.setattr(sys, "argv", [
        "dns-relationships", "live", "en0",
        "--count", "20", "--timeout", "30",
    ])
    assert dns_relationships.main() == 0
    assert FakeLiveProvider.last.capture_args == ("en0", "udp port 53", 20, 30.0)
    assert projections == [(
        FakePipeline.last.state.dns_relationships, Decimal("102"), "latest",
    )]
    assert len(views) == 1 and views[0].marker == "snapshot"
    output = capsys.readouterr().out
    assert "Frames processed: 2" in output
    assert "DNS observations: 2" in output
    assert "correlated exchanges: 1" in output
    assert "DNS records observed: 2" in output
    assert "pending requests: 1" in output
    assert "decode errors: 0" in output


def test_replay_as_of_and_history_are_explicit_and_deterministic(
    monkeypatch, capsys,
):
    projections, views = _patch(monkeypatch)
    monkeypatch.setattr(sys, "argv", [
        "dns-relationships", "replay", "test.pcapng",
        "--history", "--as-of", "101.125",
        "--interface-label", "fixture",
    ])
    assert dns_relationships.main() == 0
    assert len(views) == 1
    assert projections[0][1:] == (Decimal("101.125"), "history")
    assert FakeReplayProvider.last is not None
    assert "Frames processed: 2" in capsys.readouterr().out


def test_empty_replay_does_not_fabricate_current_timestamp(monkeypatch, capsys):
    projections, views = _patch(monkeypatch)
    monkeypatch.setattr(FakeReplayProvider, "frames", ())
    monkeypatch.setattr(sys, "argv", [
        "dns-relationships", "replay", "empty.pcap",
    ])
    assert dns_relationships.main() == 0
    assert projections == []
    assert views == []
    assert "No capture timestamp available" in capsys.readouterr().out


def test_explicit_timestamp_with_empty_replay_allows_empty_projection(monkeypatch):
    projections, views = _patch(monkeypatch)
    monkeypatch.setattr(FakeReplayProvider, "frames", ())
    monkeypatch.setattr(sys, "argv", [
        "dns-relationships", "replay", "empty.pcap", "--as-of", "50",
    ])
    assert dns_relationships.main() == 0
    assert projections[0][1:] == (Decimal("50"), "latest")
    assert len(views) == 1


@pytest.mark.parametrize("args", [
    ["live", "en0", "--count", "-1"],
    ["live", "en0", "--timeout", "0"],
    ["live", "en0", "--timeout", "nan"],
    ["live", "en0", "--correlation-window", "NaN"],
    ["replay", "test.pcap", "--correlation-window", "-1"],
    ["replay", "test.pcap", "--as-of", "Infinity"],
    ["replay", "test.pcap", "--interface-label", ""],
])
def test_invalid_cli_parameters_are_rejected(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["dns-relationships", *args])
    with pytest.raises(SystemExit) as exc:
        dns_relationships.main()
    assert exc.value.code == 2


def test_optional_group_mode_consumes_projection_without_changing_pipeline(
    monkeypatch, capsys,
):
    projections, flat_views = _patch(monkeypatch)
    grouped_views = []
    grouped_inputs = []

    def group(snapshot):
        grouped_inputs.append(snapshot)
        return SimpleNamespace(marker="grouped")

    monkeypatch.setattr(dns_relationships, "group_dns_relationships", group)
    monkeypatch.setattr(
        dns_relationships, "print_dns_grouped_snapshot", grouped_views.append,
    )
    monkeypatch.setattr(sys, "argv", [
        "dns-relationships", "live", "en0",
        "--group", "--count", "20",
    ])
    assert dns_relationships.main() == 0
    assert len(projections) == 1
    assert len(grouped_inputs) == 1
    assert grouped_inputs[0].marker == "snapshot"
    assert len(grouped_views) == 1
    assert grouped_views[0].marker == "grouped"
    assert flat_views == []
    output = capsys.readouterr().out
    assert "DNS observations: 2" in output
    assert "correlated exchanges: 1" in output


def test_group_mode_can_be_used_with_replay_and_history(monkeypatch):
    projections, flat_views = _patch(monkeypatch)
    grouped_views = []
    monkeypatch.setattr(
        dns_relationships, "group_dns_relationships",
        lambda snapshot: SimpleNamespace(marker="replay-group"),
    )
    monkeypatch.setattr(
        dns_relationships, "print_dns_grouped_snapshot", grouped_views.append,
    )
    monkeypatch.setattr(sys, "argv", [
        "dns-relationships", "replay", "test.pcap",
        "--group", "--history", "--as-of", "101",
    ])
    assert dns_relationships.main() == 0
    assert projections[0][1:] == (Decimal("101"), "history")
    assert [view.marker for view in grouped_views] == ["replay-group"]
    assert flat_views == []
