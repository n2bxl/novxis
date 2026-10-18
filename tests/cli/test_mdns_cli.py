"""Dual-stack mDNS live/replay CLIs without accessing a network or private PCAPs."""

from decimal import Decimal
import sys
from types import SimpleNamespace

import pytest

from novxis.cli import mdns_events, mdns_replay
from novxis.protocols.dns import DNSParseError


def _frame():
    return SimpleNamespace(timestamp=Decimal("100.125"), interface="synthetic0")


def _observed(*, family=4, response=False):
    return SimpleNamespace(
        ip_version=family,
        message=SimpleNamespace(is_response=response),
    )


class DummyReplayProvider:
    def __init__(self, frames=()):
        self.frames = frames
        self.parameters = None

    def replay(self, path, handler, *, interface_label, count):
        self.parameters = (str(path), interface_label, count)
        for frame in self.frames[:count or None]:
            handler(frame)
        return len(self.frames[:count or None])


class DummyLiveProvider:
    def __init__(self, frames=(), *, interrupt=False):
        self.frames = frames
        self.interrupt = interrupt
        self.parameters = None
        self.stopped = False

    def start(self, interface, handler, *, bpf_filter, count, timeout):
        self.parameters = (interface, bpf_filter, count, timeout)
        for frame in self.frames:
            handler(frame)

    def wait(self):
        if self.interrupt:
            raise KeyboardInterrupt

    def stop(self):
        self.stopped = True


def test_replay_counts_dual_stack_queries_responses(monkeypatch, capsys):
    provider = DummyReplayProvider([_frame(), _frame(), _frame()])
    outputs = []
    values = [
        _observed(family=4),
        _observed(family=6, response=True),
        None,
    ]
    calls = iter(values)
    monkeypatch.setattr(mdns_replay, "PcapReplayProvider", lambda: provider)
    monkeypatch.setattr(
        mdns_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: next(calls))
    )
    monkeypatch.setattr(mdns_replay, "print_mdns_observation", outputs.append)
    monkeypatch.setattr(sys, "argv", [
        "novxis-mdns-replay", "synthetic.pcapng", "--interface-label", "fixture0",
    ])
    assert mdns_replay.main() == 0
    assert provider.parameters == ("synthetic.pcapng", "fixture0", 0)
    assert len(outputs) == 2
    text = capsys.readouterr().out
    assert "Frames replayed: 3" in text
    assert "mDNS observations: 2" in text
    assert "IPv4=1, IPv6=1" in text
    assert "queries=1, responses=1" in text
    assert "decode errors: 0" in text


def test_replay_summary_only_suppresses_individual_packets(monkeypatch, capsys):
    provider = DummyReplayProvider([_frame()])
    prints = []
    monkeypatch.setattr(mdns_replay, "PcapReplayProvider", lambda: provider)
    monkeypatch.setattr(
        mdns_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: _observed())
    )
    monkeypatch.setattr(mdns_replay, "print_mdns_observation", prints.append)
    monkeypatch.setattr(sys, "argv", [
        "novxis-mdns-replay", "local.pcapng", "--summary-only", "--count", "1",
    ])
    assert mdns_replay.main() == 0
    assert provider.parameters == ("local.pcapng", "replay", 1)
    assert not prints
    assert "mDNS observations: 1" in capsys.readouterr().out


def test_replay_handles_malformed_mdns_without_stopping(monkeypatch, capsys):
    provider = DummyReplayProvider([_frame()])
    monkeypatch.setattr(mdns_replay, "PcapReplayProvider", lambda: provider)

    def malformed(_):
        raise DNSParseError("truncated mDNS message")

    monkeypatch.setattr(
        mdns_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=malformed)
    )
    monkeypatch.setattr(sys, "argv", ["novxis-mdns-replay", "bad.pcap"])
    assert mdns_replay.main() == 1
    captured = capsys.readouterr()
    assert "mDNS decode failed: truncated mDNS message" in captured.err
    assert "decode errors: 1" in captured.out


@pytest.mark.parametrize("args", [
    ["f.pcapng", "--count", "-1"],
    ["f.pcapng", "--interface-label", ""],
])
def test_replay_rejects_invalid_arguments(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["novxis-mdns-replay", *args])
    with pytest.raises(SystemExit) as e:
        mdns_replay.main()
    assert e.value.code == 2


def test_live_uses_passive_udp5353_bpf(monkeypatch, capsys):
    provider = DummyLiveProvider([_frame(), _frame()])
    result = iter([_observed(family=6), None])
    printed = []
    monkeypatch.setattr(mdns_events, "ScapyCaptureProvider", lambda: provider)
    monkeypatch.setattr(
        mdns_events, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: next(result))
    )
    monkeypatch.setattr(mdns_replay, "print_mdns_observation", printed.append)
    monkeypatch.setattr(sys, "argv", [
        "novxis-mdns-events", "en0", "--count", "5", "--timeout", "20",
    ])
    assert mdns_events.main() == 0
    assert provider.parameters == ("en0", "udp port 5353", 5, 20.0)
    assert len(printed) == 1
    assert "IPv4=0, IPv6=1" in capsys.readouterr().out


def test_live_keyboard_interrupt_stops_sniffer(monkeypatch, capsys):
    provider = DummyLiveProvider(interrupt=True)
    monkeypatch.setattr(mdns_events, "ScapyCaptureProvider", lambda: provider)
    monkeypatch.setattr(sys, "argv", ["novxis-mdns-events", "en0"])
    assert mdns_events.main() == 130
    assert provider.stopped
    assert "Capture stopped" in capsys.readouterr().out


@pytest.mark.parametrize("args", [
    ["en0", "--count", "-1"],
    ["en0", "--timeout", "0"],
    ["en0", "--timeout", "-1"],
])
def test_live_rejects_invalid_limits(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["novxis-mdns-events", *args])
    with pytest.raises(SystemExit) as e:
        mdns_events.main()
    assert e.value.code == 2
