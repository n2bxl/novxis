"""Service-state replay CLI contract without private files or live sockets."""

from decimal import Decimal
import sys
from types import SimpleNamespace

import pytest

from novxis.cli import mdns_state_replay
from novxis.protocols.dns import DNSParseError


def _frame(at: str):
    return SimpleNamespace(timestamp=Decimal(at), interface="test0")


class Replay:
    def __init__(self, frames):
        self.frames = frames
        self.called = None

    def replay(self, path, handler, *, count, interface_label):
        self.called = (str(path), count, interface_label)
        frames = self.frames[:count or None]
        for frame in frames:
            handler(frame)
        return len(frames)


class State:
    def __init__(self, **settings):
        self.settings = settings
        self.ads = []
        self.as_of = None

    def observe(self, source, ad):
        self.ads.append((source, ad))

    def snapshots(self, as_of):
        self.as_of = as_of
        return (SimpleNamespace(has_fresh_ptr=True),) if self.ads else ()


def test_replay_aggregates_with_explicit_capture_time(monkeypatch, capsys):
    provider = Replay([_frame("100"), _frame("101"), _frame("102")])
    state = State()
    seen = iter([
        SimpleNamespace(ip_version=4),
        None,
        SimpleNamespace(ip_version=6),
    ])
    monkeypatch.setattr(mdns_state_replay, "PcapReplayProvider", lambda: provider)
    monkeypatch.setattr(mdns_state_replay, "MDNSServiceEvidenceState", lambda **_: state)
    monkeypatch.setattr(
        mdns_state_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: next(seen)),
    )
    monkeypatch.setattr(
        mdns_state_replay, "project_dnssd_advertisements",
        lambda _: (object(),),
    )
    monkeypatch.setattr(
        mdns_state_replay, "format_mdns_service_snapshot",
        lambda _: "service=_demo._tcp.local",
    )
    monkeypatch.setattr(sys, "argv", [
        "novxis-mdns-state-replay", "synthetic.pcap",
        "--count", "3", "--after", "30.5",
    ])
    assert mdns_state_replay.main() == 0
    assert provider.called == ("synthetic.pcap", 3, "replay")
    assert state.as_of == Decimal("132.5")
    assert len(state.ads) == 2
    output = capsys.readouterr().out
    assert "DNS-SD PTR observations: 2" in output
    assert "instances retained: 1" in output
    assert "fresh PTR instances: 1" in output
    assert "service=_demo._tcp.local" in output
    assert "decode errors: 0" in output


def test_malformed_mdns_counts_error_and_keeps_other_frames(monkeypatch, capsys):
    provider = Replay([_frame("100"), _frame("101")])
    monkeypatch.setattr(mdns_state_replay, "PcapReplayProvider", lambda: provider)
    calls = 0

    def broken(_):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise DNSParseError("invalid mDNS")
        return None

    monkeypatch.setattr(
        mdns_state_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=broken),
    )
    monkeypatch.setattr(sys, "argv", ["novxis-mdns-state-replay", "bad.pcap"])
    assert mdns_state_replay.main() == 1
    captured = capsys.readouterr()
    assert "mDNS state decode failed: invalid mDNS" in captured.err
    assert "mDNS messages: 0" in captured.out
    assert "decode errors: 1" in captured.out


def test_empty_replay_is_valid_empty_snapshot(monkeypatch, capsys):
    monkeypatch.setattr(
        mdns_state_replay, "PcapReplayProvider",
        lambda: Replay([]),
    )
    monkeypatch.setattr(sys, "argv", [
        "novxis-mdns-state-replay", "empty.pcap",
    ])
    assert mdns_state_replay.main() == 0
    assert "instances retained: 0" in capsys.readouterr().out


@pytest.mark.parametrize("args", [
    ["x.pcap", "--count", "-1"],
    ["x.pcap", "--interface-label", ""],
    ["x.pcap", "--after", "-1"],
    ["x.pcap", "--after", "nan"],
    ["x.pcap", "--after", "Infinity"],
    ["x.pcap", "--after", "junk"],
    ["x.pcap", "--limit", "-1"],
    ["x.pcap", "--max-instances", "0"],
    ["x.pcap", "--max-records-per-instance", "-1"],
    ["x.pcap", "--max-history", "0"],
])
def test_invalid_replay_limits_rejected(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["novxis-mdns-state-replay", *args])
    with pytest.raises(SystemExit) as e:
        mdns_state_replay.main()
    assert e.value.code == 2
