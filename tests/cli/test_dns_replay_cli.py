"""DNS replay CLI tests without private PCAP files or file I/O."""

from decimal import Decimal
from types import SimpleNamespace
import sys

import pytest

from novxis.cli import dns_replay
from novxis.protocols.dns import DNSParseError


class DummyProvider:
    def __init__(self, frames=()):
        self.frames = frames
        self.settings = None

    def replay(self, path, handler, *, interface_label, count):
        self.settings = (str(path), interface_label, count)
        for frame in self.frames:
            handler(frame)
        return len(self.frames)


def _frame():
    return SimpleNamespace(timestamp=Decimal("100.125"), interface="replay")


def test_replay_emits_events_and_passes_metadata(monkeypatch, capsys):
    provider = DummyProvider([_frame(), _frame()])
    observed = object()
    rendered = []
    monkeypatch.setattr(dns_replay, "PcapReplayProvider", lambda: provider)
    monkeypatch.setattr(
        dns_replay, "DNSEventPipeline",
        lambda: SimpleNamespace(process=lambda frame: observed),
    )
    monkeypatch.setattr(dns_replay, "print_dns_observation", rendered.append)
    monkeypatch.setattr(sys, "argv", [
        "novxis-dns-replay", "synthetic.pcapng", "--count", "3",
        "--interface-label", "test0",
    ])
    assert dns_replay.main() == 0
    assert provider.settings == ("synthetic.pcapng", "test0", 3)
    assert rendered == [observed, observed]
    assert "DNS observations: 2; decode errors: 0" in capsys.readouterr().out


def test_replay_ignores_non_dns_packets(monkeypatch, capsys):
    provider = DummyProvider([_frame()])
    monkeypatch.setattr(dns_replay, "PcapReplayProvider", lambda: provider)
    monkeypatch.setattr(
        dns_replay, "DNSEventPipeline",
        lambda: SimpleNamespace(process=lambda frame: None),
    )
    monkeypatch.setattr(sys, "argv", ["novxis-dns-replay", "synthetic.pcap"])
    assert dns_replay.main() == 0
    assert "DNS observations: 0; decode errors: 0" in capsys.readouterr().out


def test_replay_continues_after_malformed_dns_message(monkeypatch, capsys):
    provider = DummyProvider([_frame()])
    monkeypatch.setattr(dns_replay, "PcapReplayProvider", lambda: provider)

    def invalid(frame):
        raise DNSParseError("bad DNS header")

    monkeypatch.setattr(
        dns_replay, "DNSEventPipeline",
        lambda: SimpleNamespace(process=invalid),
    )
    monkeypatch.setattr(sys, "argv", ["novxis-dns-replay", "bad.pcap"])
    assert dns_replay.main() == 1
    captured = capsys.readouterr()
    assert "decode failed: bad DNS header" in captured.err
    assert "decode errors: 1" in captured.out


@pytest.mark.parametrize("args", [
    ["synthetic.pcap", "--count", "-1"],
    ["synthetic.pcap", "--interface-label", ""],
])
def test_replay_rejects_invalid_arguments(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["novxis-dns-replay", *args])
    with pytest.raises(SystemExit) as error:
        dns_replay.main()
    assert error.value.code == 2
