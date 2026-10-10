"""CLI tests for correlated DHCPv4 replay and safe argument handling."""

from decimal import Decimal
from types import SimpleNamespace
import sys

import pytest

from novxis.cli import dhcpv4_state_replay
from novxis.protocols.dhcpv4 import DHCPv4ParseError


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
    return SimpleNamespace(timestamp=Decimal("100.125"), interface="lab0")


def test_empty_replay_prints_empty_snapshot(monkeypatch, capsys):
    provider = DummyProvider()
    monkeypatch.setattr(dhcpv4_state_replay, "PcapReplayProvider", lambda: provider)
    monkeypatch.setattr(sys, "argv", [
        "novxis-dhcpv4-state-replay", "fake.pcap", "--count", "30",
        "--interface-label", "lab0", "--correlation-window", "20",
    ])
    assert dhcpv4_state_replay.main() == 0
    assert provider.settings == ("fake.pcap", "lab0", 30)
    out = capsys.readouterr().out
    assert "DHCPv4 latest ACK-derived configuration evidence" in out
    assert "correlated exchanges: 0; decode errors: 0" in out


def test_errors_are_reported_without_creating_a_fictitious_exchange(
    monkeypatch, capsys
):
    provider = DummyProvider([_frame()])
    monkeypatch.setattr(dhcpv4_state_replay, "PcapReplayProvider", lambda: provider)

    def bad_event(frame):
        raise DHCPv4ParseError("invalid magic cookie")

    monkeypatch.setattr(
        dhcpv4_state_replay, "DHCPv4StatePipeline",
        lambda correlation_window: SimpleNamespace(
            process=bad_event,
            state=SimpleNamespace(dhcpv4_acknowledgments=()),
            pending_requests=(),
        ),
    )
    monkeypatch.setattr(
        sys, "argv", ["novxis-dhcpv4-state-replay", "bad.pcap"],
    )
    assert dhcpv4_state_replay.main() == 1
    result = capsys.readouterr()
    assert "decode failed: invalid magic cookie" in result.err
    assert "correlated exchanges: 0; decode errors: 1" in result.out


@pytest.mark.parametrize(
    "args",
    [
        ["fake.pcap", "--count", "-1"],
        ["fake.pcap", "--interface-label", ""],
        ["fake.pcap", "--correlation-window", "0"],
        ["fake.pcap", "--correlation-window", "-5"],
        ["fake.pcap", "--correlation-window", "NaN"],
    ],
)
def test_invalid_arguments_fail_before_opening_capture(monkeypatch, args):
    monkeypatch.setattr(
        sys, "argv", ["novxis-dhcpv4-state-replay", *args],
    )
    with pytest.raises(SystemExit) as error:
        dhcpv4_state_replay.main()
    assert error.value.code == 2
