"""CLI replay contract without opening an interface or reading private traffic."""

from decimal import Decimal
from types import SimpleNamespace
import sys

import pytest

from novxis.cli import dhcpv4_replay
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
    return SimpleNamespace(timestamp=Decimal("100.125"), interface="replay")


def test_cli_reports_observed_messages_and_replay_metadata(monkeypatch, capsys):
    provider = DummyProvider([_frame()])
    msg = object()
    rendered = []
    monkeypatch.setattr(dhcpv4_replay, "PcapReplayProvider", lambda: provider)
    monkeypatch.setattr(
        dhcpv4_replay, "DHCPv4EventPipeline",
        lambda: SimpleNamespace(process=lambda frame: msg),
    )
    monkeypatch.setattr(dhcpv4_replay, "print_dhcpv4_observation", rendered.append)
    monkeypatch.setattr(
        sys, "argv",
        ["novxis-dhcpv4-replay", "synthetic.pcap", "--count", "8",
         "--interface-label", "lab0"],
    )
    assert dhcpv4_replay.main() == 0
    assert rendered == [msg]
    assert provider.settings == ("synthetic.pcap", "lab0", 8)
    assert "DHCPv4 observations: 1; decode errors: 0" in capsys.readouterr().out


def test_cli_continues_after_malformed_dhcp_message(monkeypatch, capsys):
    provider = DummyProvider([_frame()])
    monkeypatch.setattr(dhcpv4_replay, "PcapReplayProvider", lambda: provider)

    def invalid(frame):
        raise DHCPv4ParseError("invalid magic cookie")

    monkeypatch.setattr(
        dhcpv4_replay, "DHCPv4EventPipeline",
        lambda: SimpleNamespace(process=invalid),
    )
    monkeypatch.setattr(sys, "argv", ["novxis-dhcpv4-replay", "bad.pcap"])
    assert dhcpv4_replay.main() == 1
    result = capsys.readouterr()
    assert "decode failed: invalid magic cookie" in result.err
    assert "decode errors: 1" in result.out


@pytest.mark.parametrize(
    "arguments",
    [
        ["synthetic.pcap", "--count", "-1"],
        ["synthetic.pcap", "--interface-label", ""],
    ],
)
def test_cli_rejects_invalid_arguments(monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["novxis-dhcpv4-replay", *arguments])
    with pytest.raises(SystemExit) as exc:
        dhcpv4_replay.main()
    assert exc.value.code == 2
