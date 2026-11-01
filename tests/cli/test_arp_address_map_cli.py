"""Sanitized ARP replay validates the opt-in read-only address map."""

from pathlib import Path
import sys

from novxis.cli.arp_state_replay import main


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures" / "arp_phase0_sanitized.pcap"
)


def _replay(monkeypatch, capsys, *extra):
    monkeypatch.setattr(sys, "argv", [
        "novxis-arp-state-replay", str(FIXTURE),
        "--interface-label", "fixture", *extra,
    ])
    return main(), capsys.readouterr()


def test_opt_in_map_displays_fixture_state(monkeypatch, capsys):
    code, output = _replay(monkeypatch, capsys, "--map")
    assert code == 0
    assert output.err == ""
    assert "Observed ARP address map (sender claims only)" in output.out
    assert "sender claims=6" in output.out
    assert "192.0.2.70" in output.out
    assert "Evidence only: not verified physical devices" in output.out
    assert "Frames replayed: 8" in output.out


def test_replay_default_remains_unchanged(monkeypatch, capsys):
    code, output = _replay(monkeypatch, capsys)
    assert code == 0
    assert "ARP-derived network state" in output.out
    assert "Current ARP bindings: 6" in output.out
    assert "Observed ARP address map" not in output.out
