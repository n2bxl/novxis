"""Service-only CLI mode without private captures or external network access."""

from decimal import Decimal
import sys
from types import SimpleNamespace

import pytest

from novxis.cli import mdns_events, mdns_replay
from novxis.protocols.dnssd import DNSSDParseError


def _frame():
    return SimpleNamespace(timestamp=Decimal("100.125"), interface="test0")


def _observation(response=True):
    return SimpleNamespace(
        ip_version=4,
        message=SimpleNamespace(is_response=response),
    )


class ReplayProvider:
    def __init__(self, frames):
        self.frames = frames

    def replay(self, path, handler, *, interface_label, count):
        for frame in self.frames[:count or None]:
            handler(frame)
        return len(self.frames[:count or None])


class LiveProvider:
    def start(self, interface, handler, *, bpf_filter, count, timeout):
        assert bpf_filter == "udp port 5353"
        handler(_frame())

    def wait(self):
        return None

    def stop(self):
        return None


def test_replay_service_mode_prints_advertisements_not_raw_packets(
    monkeypatch, capsys
):
    ad = object()
    rendered = []
    monkeypatch.setattr(
        mdns_replay, "PcapReplayProvider",
        lambda: ReplayProvider([_frame(), _frame()])
    )
    items = iter([_observation(), _observation(False)])
    monkeypatch.setattr(
        mdns_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: next(items))
    )
    calls = []
    def project(observation):
        calls.append(observation)
        return (ad,) if observation.message.is_response else ()
    monkeypatch.setattr(mdns_replay, "project_dnssd_advertisements", project)
    monkeypatch.setattr(
        mdns_replay, "print_dnssd_advertisement",
        lambda obs, item: rendered.append((obs, item))
    )
    monkeypatch.setattr(
        mdns_replay, "print_mdns_observation",
        lambda _: pytest.fail("Raw packet rendering must be suppressed")
    )
    monkeypatch.setattr(
        sys, "argv", ["novxis-mdns-replay", "private.pcapng", "--services"]
    )
    assert mdns_replay.main() == 0
    assert len(calls) == 2
    assert len(rendered) == 1 and rendered[0][1] is ad
    text = capsys.readouterr().out
    assert "mDNS observations: 2" in text
    assert "DNS-SD advertised PTRs: 1" in text
    assert "decode errors: 0" in text


def test_replay_services_summary_only_counts_without_printing(monkeypatch, capsys):
    monkeypatch.setattr(
        mdns_replay, "PcapReplayProvider",
        lambda: ReplayProvider([_frame()])
    )
    monkeypatch.setattr(
        mdns_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: _observation())
    )
    monkeypatch.setattr(
        mdns_replay, "project_dnssd_advertisements",
        lambda _: (object(), object())
    )
    monkeypatch.setattr(
        mdns_replay, "print_dnssd_advertisement",
        lambda *_: pytest.fail("summary-only must not print advertisements")
    )
    monkeypatch.setattr(
        sys, "argv", [
            "novxis-mdns-replay", "private.pcapng",
            "--services", "--summary-only"
        ]
    )
    assert mdns_replay.main() == 0
    assert "DNS-SD advertised PTRs: 2" in capsys.readouterr().out


def test_malformed_service_record_is_counted_not_crash(monkeypatch, capsys):
    monkeypatch.setattr(
        mdns_replay, "PcapReplayProvider",
        lambda: ReplayProvider([_frame()])
    )
    monkeypatch.setattr(
        mdns_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: _observation())
    )
    def broken(_):
        raise DNSSDParseError("invalid TXT length")
    monkeypatch.setattr(mdns_replay, "project_dnssd_advertisements", broken)
    monkeypatch.setattr(
        sys, "argv", ["novxis-mdns-replay", "bad.pcap", "--services"]
    )
    assert mdns_replay.main() == 1
    out = capsys.readouterr()
    assert "mDNS decode failed: invalid TXT length" in out.err
    assert "decode errors: 1" in out.out


def test_live_services_switch_passed_to_handler(monkeypatch, capsys):
    monkeypatch.setattr(mdns_events, "ScapyCaptureProvider", LiveProvider)
    monkeypatch.setattr(
        mdns_events, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: _observation())
    )
    monkeypatch.setattr(
        mdns_replay, "project_dnssd_advertisements",
        lambda _: (object(),)
    )
    monkeypatch.setattr(
        mdns_replay, "print_dnssd_advertisement",
        lambda *_: None
    )
    monkeypatch.setattr(
        sys, "argv", ["novxis-mdns-events", "en0", "--services", "--count", "1"]
    )
    assert mdns_events.main() == 0
    assert "DNS-SD advertised PTRs: 1" in capsys.readouterr().out


def test_service_display_is_opt_in(monkeypatch):
    processed = []
    monkeypatch.setattr(
        mdns_replay, "project_dnssd_advertisements",
        lambda _: pytest.fail("Default mDNS mode should not project services")
    )
    handler = mdns_replay._build_handler(
        SimpleNamespace(process=lambda _: _observation()),
        mdns_replay._make_counts(),
        summary_only=True,
    )
    handler(_frame())
    processed.append(True)
    assert processed
