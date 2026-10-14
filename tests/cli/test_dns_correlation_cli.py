"""Optional DNS correlation display contract for live and replay CLIs."""

from decimal import Decimal
from types import SimpleNamespace
import sys

import pytest

from novxis.cli import dns_events, dns_replay


class DummyCorrelator:
    last_instance = None

    def __init__(self):
        self.pending_requests = ()
        self.observed = []
        DummyCorrelator.last_instance = self

    def observe(self, observation):
        self.observed.append(observation)
        return SimpleNamespace(marker="matched") if len(self.observed) == 2 else None


class DummyLiveProvider:
    def __init__(self):
        self.settings = None

    def start(self, interface, handler, *, bpf_filter, count, timeout):
        self.settings = (interface, bpf_filter, count, timeout)
        frame = SimpleNamespace(timestamp=Decimal("100"), interface="test0")
        handler(frame)
        handler(frame)

    def wait(self):
        pass

    def stop(self):
        pass


class DummyReplayProvider:
    def replay(self, path, handler, *, interface_label, count):
        frame = SimpleNamespace(timestamp=Decimal("100"), interface=interface_label)
        handler(frame)
        handler(frame)
        return 2


@pytest.mark.parametrize("target", ["live", "replay"])
def test_optional_correlator_adds_exchange_lines_without_hiding_observations(
    monkeypatch, capsys, target
):
    module = dns_events if target == "live" else dns_replay
    observation = object()
    printed_events = []
    printed_pairs = []
    monkeypatch.setattr(module, "DNSEventPipeline", lambda: SimpleNamespace(
        process=lambda frame: observation,
    ))
    monkeypatch.setattr(module, "DNSCorrelator", DummyCorrelator)
    monkeypatch.setattr(module, "print_dns_observation", printed_events.append)
    monkeypatch.setattr(module, "print_dns_exchange", printed_pairs.append)

    if target == "live":
        provider = DummyLiveProvider()
        monkeypatch.setattr(module, "ScapyCaptureProvider", lambda: provider)
        monkeypatch.setattr(sys, "argv", [
            "novxis-dns-events", "en5", "--correlate", "--count", "2",
        ])
    else:
        monkeypatch.setattr(module, "PcapReplayProvider", DummyReplayProvider)
        monkeypatch.setattr(sys, "argv", [
            "novxis-dns-replay", "synthetic.pcap", "--correlate",
        ])

    assert module.main() == 0
    assert printed_events == [observation, observation]
    assert len(printed_pairs) == 1
    assert printed_pairs[0].marker == "matched"
    assert DummyCorrelator.last_instance.observed == [observation, observation]
    output = capsys.readouterr().out
    assert "DNS observations: 2" in output
    assert "Correlated exchanges: 1; pending requests: 0" in output
    if target == "live":
        assert provider.settings == ("en5", "udp port 53", 2, 45.0)


def test_default_live_mode_does_not_construct_correlator(monkeypatch):
    provider = DummyLiveProvider()
    monkeypatch.setattr(dns_events, "ScapyCaptureProvider", lambda: provider)
    monkeypatch.setattr(dns_events, "DNSEventPipeline", lambda: SimpleNamespace(
        process=lambda frame: None,
    ))

    def unexpected():
        raise AssertionError("Default observation mode must not correlate")

    monkeypatch.setattr(dns_events, "DNSCorrelator", unexpected)
    monkeypatch.setattr(sys, "argv", ["novxis-dns-events", "en5"])
    assert dns_events.main() == 0


def test_default_replay_mode_does_not_construct_correlator(monkeypatch):
    monkeypatch.setattr(dns_replay, "PcapReplayProvider", DummyReplayProvider)
    monkeypatch.setattr(dns_replay, "DNSEventPipeline", lambda: SimpleNamespace(
        process=lambda frame: None,
    ))

    def unexpected():
        raise AssertionError("Default replay observation must not correlate")

    monkeypatch.setattr(dns_replay, "DNSCorrelator", unexpected)
    monkeypatch.setattr(sys, "argv", ["novxis-dns-replay", "synthetic.pcap"])
    assert dns_replay.main() == 0
