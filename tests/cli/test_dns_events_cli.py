"""Live DNS CLI contract without opening a network capture interface."""

from decimal import Decimal
from types import SimpleNamespace
import sys

import pytest

from novxis.cli import dns_events
from novxis.protocols.dns import DNSParseError


class DummyProvider:
    def __init__(self, frames=(), *, interrupt=False):
        self.frames = frames
        self.interrupt = interrupt
        self.parameters = None
        self.was_stopped = False

    def start(self, interface, handler, *, bpf_filter, count, timeout):
        self.parameters = (interface, bpf_filter, count, timeout)
        for frame in self.frames:
            handler(frame)

    def wait(self):
        if self.interrupt:
            raise KeyboardInterrupt

    def stop(self):
        self.was_stopped = True


def _frame():
    return SimpleNamespace(timestamp=Decimal("100.125"), interface="en0")


def test_live_passively_filters_port_53_and_displays_events(monkeypatch, capsys):
    provider = DummyProvider([_frame()])
    observed = object()
    printed = []
    monkeypatch.setattr(dns_events, "ScapyCaptureProvider", lambda: provider)
    monkeypatch.setattr(
        dns_events, "DNSEventPipeline",
        lambda: SimpleNamespace(process=lambda frame: observed),
    )
    monkeypatch.setattr(dns_events, "print_dns_observation", printed.append)
    monkeypatch.setattr(sys, "argv", [
        "novxis-dns-events", "en0", "--count", "5", "--timeout", "15",
    ])
    assert dns_events.main() == 0
    assert provider.parameters == ("en0", "udp port 53", 5, 15.0)
    assert printed == [observed]
    assert "DNS observations: 1; decode errors: 0" in capsys.readouterr().out


def test_live_collects_decoder_errors_without_aborting_capture(monkeypatch, capsys):
    provider = DummyProvider([_frame()])
    monkeypatch.setattr(dns_events, "ScapyCaptureProvider", lambda: provider)

    def invalid(frame):
        raise DNSParseError("bad DNS header")

    monkeypatch.setattr(
        dns_events, "DNSEventPipeline",
        lambda: SimpleNamespace(process=invalid),
    )
    monkeypatch.setattr(sys, "argv", ["novxis-dns-events", "en0"])
    assert dns_events.main() == 1
    result = capsys.readouterr()
    assert "decode failed: bad DNS header" in result.err
    assert "DNS observations: 0; decode errors: 1" in result.out


def test_live_handles_manual_cancellation(monkeypatch, capsys):
    provider = DummyProvider(interrupt=True)
    monkeypatch.setattr(dns_events, "ScapyCaptureProvider", lambda: provider)
    monkeypatch.setattr(sys, "argv", ["novxis-dns-events", "en0"])
    assert dns_events.main() == 130
    assert provider.was_stopped
    assert "Capture stopped" in capsys.readouterr().out


@pytest.mark.parametrize("args", [
    ["en0", "--count", "-2"],
    ["en0", "--timeout", "0"],
    ["en0", "--timeout", "-5"],
])
def test_live_rejects_invalid_limits(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["novxis-dns-events", *args])
    with pytest.raises(SystemExit) as error:
        dns_events.main()
    assert error.value.code == 2
