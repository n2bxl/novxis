"""Port-filter CLI argument and capture-provider wiring."""

import sys

import pytest

from novxis.cli import udp_events


class DummyProvider:
    def __init__(self):
        self.capture_filter = None

    def start(self, interface, callback, *, bpf_filter, count, timeout):
        assert interface == "en0"
        self.capture_filter = bpf_filter

    def wait(self):
        pass

    def stop(self):
        pass


@pytest.mark.parametrize(
    "arguments, expected_filter",
    [
        (["en0"], "udp"),
        (["en0", "--port", "49000"], "udp port 49000"),
    ],
)
def test_cli_passes_valid_filter_to_capture_provider(
    monkeypatch, arguments, expected_filter
):
    provider = DummyProvider()
    monkeypatch.setattr(udp_events, "ScapyCaptureProvider", lambda: provider)
    monkeypatch.setattr(sys, "argv", ["novxis-udp-events", *arguments])
    assert udp_events.main() == 0
    assert provider.capture_filter == expected_filter


@pytest.mark.parametrize("invalid_port", ["0", "65536", "-1"])
def test_cli_rejects_invalid_port(monkeypatch, invalid_port):
    monkeypatch.setattr(
        sys, "argv", ["novxis-udp-events", "en0", "--port", invalid_port]
    )
    with pytest.raises(SystemExit) as exc:
        udp_events.main()
    assert exc.value.code == 2
