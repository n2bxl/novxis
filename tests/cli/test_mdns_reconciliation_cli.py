"""Opt-in reconciliation CLI behavior without private capture files."""

from decimal import Decimal
import sys
from types import SimpleNamespace

import pytest

from novxis.cli import mdns_state_replay
from novxis.protocols.dnssd import DNSSDParseError


class ReplayProvider:
    def replay(self, path, handler, *, count, interface_label):
        handler(SimpleNamespace(timestamp=Decimal("100"), interface="test0"))
        return 1


class MockReconciler:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.seen = []
        self.unassociated_count = 2

    def observe_message(self, observed, advertisements):
        self.seen.append((observed, advertisements))
        return len(advertisements)

    def snapshots(self, as_of):
        assert as_of == Decimal("300")
        return (
            SimpleNamespace(
                snapshot=SimpleNamespace(has_fresh_ptr=True),
                cross_message_records=(object(),),
            ),
        )


def test_opt_in_reconciliation_shows_joined_records(monkeypatch, capsys):
    captured = {}
    def construct(**kw):
        state = MockReconciler(**kw)
        captured["state"] = state
        return state
    monkeypatch.setattr(mdns_state_replay, "PcapReplayProvider", ReplayProvider)
    monkeypatch.setattr(mdns_state_replay, "MDNSServiceReconciliation", construct)
    monkeypatch.setattr(
        mdns_state_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: SimpleNamespace(ip_version=4)),
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
        "novxis-mdns-state-replay", "mock.pcapng",
        "--reconcile", "--after", "200", "--max-unassociated", "4",
    ])
    assert mdns_state_replay.main() == 0
    assert len(captured["state"].seen) == 1
    assert captured["state"].kwargs["max_unassociated"] == 4
    output = capsys.readouterr().out
    assert "DNS-SD PTR observations: 1" in output
    assert "instances retained: 1" in output
    assert "unassociated RRs retained: 2" in output
    assert "separately-observed-RRs-linked=1" in output


def test_invalid_unassociated_limit_rejected(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "novxis-mdns-state-replay", "mock.pcapng",
        "--reconcile", "--max-unassociated", "0",
    ])
    with pytest.raises(SystemExit) as result:
        mdns_state_replay.main()
    assert result.value.code == 2


def test_malformed_orphan_is_reported_as_error_instead_of_crashing(
    monkeypatch, capsys
):
    class BrokenReconciler(MockReconciler):
        def observe_message(self, *args):
            raise DNSSDParseError("bad standalone SRV")

        def snapshots(self, as_of):
            return ()

    monkeypatch.setattr(mdns_state_replay, "PcapReplayProvider", ReplayProvider)
    monkeypatch.setattr(
        mdns_state_replay, "MDNSServiceReconciliation",
        lambda **kw: BrokenReconciler(**kw)
    )
    monkeypatch.setattr(
        mdns_state_replay, "MDNSEventPipeline",
        lambda: SimpleNamespace(process=lambda _: SimpleNamespace(ip_version=4)),
    )
    monkeypatch.setattr(
        mdns_state_replay, "project_dnssd_advertisements",
        lambda _: (),
    )
    monkeypatch.setattr(sys, "argv", [
        "novxis-mdns-state-replay", "mock.pcapng", "--reconcile",
    ])
    assert mdns_state_replay.main() == 1
    output = capsys.readouterr()
    assert "mDNS state decode failed: bad standalone SRV" in output.err
    assert "decode errors: 1" in output.out
