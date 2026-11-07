"""Finite offline replay CLI tests with synthetic, documentation-only PCAP."""

from ipaddress import IPv6Address
from pathlib import Path
import struct
import sys

import pytest

from novxis.cli.ndp_replay import main


def _frame(kind=135, *, hop_limit=255, flags=0):
    source = IPv6Address("fe80::10").packed
    destination = IPv6Address("fe80::20").packed
    target = IPv6Address("2001:db8::20").packed
    option = (b"\x01\x01" if kind == 135 else b"\x02\x01")
    option += bytes.fromhex("020000000010")
    icmp = (
        bytes((kind, 0)) + bytes(2)
        + flags.to_bytes(4, "big") + target + option
    )
    pseudo = source + destination + len(icmp).to_bytes(4, "big")
    pseudo += b"\x00\x00\x00\x3a"
    words = pseudo + icmp
    if len(words) % 2:
        words += b"\x00"
    total = sum(int.from_bytes(words[i:i + 2], "big")
                for i in range(0, len(words), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    icmp = icmp[:2] + ((~total) & 65535).to_bytes(2, "big") + icmp[4:]
    ipv6 = (
        b"\x60\x00\x00\x00" + len(icmp).to_bytes(2, "big")
        + bytes((58, hop_limit)) + source + destination + icmp
    )
    return bytes.fromhex("3333000000010266778899aa86dd") + ipv6


def _pcap(path: Path, *frames: bytes):
    # PCAP little-endian magic, Ethernet linktype, synthetic timestamps.
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        data += struct.pack(
            "<IIII", 100 + index, 0, len(frame), len(frame)
        ) + frame
    path.write_bytes(data)


def _run(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["novxis-ndp-replay", *map(str, args)])
    return main()


def test_offline_replay_counts_valid_ns_na_without_host_state(tmp_path, monkeypatch, capsys):
    path = tmp_path / "synthetic-ndp.pcap"
    _pcap(path, _frame(135), _frame(136, flags=0x60000000))
    assert _run(monkeypatch, path, "--summary-only") == 0
    stdout = capsys.readouterr().out
    assert "frames=2" in stdout
    assert "NS=1" in stdout and "NA=1" in stdout
    assert "DAD probes=0" in stdout and "decode errors=0" in stdout
    assert "fe80::" not in stdout
    assert "2001:db8::" not in stdout
    assert "02:00:00:00" not in stdout


def test_offline_replay_prints_protocol_evidence_when_explicitly_requested(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "synthetic-ndp.pcap"
    _pcap(path, _frame(136, flags=0x60000000))
    assert _run(monkeypatch, path) == 0
    output = capsys.readouterr().out
    assert "NA" in output and "target=2001:db8::20" in output
    assert "advertised target LLA=" in output
    assert "Replay complete" in output


def test_offline_replay_count_limit_is_finite(tmp_path, monkeypatch, capsys):
    path = tmp_path / "synthetic-ndp.pcap"
    _pcap(path, _frame(), _frame(136))
    assert _run(monkeypatch, path, "--count", "1", "--summary-only") == 0
    assert "frames=1" in capsys.readouterr().out


def test_invalid_nd_frame_is_counted_as_decode_error_not_an_address_binding(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "invalid-ndp.pcap"
    _pcap(path, _frame(hop_limit=64), _frame())
    assert _run(monkeypatch, path, "--summary-only") == 1
    out = capsys.readouterr().out
    assert "NS=1" in out and "decode errors=1" in out


@pytest.mark.parametrize("args", [
    ("--count", "-1"),
    ("--interface-label", ""),
])
def test_invalid_replay_parameters_raise_parser_error(monkeypatch, args):
    with pytest.raises(SystemExit, match="2"):
        _run(monkeypatch, "unused.pcap", *args)


def test_missing_pcap_fails_gracefully(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "does-not-exist.pcap"
    assert _run(monkeypatch, missing, "--summary-only") == 1
    assert "Replay failed" in capsys.readouterr().err


# Phase 1N-K Stage 2: retain distinct interface-scoped packet assertions.

def _state_run(monkeypatch, *args):
    from novxis.cli.ndp_state_replay import main as state_main
    monkeypatch.setattr(
        sys, "argv", ["novxis-ndp-state-replay", *map(str, args)],
    )
    return state_main()


def _frame_without_lla(kind=136):
    """Drop the 8-byte link-layer option and recompute IPv6/ICMPv6 checksums."""
    raw = bytearray(_frame(kind))
    ipv6_start = 14
    icmp_start = ipv6_start + 40
    del raw[-8:]
    payload_len = len(raw) - icmp_start
    raw[ipv6_start + 4:ipv6_start + 6] = payload_len.to_bytes(2, "big")
    src = bytes(raw[ipv6_start + 8:ipv6_start + 24])
    dst = bytes(raw[ipv6_start + 24:ipv6_start + 40])
    raw[icmp_start + 2:icmp_start + 4] = bytes(2)
    pseudo = src + dst + payload_len.to_bytes(4, "big") + b"\x00\x00\x00\x3a"
    data = pseudo + bytes(raw[icmp_start:])
    total = sum(
        int.from_bytes(data[i:i + 2], "big")
        for i in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    raw[icmp_start + 2:icmp_start + 4] = ((~total) & 65535).to_bytes(2, "big")
    return bytes(raw)


def test_stage2_summary_reports_source_and_target_claims_separately(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "synthetic-ndp-state.pcap"
    _pcap(path, _frame(135), _frame(136))
    assert _state_run(monkeypatch, path, "--interface-label", "en0",
                      "--summary-only") == 0
    out = capsys.readouterr().out
    assert "frames=2; messages=2; NS=1; NA=1; DAD=0" in out
    assert "NS source SLLA=1" in out
    assert "NA target TLLA=1" in out
    assert "unlinked evidence=0" in out
    assert "fe80::" not in out and "2001:db8::" not in out
    assert "02:00:00:00" not in out


def test_stage2_na_missing_tlla_is_unlinked_not_a_mac_claim(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "synthetic-no-tlla.pcap"
    _pcap(path, _frame_without_lla(136))
    assert _state_run(monkeypatch, path, "--summary-only") == 0
    out = capsys.readouterr().out
    assert "NA target TLLA=0" in out
    assert "unlinked evidence=1" in out
    assert "unlinked na_missing_tlla: 1" in out


def test_stage2_detailed_replay_names_evidence_kind_without_claiming_host(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "synthetic-ndp-state.pcap"
    _pcap(path, _frame(135), _frame_without_lla(136))
    assert _state_run(monkeypatch, path) == 0
    out = capsys.readouterr().out
    assert "ns_source_slla" in out
    assert "na_missing_tlla" in out
    assert "unverified packet assertions" in out
    assert "fe80::10" in out
    assert "target=2001:db8::20" in out


def test_stage2_replay_respects_count_limit_and_summary_mode(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "synthetic-ndp-state.pcap"
    _pcap(path, _frame(135), _frame(136))
    assert _state_run(monkeypatch, path, "--count", "1", "--summary-only") == 0
    assert "frames=1; messages=1; NS=1; NA=0" in capsys.readouterr().out


@pytest.mark.parametrize("args", [
    ("--count", "-1"),
    ("--limit", "-1"),
    ("--interface-label", ""),
    ("--max-history", "0"),
    ("--max-claims", "99999"),
    ("--max-unlinked", "0"),
])
def test_stage2_invalid_limits_rejected_without_replaying(monkeypatch, args):
    with pytest.raises(SystemExit, match="2"):
        _state_run(monkeypatch, "missing.pcap", *args)


def test_stage2_replay_missing_file_fails_gracefully(
    tmp_path, monkeypatch, capsys
):
    assert _state_run(
        monkeypatch, tmp_path / "missing.pcap", "--summary-only",
    ) == 1
    assert "Replay failed" in capsys.readouterr().err
