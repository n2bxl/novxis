from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.cli.icmp_events import _build_handler
from novxis.pipeline import ICMPEventPipeline


def _outer_frame(icmp: bytes, timestamp: str, source: bytes, destination: bytes):
    total_length = 20 + len(icmp)
    ipv4 = (
        bytes.fromhex("4500")
        + total_length.to_bytes(2, "big")
        + bytes.fromhex("123440004001abcd")
        + source
        + destination
        + icmp
    )
    ethernet = bytes.fromhex("00112233445566778899aabb0800") + ipv4
    return CapturedFrame(
        timestamp=Decimal(timestamp),
        interface="en0",
        data=ethernet,
        captured_length=len(ethernet),
        original_length=len(ethernet),
        link_type=1,
    )


def _echo_frame(icmp_type: int, timestamp: str, source: bytes, destination: bytes):
    payload = b"novxis"
    icmp = (
        bytes([icmp_type, 0])
        + bytes.fromhex("1111")
        + bytes.fromhex("12340001")
        + payload
    )
    return _outer_frame(icmp, timestamp, source, destination)


def _time_exceeded_frame():
    quoted = bytes.fromhex(
        "4500003cbeef40000111abcd"
        "c000020ac6336414"
        "c000829a00281234"
    )
    icmp = bytes.fromhex("0b00222200000000") + quoted
    return _outer_frame(
        icmp,
        "101.000",
        bytes([203, 0, 113, 1]),
        bytes([192, 0, 2, 10]),
    )


def _time_exceeded_frame_with_trailing_quote_bytes():
    quoted = (
        bytes.fromhex(
            "45000028beef40000111abcd"
            "c000020ac6336414"
            "c000829a00281234"
        )
        + (b"\x00" * 12)
        + (b"\xaa" * 28)
    )
    icmp = bytes.fromhex("0b00222200000000") + quoted
    return _outer_frame(
        icmp,
        "102.000",
        bytes([198, 51, 100, 1]),
        bytes([192, 0, 2, 10]),
    )


def test_live_handler_prints_echo_events_and_completed_exchange(capsys):
    pipeline = ICMPEventPipeline()
    handle = _build_handler(pipeline)
    local = bytes([192, 0, 2, 10])
    remote = bytes([198, 51, 100, 20])

    handle(_echo_frame(8, "100.000", local, remote))
    handle(_echo_frame(0, "100.018", remote, local))

    output = capsys.readouterr().out

    assert "ICMPEchoRequestObserved" in output
    assert "ICMPEchoReplyObserved" in output
    assert "ICMPEchoExchangeCompleted" in output
    assert "id=0x1234" in output
    assert "seq=1" in output
    assert "duration=18.000ms" in output


def test_live_handler_prints_time_exceeded_with_quoted_ipv4(capsys):
    handle = _build_handler(ICMPEventPipeline())

    handle(_time_exceeded_frame())

    output = capsys.readouterr().out

    assert "ICMPTimeExceededObserved" in output
    assert "TTL Exceeded in Transit" in output
    assert "QuotedIPv4 192.0.2.10" in output
    assert "198.51.100.20" in output
    assert "protocol=17" in output
    assert "payload_prefix=8 bytes" in output
    assert "truncated=true" in output


def test_live_handler_prints_trailing_quoted_ipv4_evidence(capsys):
    handle = _build_handler(ICMPEventPipeline())

    handle(_time_exceeded_frame_with_trailing_quote_bytes())

    output = capsys.readouterr().out

    assert "ICMPTimeExceededObserved" in output
    assert "declared_total=40" in output
    assert "available=68" in output
    assert "payload_prefix=20 bytes" in output
    assert "trailing=28 bytes" in output
    assert "truncated=false" in output
