from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.cli.icmp_events import _build_handler
from novxis.pipeline import ICMPEventPipeline


def _frame(icmp_type: int, timestamp: str, source: bytes, destination: bytes):
    payload = b"novxis"
    icmp = (
        bytes([icmp_type, 0])
        + bytes.fromhex("1111")
        + bytes.fromhex("12340001")
        + payload
    )
    total_length = 20 + len(icmp)
    ipv4 = (
        bytes.fromhex("4500")
        + total_length.to_bytes(2, "big")
        + bytes.fromhex("123440004001abcd")
        + source
        + destination
        + icmp
    )
    ethernet = (
        bytes.fromhex("00112233445566778899aabb0800")
        + ipv4
    )
    return CapturedFrame(
        timestamp=Decimal(timestamp),
        interface="en0",
        data=ethernet,
        captured_length=len(ethernet),
        original_length=len(ethernet),
        link_type=1,
    )


def test_live_handler_prints_echo_events_and_completed_exchange(capsys):
    pipeline = ICMPEventPipeline()
    handle = _build_handler(pipeline)
    local = bytes([192, 0, 2, 10])
    remote = bytes([198, 51, 100, 20])

    handle(_frame(8, "100.000", local, remote))
    handle(_frame(0, "100.018", remote, local))

    output = capsys.readouterr().out

    assert "ICMPEchoRequestObserved" in output
    assert "ICMPEchoReplyObserved" in output
    assert "ICMPEchoExchangeCompleted" in output
    assert "id=0x1234" in output
    assert "seq=1" in output
    assert "duration=18.000ms" in output
