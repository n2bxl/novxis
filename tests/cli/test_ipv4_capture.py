from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.cli.ipv4_capture import _build_handler
from novxis.pipeline import IPv4EvidencePipeline


IPV4_RAW = bytes.fromhex(
    "001122334455"
    "66778899aabb"
    "0800"
    "4500001c123440004001abcdc000020ac6336414"
    "08000000deadbeef"
)


def _frame(data: bytes) -> CapturedFrame:
    return CapturedFrame(
        timestamp=Decimal("100.125"),
        interface="fixture",
        data=data,
        captured_length=len(data),
        original_length=len(data),
        link_type=1,
    )


def test_live_handler_prints_layered_ipv4_evidence(capsys):
    handle = _build_handler(IPv4EvidencePipeline())

    handle(_frame(IPV4_RAW))

    output = capsys.readouterr().out

    assert "Ethernet" in output
    assert "IPv4" in output
    assert "src=192.0.2.10" in output
    assert "dst=198.51.100.20" in output
    assert "protocol=1 (ICMP)" in output
    assert "payload=8 bytes" in output


def test_live_handler_reports_decode_failure_to_stderr(capsys):
    handle = _build_handler(IPv4EvidencePipeline())

    handle(_frame(bytes.fromhex("00112233445566778899aabb08004500")))

    captured = capsys.readouterr()

    assert captured.out == ""
    assert "decode failed" in captured.err
