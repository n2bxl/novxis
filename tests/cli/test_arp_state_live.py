from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.cli.arp_state_live import _build_handler
from novxis.pipeline import ARPStatePipeline


REQUEST_RAW = bytes.fromhex(
    "ffffffffffff"
    "020000000010"
    "0806"
    "0001"
    "0800"
    "06"
    "04"
    "0001"
    "020000000010"
    "c000020a"
    "000000000000"
    "c0000214"
) + (b"\x00" * 18)

REPLY_RAW = bytes.fromhex(
    "020000000010"
    "020000000020"
    "0806"
    "0001"
    "0800"
    "06"
    "04"
    "0002"
    "020000000020"
    "c0000214"
    "020000000010"
    "c000020a"
)


def _frame(data: bytes, timestamp: str) -> CapturedFrame:
    return CapturedFrame(
        timestamp=Decimal(timestamp),
        interface="fixture",
        data=data,
        captured_length=len(data),
        original_length=len(data),
        link_type=1,
    )


def test_live_handler_builds_state_and_preserves_event_output(capsys):
    pipeline = ARPStatePipeline()
    handle = _build_handler(pipeline)

    handle(_frame(REQUEST_RAW, "100"))
    handle(_frame(REPLY_RAW, "100.0005"))

    output = capsys.readouterr().out

    assert "ARPRequestObserved" in output
    assert "ARPReplyObserved" in output
    assert "ARPExchangeCompleted" in output
    assert "ARPBindingLearned" in output
    assert len(pipeline.state.arp_bindings) == 2


def test_live_handler_refreshes_existing_binding(capsys):
    pipeline = ARPStatePipeline()
    handle = _build_handler(pipeline)

    handle(_frame(REQUEST_RAW, "100"))
    handle(_frame(REQUEST_RAW, "101"))

    output = capsys.readouterr().out

    assert "ARPBindingRefreshed" in output
    binding = pipeline.state.arp_bindings[0]
    assert binding.observation_count == 2
