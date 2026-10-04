from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.capture.scapy_provider import ScapyCaptureProvider


class FakePacket:
    time = Decimal("1234.567890")
    wirelen = 74

    def __bytes__(self) -> bytes:
        return b"\x01\x02\x03\x04"


class FakeSniffer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.stop_calls = 0
        self.join_calls = 0

    def start(self):
        self.running = True

    def stop(self):
        self.stop_calls += 1
        self.running = False

    def join(self):
        self.join_calls += 1
        self.running = False


class FakeSnifferFactory:
    def __init__(self):
        self.instances = []

    def __call__(self, **kwargs):
        sniffer = FakeSniffer(**kwargs)
        self.instances.append(sniffer)
        return sniffer


def test_start_configures_async_sniffer_and_emits_captured_frame():
    factory = FakeSnifferFactory()
    provider = ScapyCaptureProvider(sniffer_factory=factory)
    frames: list[CapturedFrame] = []

    provider.start(
        "en5",
        frames.append,
        bpf_filter="arp",
        count=5,
        timeout=30,
    )

    sniffer = factory.instances[0]
    assert sniffer.kwargs["iface"] == "en5"
    assert sniffer.kwargs["filter"] == "arp"
    assert sniffer.kwargs["store"] is False
    assert sniffer.kwargs["count"] == 5
    assert sniffer.kwargs["timeout"] == 30
    assert provider.is_running is True

    sniffer.kwargs["prn"](FakePacket())

    assert frames == [
        CapturedFrame(
            timestamp=Decimal("1234.567890"),
            interface="en5",
            data=b"\x01\x02\x03\x04",
            captured_length=4,
            original_length=74,
        )
    ]


def test_start_omits_optional_filter_and_timeout_when_not_provided():
    factory = FakeSnifferFactory()
    provider = ScapyCaptureProvider(sniffer_factory=factory)

    provider.start("en5", lambda frame: None)

    kwargs = factory.instances[0].kwargs
    assert "filter" not in kwargs
    assert "timeout" not in kwargs
    assert kwargs["count"] == 0


def test_start_rejects_second_capture_while_running():
    factory = FakeSnifferFactory()
    provider = ScapyCaptureProvider(sniffer_factory=factory)
    provider.start("en5", lambda frame: None)

    with pytest.raises(RuntimeError, match="already running"):
        provider.start("en0", lambda frame: None)


@pytest.mark.parametrize(
    ("interface", "count", "timeout", "message"),
    [
        ("", 0, None, "interface"),
        ("en5", -1, None, "count"),
        ("en5", 0, 0, "timeout"),
    ],
)
def test_start_validates_capture_arguments(interface, count, timeout, message):
    provider = ScapyCaptureProvider(sniffer_factory=FakeSnifferFactory())

    with pytest.raises(ValueError, match=message):
        provider.start(
            interface,
            lambda frame: None,
            count=count,
            timeout=timeout,
        )


def test_stop_and_wait_delegate_to_active_sniffer():
    factory = FakeSnifferFactory()
    provider = ScapyCaptureProvider(sniffer_factory=factory)
    provider.start("en5", lambda frame: None)

    sniffer = factory.instances[0]

    provider.wait()
    assert sniffer.join_calls == 1
    assert provider.is_running is False

    sniffer.running = True
    provider.stop()
    assert sniffer.stop_calls == 1
    assert provider.is_running is False


def test_captured_frame_preserves_trailing_bytes_exactly():
    factory = FakeSnifferFactory()
    provider = ScapyCaptureProvider(sniffer_factory=factory)
    frames: list[CapturedFrame] = []

    class PaddedPacket:
        time = Decimal("2000.25")
        wirelen = None

        def __bytes__(self) -> bytes:
            return (b"\xaa" * 42) + (b"\x00" * 32)

    provider.start("en5", frames.append, bpf_filter="arp")
    factory.instances[0].kwargs["prn"](PaddedPacket())

    assert frames[0].data == (b"\xaa" * 42) + (b"\x00" * 32)
    assert frames[0].captured_length == 74
    assert frames[0].original_length is None
