from pathlib import Path

from novxis.capture.pcap_replay import PcapReplayProvider
from novxis.pipeline import ARPStatePipeline
from novxis.state import ARPBindingLearned, ARPBindingRefreshed


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "arp_phase0_sanitized.pcap"
)


def test_sanitized_fixture_builds_deterministic_arp_network_state():
    pipeline = ARPStatePipeline()
    changes = []

    def handle(frame):
        result = pipeline.process(frame)
        if result is not None and result.state_change is not None:
            changes.append(result.state_change)

    emitted = PcapReplayProvider().replay(
        FIXTURE,
        handle,
        interface_label="fixture",
    )

    assert emitted == 8
    assert len(pipeline.state.arp_bindings) == 6
    assert sum(isinstance(change, ARPBindingLearned) for change in changes) == 6
    assert sum(isinstance(change, ARPBindingRefreshed) for change in changes) == 1
    assert len(changes) == 7

    addresses = {
        binding.protocol_address
        for binding in pipeline.state.arp_bindings
    }
    assert bytes([0, 0, 0, 0]) not in addresses
    assert addresses == {
        bytes([192, 0, 2, 10]),
        bytes([192, 0, 2, 20]),
        bytes([192, 0, 2, 30]),
        bytes([192, 0, 2, 60]),
        bytes([192, 0, 2, 70]),
        bytes([192, 0, 2, 80]),
    }
