from decimal import Decimal
from pathlib import Path

from novxis.capture.pcap_replay import PcapReplayProvider
from novxis.events import ARPReplyObserved, ARPRequestObserved
from novxis.pipeline import ARPEventPipeline


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "arp_phase0_sanitized.pcap"
)


def test_sanitized_replay_corpus_exercises_phase0_arp_pipeline():
    pipeline = ARPEventPipeline()
    results = []

    def handle(frame):
        result = pipeline.process(frame)
        if result is not None:
            results.append(result)

    emitted = PcapReplayProvider().replay(
        FIXTURE,
        handle,
        interface_label="fixture",
    )

    assert emitted == 8
    assert len(results) == 8

    requests = [
        result
        for result in results
        if isinstance(result.observation, ARPRequestObserved)
    ]
    replies = [
        result
        for result in results
        if isinstance(result.observation, ARPReplyObserved)
    ]
    exchanges = [
        result.exchange
        for result in results
        if result.exchange is not None
    ]

    assert len(requests) == 5
    assert len(replies) == 3
    assert len(exchanges) == 2

    assert [
        len(result.observation.message.trailing_bytes)
        for result in results
    ] == [18, 0, 0, 32, 32, 18, 18, 0]

    assert exchanges[0].duration == Decimal("0.0005")
    assert exchanges[1].duration == Decimal("0.2")

    # The final reply must correlate with the newest retransmission at t=105,
    # leaving the older request plus the two intentionally unmatched requests.
    assert exchanges[1].request.timestamp == Decimal("105")
    assert len(pipeline.pending_requests) == 3

    pending_sender_protocols = {
        request.message.sender_protocol
        for request in pipeline.pending_requests
    }
    assert bytes([0, 0, 0, 0]) in pending_sender_protocols
    assert bytes([192, 0, 2, 60]) in pending_sender_protocols
    assert bytes([192, 0, 2, 70]) in pending_sender_protocols
