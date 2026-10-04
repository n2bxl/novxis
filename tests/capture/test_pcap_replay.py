from collections import namedtuple
from decimal import Decimal
import struct

import pytest

from novxis.capture.pcap_replay import PcapReplayError, PcapReplayProvider


ClassicMetadata = namedtuple(
    "ClassicMetadata",
    ["sec", "usec", "wirelen", "caplen"],
)
NgMetadata = namedtuple(
    "NgMetadata",
    [
        "linktype",
        "tsresol",
        "tshigh",
        "tslow",
        "wirelen",
        "comments",
        "ifname",
        "direction",
        "process_information",
    ],
)


class FakeReader:
    def __init__(self, records, *, linktype=None, nano=False):
        self.records = records
        self.linktype = linktype
        self.nano = nano
        self.closed = False

    def __iter__(self):
        return iter(self.records)

    def close(self):
        self.closed = True


def test_replay_converts_classic_pcap_metadata_to_captured_frame():
    reader = FakeReader(
        [
            (
                b"\x01\x02\x03",
                ClassicMetadata(
                    sec=100,
                    usec=250_000,
                    wirelen=60,
                    caplen=3,
                ),
            )
        ],
        linktype=1,
    )
    provider = PcapReplayProvider(reader_factory=lambda path: reader)
    frames = []

    emitted = provider.replay("capture.pcap", frames.append)

    assert emitted == 1
    assert frames[0].timestamp == Decimal("100.25")
    assert frames[0].interface == "replay"
    assert frames[0].data == b"\x01\x02\x03"
    assert frames[0].captured_length == 3
    assert frames[0].original_length == 60
    assert frames[0].link_type == 1
    assert reader.closed is True


def test_replay_uses_pcapng_timestamp_and_interface_name():
    ticks = 12_345_678
    reader = FakeReader(
        [
            (
                b"frame",
                NgMetadata(
                    linktype=1,
                    tsresol=1_000_000,
                    tshigh=ticks >> 32,
                    tslow=ticks & 0xFFFFFFFF,
                    wirelen=74,
                    comments=None,
                    ifname=b"en5",
                    direction=None,
                    process_information={},
                ),
            )
        ]
    )
    provider = PcapReplayProvider(reader_factory=lambda path: reader)
    frames = []

    provider.replay(
        "capture.pcapng",
        frames.append,
        interface_label="fallback",
    )

    assert frames[0].timestamp == Decimal("12.345678")
    assert frames[0].interface == "en5"
    assert frames[0].captured_length == len(b"frame")
    assert frames[0].original_length == 74
    assert frames[0].link_type == 1


def test_replay_honors_frame_count_and_closes_reader():
    metadata = ClassicMetadata(sec=1, usec=0, wirelen=1, caplen=1)
    reader = FakeReader(
        [(b"a", metadata), (b"b", metadata), (b"c", metadata)],
        linktype=1,
    )
    provider = PcapReplayProvider(reader_factory=lambda path: reader)
    frames = []

    emitted = provider.replay(
        "capture.pcap",
        frames.append,
        count=2,
    )

    assert emitted == 2
    assert [frame.data for frame in frames] == [b"a", b"b"]
    assert reader.closed is True


def test_replay_rejects_timestamp_less_pcapng_frame_and_closes_reader():
    reader = FakeReader(
        [
            (
                b"frame",
                NgMetadata(
                    linktype=1,
                    tsresol=1_000_000,
                    tshigh=None,
                    tslow=None,
                    wirelen=60,
                    comments=None,
                    ifname=None,
                    direction=None,
                    process_information={},
                ),
            )
        ]
    )
    provider = PcapReplayProvider(reader_factory=lambda path: reader)

    with pytest.raises(PcapReplayError, match="timestamp"):
        provider.replay("capture.pcapng", lambda frame: None)

    assert reader.closed is True


@pytest.mark.parametrize(
    ("interface_label", "count", "message"),
    [
        ("", 0, "interface_label"),
        ("replay", -1, "count"),
    ],
)
def test_replay_validates_arguments(interface_label, count, message):
    provider = PcapReplayProvider(
        reader_factory=lambda path: FakeReader([])
    )

    with pytest.raises(ValueError, match=message):
        provider.replay(
            "capture.pcap",
            lambda frame: None,
            interface_label=interface_label,
            count=count,
        )


def test_replay_reads_real_classic_pcap_through_scapy(tmp_path):
    raw_frame = bytes.fromhex(
        "ffffffffffff"
        "5c475e67b325"
        "0806"
        "0001"
        "0800"
        "06"
        "04"
        "0001"
        "5c475e67b325"
        "c0a8041e"
        "000000000000"
        "c0a8041e"
    ) + (b"\x00" * 18)

    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )
    packet_header = struct.pack(
        "<IIII",
        100,
        250_000,
        len(raw_frame),
        len(raw_frame),
    )

    path = tmp_path / "fixture.pcap"
    path.write_bytes(global_header + packet_header + raw_frame)

    frames = []
    emitted = PcapReplayProvider().replay(path, frames.append)

    assert emitted == 1
    assert frames[0].timestamp == Decimal("100.25")
    assert frames[0].data == raw_frame
    assert frames[0].captured_length == len(raw_frame)
    assert frames[0].original_length == len(raw_frame)
    assert frames[0].link_type == 1
