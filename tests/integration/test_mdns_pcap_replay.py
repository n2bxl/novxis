"""True byte-level PCAP replay through the dual-stack mDNS pipeline.

The test fixture is generated locally from synthetic RFC 5737 / RFC 3849
addresses; no private Wireshark captures or identifiable hostnames.
"""

from ipaddress import IPv6Address
import struct

from novxis.capture.pcap_replay import PcapReplayProvider
from novxis.pipeline.mdns import MDNSEventPipeline


def _name(*labels):
    return b"".join(bytes((len(v),)) + v.encode("ascii") for v in labels) + b"\x00"


def _dns_query():
    name = _name("_demo", "_tcp", "local")
    return (
        b"\x00\x00\x00\x00\x00\x01" + bytes(6)
        + name + b"\x00\x0c\x80\x01"
    )


def _udp(payload):
    return (
        b"\x14\xe9\x14\xe9"  # 5353 / 5353
        + (len(payload) + 8).to_bytes(2, "big")
        + b"\x00\x01" + payload
    )


def _ethernet(etype, payload):
    return (
        bytes.fromhex("01005e0000fb0266778899aa")
        + etype.to_bytes(2, "big") + payload
    )


def _ipv4_mdns():
    udp = _udp(_dns_query())
    ip = (
        b"\x45\x00" + (len(udp) + 20).to_bytes(2, "big")
        + b"\x00\x00\x00\x00\xff\x11\x00\x00"
        + bytes((192, 0, 2, 14))
        + bytes((224, 0, 0, 251))
        + udp
    )
    return _ethernet(0x0800, ip)


def _ipv6_mdns():
    udp = _udp(_dns_query())
    ip = (
        b"\x60\x00\x00\x00" + len(udp).to_bytes(2, "big")
        + b"\x11\xff"
        + IPv6Address("fe80::14").packed
        + IPv6Address("ff02::fb").packed
        + udp
    )
    return _ethernet(0x86DD, ip)


def test_real_pcap_reader_replays_ipv4_ipv6_mdns_without_active_network(tmp_path):
    frames = [
        _ipv4_mdns(),
        _ethernet(0x0806, bytes(28)),  # unrelated ARP
        _ipv6_mdns(),
    ]
    raw_pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        raw_pcap += struct.pack(
            "<IIII", 100 + index, 250_000,
            len(frame), len(frame),
        ) + frame

    capture_file = tmp_path / "synthetic-dual-stack-mdns.pcap"
    capture_file.write_bytes(raw_pcap)

    pipeline = MDNSEventPipeline()
    observed = []

    def handle(frame):
        result = pipeline.process(frame)
        if result is not None:
            observed.append(result)

    processed = PcapReplayProvider().replay(
        capture_file, handle, interface_label="test-replay"
    )
    assert processed == 3
    assert len(observed) == 2
    assert [o.ip_version for o in observed] == [4, 6]
    assert [o.message.questions[0].response_mode for o in observed] == ["QU", "QU"]
    assert [o.interface for o in observed] == ["test-replay", "test-replay"]
    assert all(o.captured.link_type == 1 for o in observed)
    assert all(o.message.dns.trailing_bytes == b"" for o in observed)
