"""Per-response DNS-SD service claims with source and record provenance."""

from dataclasses import FrozenInstanceError
from decimal import Decimal
from ipaddress import IPv6Address

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.pipeline.mdns import MDNSEventPipeline
from novxis.presentation.mdns_service_console import format_dnssd_advertisement
from novxis.protocols.dns import DNSParseError
from novxis.protocols.dnssd import DNSSDParseError
from novxis.views.mdns_services import project_dnssd_advertisements


def _name(*labels: str) -> bytes:
    return b"".join(bytes((len(l),)) + l.encode("ascii") for l in labels) + b"\x00"


SERVICE = _name("_demo", "_tcp", "local")
INSTANCE = _name("Living.Room", "_demo", "_tcp", "local")
HOST = _name("host", "local")
DIFFERENT = _name("other", "local")


def _rr(name: bytes, kind: int, value: bytes, *, ttl=120, cls=1):
    return (
        name + kind.to_bytes(2, "big") + cls.to_bytes(2, "big")
        + ttl.to_bytes(4, "big") + len(value).to_bytes(2, "big") + value
    )


def _packet(
    *, response=True, with_srv=True, with_txt=True, with_addr=True,
    ptr_owner=SERVICE, ptr_target=INSTANCE, srv_target=b"\xc0\x0c",
    srv_port=4070, ptr_ttl=4500, txt_data=b"\x09CPath=/zc",
    extra_address=False, broken_srv=False,
):
    # Question starts at offset 12, allowing SRV target to use compression.
    question = HOST + b"\x00\x01\x00\x01"
    answers = [_rr(ptr_owner, 12, ptr_target, ttl=ptr_ttl)]
    extras = []
    if with_srv:
        value = (
            b"\x00\x00\x00\x00" + srv_port.to_bytes(2, "big")
            + (b"\xc0" if broken_srv else srv_target)
        )
        extras.append(_rr(INSTANCE, 33, value, cls=0x8001))
    if with_txt:
        extras.append(_rr(INSTANCE, 16, txt_data, ttl=600, cls=0x8001))
    if with_addr:
        extras.append(_rr(HOST, 1, b"\xc0\x00\x02\x19", cls=0x8001))
    if extra_address:
        extras.append(_rr(HOST, 28, IPv6Address("2001:db8::25").packed,
                          cls=0x8001))
    flags = 0x8400 if response else 0
    header = (
        b"\x00\x00" + flags.to_bytes(2, "big")
        + b"\x00\x01" + len(answers).to_bytes(2, "big")
        + b"\x00\x00" + len(extras).to_bytes(2, "big")
    )
    dns = header + question + b"".join(answers + extras)
    udp = (
        b"\x14\xe9\x14\xe9" + (8 + len(dns)).to_bytes(2, "big")
        + b"\x00\x00" + dns
    )
    ipv4 = (
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x00\x00\x00" + bytes((255, 17)) + b"\x00\x00"
        + b"\xc0\x00\x02\x1a" + b"\xe0\x00\x00\xfb" + udp
    )
    ethernet = bytes.fromhex("01005e0000fb0266778899aa0800") + ipv4
    return CapturedFrame(
        timestamp=Decimal("1792341600.125"),
        interface="test0", data=ethernet,
        captured_length=len(ethernet), original_length=len(ethernet),
        link_type=1,
    )


def _project(**kwargs):
    observed = MDNSEventPipeline().process(_packet(**kwargs))
    assert observed is not None
    return observed, project_dnssd_advertisements(observed)


def test_advertisement_joins_native_type_instance_srv_txt_and_addresses():
    observation, claims = _project(extra_address=True)
    assert len(claims) == 1
    ad = claims[0]
    assert ad.service_type.text == "_demo._tcp.local"
    assert ad.instance.labels[0] == b"Living.Room"
    assert r"Living\x2eRoom._demo._tcp.local" == ad.instance.text
    assert ad.ptr_record.wire.ttl == 4500
    assert len(ad.targets) == 1
    target = ad.targets[0]
    assert target.srv.target.text == "host.local"
    assert target.srv.port == 4070
    assert target.srv_record.cache_flush
    assert [r.wire.decoded_data for r in target.address_records] == [
        "192.0.2.25", "2001:db8::25"
    ]
    assert len(ad.txt_records) == 1
    assert ad.txt_records[0].txt.entries[0].raw == b"CPath=/zc"
    assert ad.txt_records[0].txt_record.wire.ttl == 600
    out = format_dnssd_advertisement(observation, ad)
    assert "service=_demo._tcp.local" in out
    assert "target=host.local:4070" in out
    assert "192.0.2.25,2001:db8::25" in out
    assert "sender=192.0.2.26" in out
    assert "scope=same-response-evidence" in out
    assert "Spotify" not in out


def test_ptr_only_keeps_incomplete_service_evidence():
    _, claims = _project(with_srv=False, with_txt=False, with_addr=False)
    assert len(claims) == 1
    assert claims[0].targets == ()
    assert claims[0].txt_records == ()


def test_address_claim_not_linked_without_matching_srv_target():
    _, claims = _project(srv_target=DIFFERENT)
    assert len(claims) == 1
    assert claims[0].targets[0].srv.target.text == "other.local"
    assert claims[0].targets[0].address_records == ()


def test_query_known_answer_is_not_promoted_to_advertised_service():
    _, claims = _project(response=False)
    assert claims == ()


@pytest.mark.parametrize(("owner", "instance"), [
    (_name("25", "2", "0", "192", "in-addr", "arpa"), INSTANCE),
    (_name("_services", "_dns-sd", "_udp", "local"), SERVICE),
    (SERVICE, _name("instance", "_other", "_tcp", "local")),
])
def test_unrelated_ptr_and_service_enumeration_are_not_instance_ads(owner, instance):
    _, claims = _project(ptr_owner=owner, ptr_target=instance)
    assert claims == ()


def test_zero_ttl_ptr_is_a_goodbye_candidate_not_current_reachability():
    _, claims = _project(ptr_ttl=0)
    assert claims[0].ptr_record.goodbye_candidate
    assert not hasattr(claims[0], "is_online")


def test_malformed_srv_record_does_not_generate_guessed_service_claim():
    observation = MDNSEventPipeline().process(_packet(broken_srv=True))
    assert observation is not None
    with pytest.raises((DNSParseError, DNSSDParseError)):
        project_dnssd_advertisements(observation)


def test_malformed_txt_record_does_not_generate_guessed_metadata():
    observation = MDNSEventPipeline().process(
        _packet(txt_data=b"\x05abcd")
    )
    assert observation is not None
    with pytest.raises(DNSSDParseError, match="extends beyond"):
        project_dnssd_advertisements(observation)


def test_projection_is_immutable_and_preserves_original_wire_record():
    observation, ads = _project()
    assert ads[0].ptr_record.wire.rdata == INSTANCE
    with pytest.raises(FrozenInstanceError):
        ads[0].service_type = observation.message.answers[0].wire.name


def test_only_same_message_rrs_are_joined():
    # A PTR-only response is not fused with a later SRV-only response.
    _, initial = _project(with_srv=False, with_txt=False, with_addr=False)
    assert len(initial) == 1 and initial[0].targets == ()
    _, full = _project()
    assert full[0].targets
    assert initial[0].targets == ()
