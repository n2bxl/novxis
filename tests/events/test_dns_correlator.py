"""DNS correlation regression tests using actual synthetic Ethernet/IPv4/UDP/DNS."""

from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events.dns_correlator import DNSCorrelator, DNSExchangeCorrelated
from novxis.pipeline.dns import DNSEventPipeline
from novxis.presentation.dns_exchange_console import format_dns_exchange

CLIENT = bytes((192, 0, 2, 10))
RESOLVER = bytes((198, 51, 100, 53))
OTHER_RESOLVER = bytes((203, 0, 113, 53))


def _qname(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    return b"".join(
        bytes((len(label),)) + label.encode("ascii")
        for label in name.rstrip(".").split(".")
    ) + b"\x00"


def _observed(
    *,
    response: bool = False,
    timestamp: str = "100.000",
    interface: str = "test0",
    qname: str = "example.test",
    qtype: int = 1,
    qclass: int = 1,
    txid: int = 0x1234,
    client_port: int = 51000,
    client: bytes = CLIENT,
    resolver: bytes = RESOLVER,
    rcode: int = 0,
    opcode: int = 0,
    include_question: bool = True,
):
    """Build bytes then parse through the actual application observation path."""
    question = _qname(qname) + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big")
    flags = (0x8000 if response else 0) | (opcode << 11) | (rcode if response else 0)
    header = (
        txid.to_bytes(2, "big") + flags.to_bytes(2, "big")
        + int(include_question).to_bytes(2, "big")
        + bytes(6)
    )
    dns_payload = header + (question if include_question else b"")
    src_port, dst_port = (53, client_port) if response else (client_port, 53)
    udp = (
        src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big")
        + (8 + len(dns_payload)).to_bytes(2, "big") + b"\x00\x00" + dns_payload
    )
    ip_src, ip_dst = (resolver, client) if response else (client, resolver)
    ip = (
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x01\x40\x00\x40\x11\x00\x00"
        + ip_src + ip_dst + udp
    )
    ethernet = bytes.fromhex("0211223344550266778899aa") + b"\x08\x00" + ip
    frame = CapturedFrame(
        timestamp=Decimal(timestamp),
        interface=interface,
        data=ethernet,
        captured_length=len(ethernet),
        original_length=len(ethernet),
        link_type=1,
    )
    observation = DNSEventPipeline().process(frame)
    assert observation is not None
    return observation


def test_correlates_exact_request_response_with_round_trip_duration():
    matcher = DNSCorrelator()
    request = _observed()
    response = _observed(response=True, timestamp="100.005")
    assert matcher.observe(request) is None
    exchange = matcher.observe(response)

    assert isinstance(exchange, DNSExchangeCorrelated)
    assert exchange.request is request
    assert exchange.response is response
    assert exchange.duration == Decimal("0.005")
    assert matcher.pending_requests == ()
    output = format_dns_exchange(exchange)
    assert "id=0x1234" in output
    assert "q=example.test/TYPE1/class1" in output
    assert "duration=5.000ms" in output
    assert "evidence=observed-only" in output


def test_nxdomain_is_still_an_observed_complete_exchange():
    matcher = DNSCorrelator()
    matcher.observe(_observed(qtype=12))
    paired = matcher.observe(_observed(
        response=True, qtype=12, rcode=3, timestamp="100.007",
    ))
    assert paired is not None
    assert paired.response.message.header.response_code == 3
    assert "rcode=3" in format_dns_exchange(paired)


@pytest.mark.parametrize("changes", [
    {"interface": "other0"},
    {"client": bytes((192, 0, 2, 20))},
    {"resolver": OTHER_RESOLVER},
    {"client_port": 51001},
    {"txid": 0x9999},
    {"qname": "different.test"},
    {"qtype": 28},
    {"qclass": 3},
    {"opcode": 1},
])
def test_mismatched_reply_does_not_complete(changes):
    matcher = DNSCorrelator()
    request = _observed()
    matcher.observe(request)
    assert matcher.observe(_observed(
        response=True, timestamp="100.001", **changes
    )) is None
    assert matcher.pending_requests == (request,)


def test_case_insensitive_dns_labels_match_without_destroying_raw_evidence():
    matcher = DNSCorrelator()
    request = _observed(qname="ExAmPlE.TeSt")
    response = _observed(response=True, qname="example.test", timestamp="100.004")
    matcher.observe(request)
    pair = matcher.observe(response)
    assert pair is not None
    assert pair.request.message.questions[0].name.text == "ExAmPlE.TeSt"


def test_parallel_A_and_HTTPS_queries_stay_separate():
    matcher = DNSCorrelator()
    https_request = _observed(qtype=65, client_port=3981, txid=0x944C)
    a_request = _observed(qtype=1, client_port=8266, txid=0x4E7A)
    matcher.observe(https_request)
    matcher.observe(a_request)

    a_reply = _observed(
        response=True, qtype=1, client_port=8266, txid=0x4E7A,
        timestamp="100.006",
    )
    https_reply = _observed(
        response=True, qtype=65, client_port=3981, txid=0x944C,
        timestamp="100.007",
    )
    a_pair = matcher.observe(a_reply)
    https_pair = matcher.observe(https_reply)
    assert a_pair is not None and https_pair is not None
    assert a_pair.request is a_request
    assert https_pair.request is https_request
    assert matcher.pending_requests == ()


def test_unmatched_response_does_not_create_synthetic_query():
    matcher = DNSCorrelator()
    response = _observed(response=True)
    assert matcher.observe(response) is None
    assert matcher.pending_requests == ()


def test_repeated_response_does_not_generate_two_exchanges():
    matcher = DNSCorrelator()
    matcher.observe(_observed())
    reply = _observed(response=True, timestamp="100.004")
    assert matcher.observe(reply) is not None
    assert matcher.observe(reply) is None


def test_duplicate_pending_requests_quarantine_matching_key():
    matcher = DNSCorrelator(max_age=Decimal("2"))
    request = _observed()
    repeated = _observed(timestamp="100.100")
    matcher.observe(request)
    matcher.observe(repeated)
    assert matcher.pending_requests == ()
    assert matcher.observe(_observed(response=True, timestamp="100.200")) is None
    assert matcher.observe(_observed(timestamp="101.000")) is None
    assert matcher.observe(_observed(response=True, timestamp="101.005")) is None
    # After quarantine expires, a genuinely fresh transaction may pair.
    new_request = _observed(timestamp="104.000")
    matcher.observe(new_request)
    paired = matcher.observe(_observed(response=True, timestamp="104.004"))
    assert paired is not None and paired.request is new_request


def test_request_older_than_window_is_not_matched():
    matcher = DNSCorrelator(max_age=Decimal("1"))
    matcher.observe(_observed(timestamp="100"))
    assert matcher.observe(_observed(response=True, timestamp="101.001")) is None
    assert matcher.pending_requests == ()


def test_exact_time_boundary_is_accepted():
    matcher = DNSCorrelator(max_age=Decimal("1"))
    matcher.observe(_observed(timestamp="100"))
    assert matcher.observe(_observed(response=True, timestamp="101")) is not None


def test_response_before_request_timestamp_is_not_matched():
    matcher = DNSCorrelator()
    request = _observed(timestamp="100.100")
    matcher.observe(request)
    assert matcher.observe(_observed(response=True, timestamp="100.050")) is None
    assert matcher.pending_requests == (request,)


def test_out_of_order_replay_cannot_resurrect_stale_request():
    matcher = DNSCorrelator(max_age=Decimal("1"))
    matcher.observe(_observed(timestamp="103", txid=2))
    assert matcher.observe(_observed(timestamp="100", txid=1)) is None
    assert matcher.observe(_observed(
        response=True, timestamp="100.010", txid=1,
    )) is None
    assert len(matcher.pending_requests) == 1


def test_bounded_pending_requests_eviction_prefers_recency():
    matcher = DNSCorrelator(max_pending=2)
    first = _observed(txid=1)
    second = _observed(txid=2)
    third = _observed(txid=3)
    matcher.observe(first)
    matcher.observe(second)
    matcher.observe(third)
    assert matcher.pending_requests == (second, third)
    assert matcher.observe(_observed(response=True, txid=1)) is None
    assert matcher.observe(_observed(response=True, txid=2)) is not None


def test_nonstandard_opcode_and_empty_question_are_not_correlated():
    matcher = DNSCorrelator()
    matcher.observe(_observed(opcode=1))
    matcher.observe(_observed(include_question=False))
    assert matcher.pending_requests == ()
    assert matcher.observe(_observed(
        response=True, opcode=1, timestamp="100.005",
    )) is None


@pytest.mark.parametrize("age", [
    Decimal("0"), Decimal("-1"), Decimal("NaN"),
    Decimal("Infinity"), Decimal("-Infinity"),
])
def test_invalid_max_age_rejected(age):
    with pytest.raises(ValueError, match="finite"):
        DNSCorrelator(max_age=age)


@pytest.mark.parametrize("maximum", [0, -1, True, False, 1.5, "100"])
def test_invalid_max_pending_rejected(maximum):
    with pytest.raises(ValueError, match="positive integer"):
        DNSCorrelator(max_pending=maximum)
