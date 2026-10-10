"""Synthetic regression tests for conservative DHCPv4 exchange/state inference."""

from decimal import Decimal

import pytest

from novxis.capture.frame import CapturedFrame
from novxis.events.dhcpv4_correlator import DHCPv4Correlator, classify_dhcpv4_request
from novxis.pipeline.dhcpv4_state import DHCPv4StatePipeline
from novxis.presentation.dhcpv4_exchange_console import (
    format_dhcpv4_exchange,
    format_dhcpv4_acknowledgment,
)
from novxis.state.dhcpv4 import (
    DHCPv4AcknowledgmentRecorded,
    DHCPv4AcknowledgmentUpdated,
)

CLIENT_ADDRESS = bytes((192, 0, 2, 26))
SERVER_ADDRESS = bytes((192, 0, 2, 1))
ANOTHER_SERVER = bytes((192, 0, 2, 2))
CLIENT_MAC = bytes.fromhex("021122334455")
OTHER_CLIENT_MAC = bytes.fromhex("02aabbccddee")
CLIENT_ID = bytes((1,)) + CLIENT_MAC
REQUESTED_90_DAYS = 90 * 24 * 60 * 60
GRANTED_8_HOURS = 8 * 60 * 60


def _opt(code: int, payload: bytes) -> bytes:
    return bytes((code, len(payload))) + payload


def _frame(
    kind: int,
    *,
    timestamp: str = "100",
    xid: int = 0x1234ABCD,
    interface: str = "test0",
    client_mac: bytes = CLIENT_MAC,
    client_id: bytes | None = CLIENT_ID,
    requested_ip: bytes | None = None,
    selected_server: bytes | None = None,
    ciaddr: bytes = bytes(4),
    yiaddr: bytes | None = None,
    source: bytes | None = None,
    destination: bytes | None = None,
    ack_server: bytes | None = SERVER_ADDRESS,
    lease: int | None = None,
    extra_ack_options: bytes = b"",
) -> CapturedFrame:
    client_to_server = kind in (1, 3, 7, 8)
    if source is None:
        source = bytes(4) if client_to_server else SERVER_ADDRESS
    if destination is None:
        destination = bytes((255,) * 4) if client_to_server else CLIENT_ADDRESS
    if yiaddr is None:
        yiaddr = CLIENT_ADDRESS if kind in (2, 5) and kind != 8 else bytes(4)

    body = bytearray(236)
    body[0] = 1 if client_to_server else 2
    body[1:3] = b"\x01\x06"
    body[4:8] = xid.to_bytes(4, "big")
    body[12:16] = ciaddr
    body[16:20] = yiaddr
    body[28:34] = client_mac

    opts = _opt(53, bytes((kind,)))
    if client_id is not None:
        opts += _opt(61, client_id)
    if requested_ip is not None:
        opts += _opt(50, requested_ip)
    if selected_server is not None:
        opts += _opt(54, selected_server)
    if not client_to_server and ack_server is not None:
        opts += _opt(54, ack_server)
    if lease is None and kind in (2, 3, 5):
        lease = REQUESTED_90_DAYS if client_to_server else GRANTED_8_HOURS
    if lease is not None:
        opts += _opt(51, lease.to_bytes(4, "big"))
    if kind == 5:
        opts += extra_ack_options
    payload = bytes(body) + bytes.fromhex("63825363") + opts + b"\xff"
    udp = (
        (68 if client_to_server else 67).to_bytes(2, "big")
        + (67 if client_to_server else 68).to_bytes(2, "big")
        + (len(payload) + 8).to_bytes(2, "big") + b"\x00\x00" + payload
    )
    ipv4 = (
        b"\x45\x00" + (20 + len(udp)).to_bytes(2, "big")
        + b"\x00\x01\x40\x00\x40\x11\x00\x00"
        + source + destination + udp
    )
    raw = bytes.fromhex("ffffffffffff0211223344550800") + ipv4
    return CapturedFrame(
        timestamp=Decimal(timestamp), interface=interface,
        data=raw, captured_length=len(raw), original_length=len(raw), link_type=1
    )


def _request(**kw):
    return _frame(3, requested_ip=CLIENT_ADDRESS, **kw)


def test_init_reboot_request_ack_creates_ack_evidence_not_active_host():
    pipe = DHCPv4StatePipeline()
    initial = pipe.process(_request(timestamp="100"))
    assert initial is not None and initial.exchange is None
    assert classify_dhcpv4_request(initial.observation) == "INIT-REBOOT"

    extra = (
        _opt(1, bytes((255, 255, 255, 0)))
        + _opt(3, SERVER_ADDRESS)
        + _opt(6, SERVER_ADDRESS + ANOTHER_SERVER)
        + _opt(58, (14400).to_bytes(4, "big"))
        + _opt(59, (25200).to_bytes(4, "big"))
    )
    result = pipe.process(_frame(5, timestamp="100.050", extra_ack_options=extra))
    assert result is not None and result.exchange is not None
    assert result.exchange.request is initial.observation
    assert result.exchange.result == "ack"
    assert result.exchange.request_pattern == "INIT-REBOOT"
    assert result.exchange.duration == Decimal("0.050")
    assert isinstance(result.state_change, DHCPv4AcknowledgmentRecorded)
    record = result.state_change.current
    assert record.interface == "test0"
    assert record.hardware_address == CLIENT_MAC
    assert record.client_identifier == CLIENT_ID
    assert record.address == CLIENT_ADDRESS
    assert record.server_identifier == SERVER_ADDRESS
    assert record.lease_seconds == GRANTED_8_HOURS
    assert record.renewal_seconds == 14_400
    assert record.rebinding_seconds == 25_200
    assert record.subnet_mask == bytes((255, 255, 255, 0))
    assert record.routers == (SERVER_ADDRESS,)
    assert record.dns_servers == (SERVER_ADDRESS, ANOTHER_SERVER)
    assert pipe.state.arp_bindings == ()
    assert pipe.state.dhcpv4_acknowledgments == (record,)
    assert pipe.pending_requests == ()
    assert "50.000ms" in format_dhcpv4_exchange(result.exchange)
    assert "acknowledged_address=192.0.2.26" in format_dhcpv4_acknowledgment(record)


def test_second_ack_refreshes_client_snapshot_without_proving_connectivity():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request(timestamp="100"))
    pipe.process(_frame(5, timestamp="100.1"))
    pipe.process(_request(timestamp="200", xid=0x22222222))
    updated = pipe.process(_frame(5, timestamp="200.1", xid=0x22222222))
    assert updated is not None
    assert isinstance(updated.state_change, DHCPv4AcknowledgmentUpdated)
    assert updated.state_change.current.first_seen == Decimal("100.1")
    assert updated.state_change.current.last_seen == Decimal("200.1")
    assert updated.state_change.current.acknowledgment_count == 2
    assert len(pipe.state.dhcpv4_acknowledgments) == 1


def test_discover_can_match_offers_from_two_servers_without_ack_state():
    pipe = DHCPv4StatePipeline()
    discovered = pipe.process(_frame(1, timestamp="100"))
    first = pipe.process(_frame(2, timestamp="100.1", ack_server=SERVER_ADDRESS))
    second = pipe.process(_frame(
        2, timestamp="100.2", source=ANOTHER_SERVER, ack_server=ANOTHER_SERVER
    ))
    assert discovered is not None and first is not None and second is not None
    assert first.exchange is not None and first.exchange.result == "offer"
    assert second.exchange is not None and second.exchange.result == "offer"
    assert first.state_change is None and second.state_change is None
    assert len(pipe.pending_requests) == 1
    assert pipe.state.dhcpv4_acknowledgments == ()


def test_dhcpnak_is_matched_but_never_establishes_address():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request())
    result = pipe.process(_frame(6, timestamp="100.1", yiaddr=bytes(4)))
    assert result is not None and result.exchange is not None
    assert result.exchange.result == "nak"
    assert result.state_change is None
    assert pipe.state.dhcpv4_acknowledgments == ()


def test_inform_ack_is_not_a_lease_even_when_a_server_responds():
    pipe = DHCPv4StatePipeline()
    pipe.process(_frame(8, ciaddr=CLIENT_ADDRESS))
    reply = pipe.process(_frame(5, timestamp="100.1", yiaddr=bytes(4), lease=0))
    assert reply is not None and reply.exchange is not None
    assert reply.exchange.result == "inform-ack"
    assert reply.state_change is None


@pytest.mark.parametrize(
    "wrong",
    [
        {"xid": 0x99999999},
        {"client_mac": OTHER_CLIENT_MAC},
        {"client_id": bytes.fromhex("01aabbccddeeff")},
        {"interface": "other0"},
        {"timestamp": "111"},
    ],
)
def test_wrong_xid_client_identity_interface_or_expired_ack_is_not_correlated(wrong):
    pipe = DHCPv4StatePipeline(correlation_window=Decimal("5"))
    pipe.process(_request())
    reply = pipe.process(_frame(5, **wrong))
    assert reply is not None and reply.exchange is None
    assert pipe.state.dhcpv4_acknowledgments == ()


def test_acknowledgment_for_other_address_is_rejected():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request())
    other_addr = bytes((192, 0, 2, 99))
    reply = pipe.process(_frame(5, timestamp="100.1", yiaddr=other_addr))
    assert reply is not None and reply.exchange is None


def test_selected_server_must_agree_with_reply_identifier():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request(selected_server=SERVER_ADDRESS))
    wrong = pipe.process(_frame(5, timestamp="100.1", ack_server=ANOTHER_SERVER))
    assert wrong is not None and wrong.exchange is None
    correct = pipe.process(_frame(5, timestamp="100.2"))
    assert correct is not None and correct.exchange is not None
    assert correct.exchange.request_pattern == "SELECTING"


def test_renewing_and_rebinding_are_pattern_classifications():
    pipe = DHCPv4StatePipeline()
    renew = pipe.process(_frame(
        3, timestamp="100", requested_ip=None, ciaddr=CLIENT_ADDRESS,
        source=CLIENT_ADDRESS, destination=SERVER_ADDRESS
    ))
    rebind = pipe.process(_frame(
        3, timestamp="101", xid=0xABABABAB, requested_ip=None,
        ciaddr=CLIENT_ADDRESS, source=CLIENT_ADDRESS,
        destination=bytes((255,) * 4)
    ))
    assert renew is not None and rebind is not None
    assert classify_dhcpv4_request(renew.observation) == "RENEWING"
    assert classify_dhcpv4_request(rebind.observation) == "REBINDING"


def test_unsupported_release_never_records_acknowledged_configuration():
    pipe = DHCPv4StatePipeline()
    observed = pipe.process(_frame(7, timestamp="100"))
    assert observed is not None
    assert observed.exchange is None and observed.state_change is None


def test_unmatched_ack_alone_never_creates_state():
    pipe = DHCPv4StatePipeline()
    response = pipe.process(_frame(5, timestamp="101"))
    assert response is not None and response.exchange is None
    assert pipe.state.dhcpv4_acknowledgments == ()


def test_repeated_same_xid_from_different_clients_are_not_confused():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request(timestamp="100"))
    pipe.process(_request(
        timestamp="100.01", client_mac=OTHER_CLIENT_MAC,
        client_id=bytes((1,)) + OTHER_CLIENT_MAC
    ))
    original = pipe.process(_frame(5, timestamp="100.1"))
    assert original is not None and original.exchange is not None
    assert original.exchange.request.message.chaddr == CLIENT_MAC
    assert len(pipe.pending_requests) == 1


def test_invalid_correlation_window_fails_fast():
    with pytest.raises(ValueError, match="greater than zero"):
        DHCPv4Correlator(max_age=Decimal("0"))

def test_full_dora_sequence_produces_offer_then_ack_but_one_ack_snapshot():
    pipe = DHCPv4StatePipeline()
    discover = pipe.process(_frame(1, timestamp="100"))
    offer = pipe.process(_frame(2, timestamp="100.1"))
    request = pipe.process(_request(timestamp="100.2", selected_server=SERVER_ADDRESS))
    ack = pipe.process(_frame(5, timestamp="100.3"))
    assert discover is not None and discover.exchange is None
    assert offer is not None and offer.exchange is not None
    assert offer.exchange.result == "offer"
    assert request is not None and request.exchange is None
    assert request.observation.message.message_type == 3
    assert ack is not None and ack.exchange is not None
    assert ack.exchange.result == "ack"
    assert ack.exchange.request_pattern == "SELECTING"
    assert len(pipe.state.dhcpv4_acknowledgments) == 1
    assert pipe.pending_requests == ()


def test_dhcpnak_does_not_erase_earlier_ack_evidence():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request(timestamp="100"))
    pipe.process(_frame(5, timestamp="100.1"))
    prior = pipe.state.dhcpv4_acknowledgments
    pipe.process(_request(timestamp="200", xid=0xABCDEF01))
    denied = pipe.process(_frame(6, timestamp="200.1", xid=0xABCDEF01))
    assert denied is not None and denied.exchange is not None
    assert denied.exchange.result == "nak"
    assert denied.state_change is None
    assert pipe.state.dhcpv4_acknowledgments == prior


def test_malformed_client_identifier_does_not_match_a_valid_ack():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request(client_id=bytes((1,))))
    result = pipe.process(_frame(5, timestamp="100.1"))
    assert result is not None and result.exchange is None


def test_client_id_missing_on_response_can_match_identical_hardware_evidence():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request())
    result = pipe.process(_frame(5, timestamp="100.1", client_id=None))
    assert result is not None and result.exchange is not None


def test_state_rejects_older_ack_from_replayed_out_of_order_evidence():
    pipe = DHCPv4StatePipeline()
    pipe.process(_request(timestamp="100"))
    pipe.process(_frame(5, timestamp="100.1"))
    pipe.process(_request(timestamp="99", xid=0xF0000001))
    old = pipe.process(_frame(5, timestamp="99.1", xid=0xF0000001))
    assert old is not None and old.exchange is not None
    assert old.state_change is None
    assert pipe.state.dhcpv4_acknowledgments[0].last_seen == Decimal("100.1")
