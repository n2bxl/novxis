import pytest

from novxis.protocols.icmp import ICMPParseError, parse_icmp


def test_parse_echo_request_decodes_identifier_sequence_and_payload():
    message = parse_icmp(bytes.fromhex("0800abcd12340001deadbeef"))

    assert message.type == 8
    assert message.code == 0
    assert message.checksum == 0xABCD
    assert message.rest_of_header == bytes.fromhex("12340001")
    assert message.echo_identifier == 0x1234
    assert message.echo_sequence == 1
    assert message.payload == bytes.fromhex("deadbeef")


def test_parse_echo_reply_uses_same_echo_header_shape():
    message = parse_icmp(bytes.fromhex("000011112222ffff"))

    assert message.type == 0
    assert message.echo_identifier == 0x2222
    assert message.echo_sequence == 0xFFFF
    assert message.payload == b""


def test_parse_generic_icmp_preserves_rest_of_header_without_echo_interpretation():
    message = parse_icmp(bytes.fromhex("0301beef00000000aabb"))

    assert message.type == 3
    assert message.code == 1
    assert message.rest_of_header == b"\x00" * 4
    assert message.echo_identifier is None
    assert message.echo_sequence is None
    assert message.payload == bytes.fromhex("aabb")


def test_destination_unreachable_fragmentation_needed_exposes_next_hop_mtu():
    message = parse_icmp(bytes.fromhex("03041234000005dc") + (b"\x00" * 20))

    assert message.next_hop_mtu == 1500


def test_next_hop_mtu_is_not_inferred_for_other_messages():
    message = parse_icmp(bytes.fromhex("0b001234000005dc") + (b"\x00" * 20))

    assert message.next_hop_mtu is None


def test_parse_icmp_rejects_truncated_base_message():
    with pytest.raises(ICMPParseError, match="at least 8 bytes"):
        parse_icmp(b"\x08" + (b"\x00" * 6))
