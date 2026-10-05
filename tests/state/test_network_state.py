from decimal import Decimal

from novxis.capture.frame import CapturedFrame
from novxis.events import observe_arp
from novxis.protocols.arp import ARPMessage
from novxis.protocols.ethernet import EthernetFrame
from novxis.state import (
    ARPBindingChanged,
    ARPBindingLearned,
    ARPBindingRefreshed,
    NetworkState,
)


def _observation(
    *,
    timestamp: str = "100",
    interface: str = "en0",
    sender_hardware: bytes = b"\x02\x00\x00\x00\x00\x10",
    sender_protocol: bytes = bytes([192, 0, 2, 10]),
    target_hardware: bytes = b"\x00" * 6,
    target_protocol: bytes = bytes([192, 0, 2, 20]),
):
    message = ARPMessage(
        hardware_type=1,
        protocol_type=0x0800,
        hardware_length=6,
        protocol_length=4,
        opcode=1,
        sender_hardware=sender_hardware,
        sender_protocol=sender_protocol,
        target_hardware=target_hardware,
        target_protocol=target_protocol,
        trailing_bytes=b"",
    )
    captured = CapturedFrame(
        timestamp=Decimal(timestamp),
        interface=interface,
        data=b"",
        captured_length=0,
    )
    ethernet = EthernetFrame(
        destination=b"\xff" * 6,
        source=sender_hardware,
        ether_type=0x0806,
        payload=b"",
    )
    return observe_arp(captured, ethernet, message)


def test_learns_sender_binding_from_first_observation():
    state = NetworkState()
    observation = _observation()

    change = state.observe_arp(observation)

    assert isinstance(change, ARPBindingLearned)
    assert change.binding.protocol_address == bytes([192, 0, 2, 10])
    assert change.binding.hardware_address == b"\x02\x00\x00\x00\x00\x10"
    assert change.binding.observation_count == 1
    assert state.arp_bindings == (change.binding,)


def test_refreshes_existing_binding_without_replacing_identity():
    state = NetworkState()
    state.observe_arp(_observation(timestamp="100"))

    change = state.observe_arp(_observation(timestamp="101"))

    assert isinstance(change, ARPBindingRefreshed)
    assert change.current.first_seen == Decimal("100")
    assert change.current.last_seen == Decimal("101")
    assert change.current.observation_count == 2


def test_changed_hardware_emits_binding_changed():
    state = NetworkState()
    state.observe_arp(_observation())

    change = state.observe_arp(
        _observation(
            timestamp="102",
            sender_hardware=b"\x02\x00\x00\x00\x00\x99",
        )
    )

    assert isinstance(change, ARPBindingChanged)
    assert change.previous.hardware_address == b"\x02\x00\x00\x00\x00\x10"
    assert change.current.hardware_address == b"\x02\x00\x00\x00\x00\x99"
    assert change.current.first_seen == Decimal("102")
    assert change.current.observation_count == 1


def test_zero_sender_protocol_does_not_establish_binding():
    state = NetworkState()

    change = state.observe_arp(
        _observation(sender_protocol=b"\x00\x00\x00\x00")
    )

    assert change is None
    assert state.arp_bindings == ()


def test_zero_sender_hardware_does_not_establish_binding():
    state = NetworkState()

    change = state.observe_arp(
        _observation(sender_hardware=b"\x00" * 6)
    )

    assert change is None
    assert state.arp_bindings == ()


def test_same_protocol_address_is_scoped_by_interface():
    state = NetworkState()

    first = state.observe_arp(_observation(interface="en0"))
    second = state.observe_arp(
        _observation(
            interface="en5",
            sender_hardware=b"\x02\x00\x00\x00\x00\x55",
        )
    )

    assert isinstance(first, ARPBindingLearned)
    assert isinstance(second, ARPBindingLearned)
    assert len(state.arp_bindings) == 2


def test_target_fields_do_not_create_indirect_binding():
    state = NetworkState()

    state.observe_arp(
        _observation(
            target_hardware=b"\x02\x00\x00\x00\x00\x20",
            target_protocol=bytes([192, 0, 2, 20]),
        )
    )

    assert state.get_arp_binding(
        interface="en0",
        hardware_type=1,
        protocol_type=0x0800,
        protocol_address=bytes([192, 0, 2, 20]),
    ) is None
