"""Network state derived from normalized NOVXIS events."""

from novxis.events import ARPMessageObserved
from novxis.events.dhcpv4_correlator import DHCPv4ExchangeCompleted
from novxis.state.dhcpv4 import (
    DHCPv4Acknowledgment,
    DHCPv4AcknowledgmentState,
    DHCPv4StateChange,
)
from novxis.state.arp import (
    ARPBinding,
    ARPBindingChanged,
    ARPBindingLearned,
    ARPBindingRefreshed,
    ARPStateChange,
)

ARPBindingKey = tuple[str, int, int, bytes]


class NetworkState:
    """Mutable current-state view built from normalized observations."""

    def __init__(self) -> None:
        self._arp_bindings: dict[ARPBindingKey, ARPBinding] = {}
        self._dhcpv4 = DHCPv4AcknowledgmentState()

    @property
    def dhcpv4_acknowledgments(self) -> tuple[DHCPv4Acknowledgment, ...]:
        """Latest matched DHCP ACKs, not proof of currently active leases."""
        return self._dhcpv4.acknowledgments

    def observe_dhcpv4_exchange(
        self, exchange: DHCPv4ExchangeCompleted
    ) -> DHCPv4StateChange | None:
        return self._dhcpv4.observe_exchange(exchange)

    @property
    def arp_bindings(self) -> tuple[ARPBinding, ...]:
        """Return a snapshot of currently known ARP-derived bindings."""
        return tuple(self._arp_bindings.values())

    def get_arp_binding(
        self,
        *,
        interface: str,
        hardware_type: int,
        protocol_type: int,
        protocol_address: bytes,
    ) -> ARPBinding | None:
        """Return the current binding for one scoped protocol address."""
        return self._arp_bindings.get(
            (
                interface,
                hardware_type,
                protocol_type,
                protocol_address,
            )
        )

    def observe_arp(
        self,
        observation: ARPMessageObserved,
    ) -> ARPStateChange | None:
        """Update state from the sender fields of one ARP observation.

        Only sender fields are used because they are direct evidence asserted by
        the observed message. An all-zero sender protocol or hardware address
        does not establish a usable binding and is therefore not added to state.
        """
        message = observation.message

        if not any(message.sender_protocol):
            return None
        if not any(message.sender_hardware):
            return None

        key: ARPBindingKey = (
            observation.interface,
            message.hardware_type,
            message.protocol_type,
            message.sender_protocol,
        )
        previous = self._arp_bindings.get(key)

        if previous is None:
            current = ARPBinding(
                interface=observation.interface,
                hardware_type=message.hardware_type,
                protocol_type=message.protocol_type,
                protocol_address=message.sender_protocol,
                hardware_address=message.sender_hardware,
                first_seen=observation.timestamp,
                last_seen=observation.timestamp,
                observation_count=1,
            )
            self._arp_bindings[key] = current
            return ARPBindingLearned(
                binding=current,
                source=observation,
            )

        if previous.hardware_address == message.sender_hardware:
            current = ARPBinding(
                interface=previous.interface,
                hardware_type=previous.hardware_type,
                protocol_type=previous.protocol_type,
                protocol_address=previous.protocol_address,
                hardware_address=previous.hardware_address,
                first_seen=min(previous.first_seen, observation.timestamp),
                last_seen=max(previous.last_seen, observation.timestamp),
                observation_count=previous.observation_count + 1,
            )
            self._arp_bindings[key] = current
            return ARPBindingRefreshed(
                previous=previous,
                current=current,
                source=observation,
            )

        current = ARPBinding(
            interface=observation.interface,
            hardware_type=message.hardware_type,
            protocol_type=message.protocol_type,
            protocol_address=message.sender_protocol,
            hardware_address=message.sender_hardware,
            first_seen=observation.timestamp,
            last_seen=observation.timestamp,
            observation_count=1,
        )
        self._arp_bindings[key] = current
        return ARPBindingChanged(
            previous=previous,
            current=current,
            source=observation,
        )
