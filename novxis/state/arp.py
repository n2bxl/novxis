"""ARP-derived network-state models and changes."""

from dataclasses import dataclass
from decimal import Decimal

from novxis.events import ARPMessageObserved


@dataclass(frozen=True, slots=True)
class ARPBinding:
    """Current observed ARP binding for one protocol address on one interface."""

    interface: str
    hardware_type: int
    protocol_type: int
    protocol_address: bytes
    hardware_address: bytes
    first_seen: Decimal
    last_seen: Decimal
    observation_count: int


@dataclass(frozen=True, slots=True)
class ARPBindingLearned:
    """A protocol-address binding was observed for the first time."""

    binding: ARPBinding
    source: ARPMessageObserved


@dataclass(frozen=True, slots=True)
class ARPBindingRefreshed:
    """An existing binding was observed again with the same hardware address."""

    previous: ARPBinding
    current: ARPBinding
    source: ARPMessageObserved


@dataclass(frozen=True, slots=True)
class ARPBindingChanged:
    """A protocol address was observed with a different hardware address."""

    previous: ARPBinding
    current: ARPBinding
    source: ARPMessageObserved


ARPStateChange = ARPBindingLearned | ARPBindingRefreshed | ARPBindingChanged
