"""Derived current network state for NOVXIS."""

from novxis.state.arp import (
    ARPBinding,
    ARPBindingChanged,
    ARPBindingLearned,
    ARPBindingRefreshed,
    ARPStateChange,
)
from novxis.state.dhcpv4 import (
    DHCPv4Acknowledgment,
    DHCPv4AcknowledgmentRecorded,
    DHCPv4AcknowledgmentState,
    DHCPv4AcknowledgmentUpdated,
    DHCPv4StateChange,
)
from novxis.state.dns import DNSRecordEvidence, DNSRelationshipState
from novxis.state.network import NetworkState
from novxis.state.mdns_services import (
    MDNSServiceEvidenceState,
    MDNSServiceInstanceSnapshot,
    MDNSServiceObservation,
    MDNSServiceRecordEvidence,
)

__all__ = [
    "ARPBinding",
    "ARPBindingChanged",
    "ARPBindingLearned",
    "ARPBindingRefreshed",
    "ARPStateChange",
    "DHCPv4Acknowledgment",
    "DHCPv4AcknowledgmentRecorded",
    "DHCPv4AcknowledgmentState",
    "DHCPv4AcknowledgmentUpdated",
    "DHCPv4StateChange",
    "DNSRecordEvidence",
    "DNSRelationshipState",
    "NetworkState",
    "MDNSServiceEvidenceState",
    "MDNSServiceInstanceSnapshot",
    "MDNSServiceObservation",
    "MDNSServiceRecordEvidence",
]
