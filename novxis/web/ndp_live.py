"""Unprivileged, bounded NDP metadata presentation state.

Only sanitized validated local NDJSON events are ingested. This models
source-SLLA and target-TLLA *observations*, not a trusted neighbor cache,
a reachability state, an IPv6 host identity or an NDP TTL.
"""

from decimal import Decimal, InvalidOperation
from ipaddress import IPv6Address

CLAIM_KINDS = frozenset(("ns_source_slla", "na_target_tlla"))
UNLINKED_REASONS = frozenset((
    "dad_tentative", "ns_missing_slla", "na_missing_tlla",
    "ns_ambiguous_slla", "na_ambiguous_tlla",
    "ns_non_ethernet_slla", "na_non_ethernet_tlla",
    "ns_unusable_slla", "na_unusable_tlla", "ns_nonunicast_source",
))
MAX_TIMESTAMP = Decimal("10000000000000")


def _at(value) -> Decimal:
    if not isinstance(value, str):
        raise ValueError("NDP capture time must be a string")
    try:
        at = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("invalid NDP capture time") from exc
    if not at.is_finite() or at < 0 or at > MAX_TIMESTAMP:
        raise ValueError("invalid NDP capture time")
    return at


def _address(value) -> str:
    if not isinstance(value, str) or len(value) > 45:
        raise ValueError("invalid IPv6 address")
    try:
        parsed = IPv6Address(value)
    except ValueError as exc:
        raise ValueError("invalid IPv6 address") from exc
    if str(parsed) != value:
        raise ValueError("noncanonical IPv6 address")
    return value


def _mac(value) -> str:
    if not isinstance(value, str) or len(value) != 12:
        raise ValueError("invalid Ethernet address")
    try:
        parsed = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("invalid Ethernet address") from exc
    if len(parsed) != 6 or parsed.hex() != value:
        raise ValueError("noncanonical Ethernet address")
    return value


class LiveNDPState:
    """Retains bounded distinct address assertions and unlinked observations."""

    def __init__(self, *, max_claims: int = 128, max_unlinked: int = 128):
        for value in (max_claims, max_unlinked):
            if type(value) is not int or not 1 <= value <= 4096:
                raise ValueError("NDP caps must be positive, bounded integers")
        self.max_claims = max_claims
        self.max_unlinked = max_unlinked
        self.messages = self.ns = self.na = self.dad = self.decode_errors = 0
        self.omitted_claims = self.omitted_unlinked = 0
        self._claims = {}
        self._unlinked = {}

    def decode_error(self):
        self.decode_errors += 1

    def observe(self, message: dict, interface: str) -> None:
        """Validate all fields, including provenance semantics, before mutation."""
        if message.get("interface") != interface:
            raise ValueError("NDP event outside capture interface")
        at = _at(message.get("observed_at"))
        kind = message.get("message_type")
        if kind not in ("ns", "na"):
            raise ValueError("unsupported NDP message kind")
        source = _address(message.get("source_ipv6"))
        target = _address(message.get("target_ipv6"))
        ethernet = _mac(message.get("frame_source_hex"))
        dad = message.get("dad")
        if type(dad) is not bool:
            raise ValueError("invalid NDP DAD marker")
        if dad != (kind == "ns" and source == "::"):
            raise ValueError("inconsistent NDP DAD source")
        claimed_kind = message.get("claim_kind")
        claimed_ip = message.get("claim_ipv6")
        claimed_mac = message.get("claim_mac_hex")
        reason = message.get("unlinked_reason")

        if claimed_kind is not None:
            if claimed_kind not in CLAIM_KINDS or reason is not None:
                raise ValueError("invalid NDP claim provenance")
            if (kind == "ns") != (claimed_kind == "ns_source_slla"):
                raise ValueError("wrong NDP claim kind")
            address = _address(claimed_ip)
            mac = _mac(claimed_mac)
            if dad or address != (source if kind == "ns" else target):
                raise ValueError("invalid NDP source/target address association")
            value = bytes.fromhex(mac)
            if value == bytes(6) or value[0] & 1:
                raise ValueError("unusable NDP link-layer claim")
            if kind == "ns" and IPv6Address(source).is_multicast:
                raise ValueError("multicast NS source is not claimable")
        else:
            if claimed_ip is not None or claimed_mac is not None:
                raise ValueError("unlinked NDP event has claim fields")
            if reason not in UNLINKED_REASONS:
                raise ValueError("invalid unlinked NDP reason")
            if dad != (reason == "dad_tentative"):
                raise ValueError("DAD reason/source mismatch")
            if (kind == "ns") != reason.startswith("ns_") and not dad:
                raise ValueError("incorrect NS/NA unlinked provenance")
            if kind == "na" and reason.startswith("ns_"):
                raise ValueError("NA cannot use NS unlinked reason")
            if kind == "ns" and reason.startswith("na_"):
                raise ValueError("NS cannot use NA unlinked reason")

        # All validation completed before counters, retention, or revision change.
        self.messages += 1
        self.ns += int(kind == "ns")
        self.na += int(kind == "na")
        self.dad += int(dad)
        if claimed_kind is not None:
            key = (interface, address, mac, claimed_kind)
            store, cap = self._claims, self.max_claims
            entry = {
                "interface": interface, "address": address,
                "mac": mac, "kind": claimed_kind,
            }
        else:
            key = (interface, source, target, ethernet, reason)
            store, cap = self._unlinked, self.max_unlinked
            entry = {
                "interface": interface, "source": source, "target": target,
                "frame_source": ethernet, "reason": reason,
            }
        previous = store.get(key)
        entry["first_seen"] = str(min(at, Decimal(previous["first_seen"]))) if previous else str(at)
        entry["last_seen"] = str(max(at, Decimal(previous["last_seen"]))) if previous else str(at)
        entry["observations"] = previous["observations"] + 1 if previous else 1
        store[key] = entry
        if len(store) > cap:
            oldest = min(
                store, key=lambda k: (Decimal(store[k]["last_seen"]), k)
            )
            del store[oldest]
            if claimed_kind is not None:
                self.omitted_claims += 1
            else:
                self.omitted_unlinked += 1

    def snapshot(self, interface: str) -> dict:
        claims = [self._claims[key].copy() for key in sorted(self._claims)]
        unlinked = [self._unlinked[key].copy() for key in sorted(self._unlinked)]
        by_address = {}
        for item in claims:
            by_address.setdefault(item["address"], set()).add(item["mac"])
        return {
            "schema_version": 1,
            "origin": "ndp-observation",
            "interface": interface,
            "messages": self.messages, "ns": self.ns, "na": self.na,
            "dad": self.dad, "decode_errors": self.decode_errors,
            "claims": claims, "unlinked": unlinked,
            "retained_claims": len(claims),
            "retained_unlinked": len(unlinked),
            "multiple_lla_addresses": sum(len(mac) > 1
                                          for mac in by_address.values()),
            "omitted_claims": self.omitted_claims,
            "omitted_unlinked": self.omitted_unlinked,
            "truncated": bool(self.omitted_claims or self.omitted_unlinked),
            "limitation": (
                "NDP packets assert options and addresses, not verified "
                "devices, ownership, adjacency, or reachability."
            ),
        }
