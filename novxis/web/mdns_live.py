"""Bounded, source-scoped mDNS counts and PTR-backed service observations.

This browser-side state consumes *only* normalized, bounded NDJSON; no
packet bytes, TXT values, or raw application content cross the pipe.
It is not an mDNS cache and does not infer device identity or liveness.
"""

from decimal import Decimal, InvalidOperation
from ipaddress import ip_address

MAX_ADVERTISEMENTS_PER_MESSAGE = 6
MAX_SERVICE_INSTANCES = 128
MAX_NAME_LENGTH = 180
MAX_SERVICE_TARGETS = 2
MAX_TARGET_ADDRESSES = 3
MAX_TIMESTAMP = Decimal("10000000000000")


def _time(value) -> Decimal:
    if not isinstance(value, str):
        raise ValueError("mDNS timestamp must be text")
    try:
        at = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("invalid mDNS timestamp") from exc
    if not at.is_finite() or at < 0 or at > MAX_TIMESTAMP:
        raise ValueError("invalid mDNS timestamp")
    return at


class LiveMDNSState:
    """Current-session observations with bounded per-instance TTL evidence."""

    def __init__(self):
        self.messages = 0
        self.queries = 0
        self.responses = 0
        self.ipv4 = 0
        self.ipv6 = 0
        self.advertisement_count = 0
        self.omitted_advertisements = 0
        self.decode_errors = 0
        self.truncated = False
        self._instances = {}

    def observe(self, message: dict, interface: str) -> None:
        if message.get("interface") != interface:
            raise ValueError("mDNS observation outside capture interface")
        ip_family = message.get("ip_version")
        role = message.get("role")
        count = message.get("advertisement_count")
        ads = message.get("advertisements")
        if type(ip_family) is not int or ip_family not in (4, 6):
            raise ValueError("unsupported mDNS IP version")
        if role not in ("query", "response"):
            raise ValueError("invalid mDNS role")
        if type(count) is not int or not 0 <= count <= 4096:
            raise ValueError("invalid mDNS advertisement count")
        if not isinstance(ads, list) or len(ads) > MAX_ADVERTISEMENTS_PER_MESSAGE:
            raise ValueError("mDNS advertisement list too large")
        if count < len(ads) or (role == "query" and (count or ads)):
            raise ValueError("query cannot assert service advertisements")
        at = _time(message.get("observed_at"))

        relation_omissions = message.get("relationships_omitted", False)
        if type(relation_omissions) is not bool:
            raise ValueError("invalid relationship omission marker")
        normalized = []
        for record in ads:
            if not isinstance(record, dict):
                raise ValueError("invalid service record")
            service_type = record.get("service_type")
            instance = record.get("instance")
            ttl = record.get("ttl")
            if not all(isinstance(s, str) and 1 <= len(s) <= MAX_NAME_LENGTH
                       and s.isprintable() for s in (service_type, instance)):
                raise ValueError("invalid mDNS service name")
            if type(ttl) is not int or not 0 <= ttl <= 0xFFFFFFFF:
                raise ValueError("invalid mDNS PTR TTL")
            claims = record.get("targets", [])
            if not isinstance(claims, list) or len(claims) > MAX_SERVICE_TARGETS:
                raise ValueError("invalid SRV target list")
            targets = []
            for claim in claims:
                if not isinstance(claim, dict):
                    raise ValueError("invalid SRV target claim")
                target = claim.get("target")
                port = claim.get("port")
                srv_ttl = claim.get("ttl")
                if not isinstance(target, str) or not (
                    1 <= len(target) <= MAX_NAME_LENGTH and target.isprintable()
                ):
                    raise ValueError("invalid SRV target name")
                if type(port) is not int or not 0 <= port <= 65535:
                    raise ValueError("invalid SRV port")
                if type(srv_ttl) is not int or not 0 <= srv_ttl <= 0xFFFFFFFF:
                    raise ValueError("invalid SRV TTL")
                claimed_addresses = claim.get("addresses")
                if not isinstance(claimed_addresses, list) or (
                    len(claimed_addresses) > MAX_TARGET_ADDRESSES
                ):
                    raise ValueError("invalid A/AAAA list")
                addresses = []
                for address_record in claimed_addresses:
                    if not isinstance(address_record, dict):
                        raise ValueError("invalid A/AAAA claim")
                    raw = address_record.get("address")
                    family = address_record.get("family")
                    address_ttl = address_record.get("ttl")
                    if not isinstance(raw, str) or len(raw) > 45:
                        raise ValueError("invalid A/AAAA address")
                    if type(family) is not int or family not in (4, 6):
                        raise ValueError("invalid A/AAAA family")
                    if type(address_ttl) is not int or not (
                        0 <= address_ttl <= 0xFFFFFFFF
                    ):
                        raise ValueError("invalid A/AAAA TTL")
                    try:
                        parsed = ip_address(raw)
                    except ValueError as exc:
                        raise ValueError("invalid A/AAAA address") from exc
                    if parsed.version != family or str(parsed) != raw:
                        raise ValueError("noncanonical or mismatched A/AAAA address")
                    addresses.append({
                        "address": raw, "family": family, "ttl": address_ttl,
                    })
                targets.append({
                    "target": target, "port": port, "ttl": srv_ttl,
                    "addresses": addresses,
                })
            normalized.append((service_type, instance, ttl, targets))

        # Validate all metadata before modifying counters or service state.
        self.messages += 1
        self.queries += int(role == "query")
        self.responses += int(role == "response")
        self.ipv4 += int(ip_family == 4)
        self.ipv6 += int(ip_family == 6)
        self.advertisement_count += count
        self.omitted_advertisements += count - len(normalized)
        if count != len(normalized) or relation_omissions:
            self.truncated = True

        for service_type, instance, ttl, targets in normalized:
            key = (interface, service_type.lower(), instance.lower())
            previous = self._instances.get(key)
            if previous is None and len(self._instances) >= MAX_SERVICE_INSTANCES:
                self.truncated = True
                self.omitted_advertisements += 1
                continue
            if previous is not None and at < previous["last_seen"]:
                # Out-of-order packet evidence doesn't extend PTR freshness.
                continue
            self._instances[key] = {
                "service_type": service_type,
                "instance": instance,
                "last_seen": at,
                "ttl": ttl,
                "targets": targets,
                "observations": (previous["observations"] if previous else 0) + 1,
            }

    def observe_reconciliation(self, message: dict, interface: str) -> bool:
        """Validate then overlay provenance-preserving cross-response targets.

        Never create a PTR service instance from SRV/A/AAAA alone. The PTR
        epoch must match a previously accepted advertisement in this
        capture session. No old/later orphan can revive a stale PTR.
        """
        if message.get("interface") != interface:
            raise ValueError("reconciliation outside capture interface")
        service_type = message.get("service_type")
        instance = message.get("instance")
        if not all(isinstance(value, str)
                   and 1 <= len(value) <= MAX_NAME_LENGTH
                   and value.isprintable()
                   for value in (service_type, instance)):
            raise ValueError("invalid reconciliation service identity")
        ptr_at = _time(message.get("ptr_observed_at"))
        snapshot_at = _time(message.get("as_of"))
        if ptr_at > snapshot_at:
            raise ValueError("reconciliation PTR after capture time")
        omitted = message.get("relationships_omitted", False)
        if type(omitted) is not bool:
            raise ValueError("invalid reconciliation truncation marker")
        raw_targets = message.get("targets")
        if not isinstance(raw_targets, list) or not (
            1 <= len(raw_targets) <= MAX_SERVICE_TARGETS
        ):
            raise ValueError("invalid reconciled target list")

        targets = []
        has_cross_response = False
        for raw_target in raw_targets:
            if not isinstance(raw_target, dict):
                raise ValueError("invalid reconciled SRV target")
            name = raw_target.get("target")
            port = raw_target.get("port")
            ttl = raw_target.get("ttl")
            observed_at = _time(raw_target.get("observed_at"))
            origin = raw_target.get("origin")
            if not isinstance(name, str) or not (
                1 <= len(name) <= MAX_NAME_LENGTH and name.isprintable()
            ):
                raise ValueError("invalid reconciled SRV name")
            if type(port) is not int or not 0 <= port <= 65535:
                raise ValueError("invalid reconciled SRV port")
            if type(ttl) is not int or not 0 <= ttl <= 0xFFFFFFFF:
                raise ValueError("invalid reconciled SRV TTL")
            if observed_at > snapshot_at or origin not in (
                "same-mdns-response", "cross-mdns-response",
            ):
                raise ValueError("invalid SRV record provenance")
            if origin == "cross-mdns-response":
                has_cross_response = True
            raw_addresses = raw_target.get("addresses")
            if not isinstance(raw_addresses, list) or (
                len(raw_addresses) > MAX_TARGET_ADDRESSES
            ):
                raise ValueError("invalid reconciled A/AAAA list")
            addresses = []
            for item in raw_addresses:
                if not isinstance(item, dict):
                    raise ValueError("invalid reconciled address claim")
                raw = item.get("address")
                family = item.get("family")
                addr_ttl = item.get("ttl")
                addr_at = _time(item.get("observed_at"))
                addr_origin = item.get("origin")
                if not isinstance(raw, str) or len(raw) > 45:
                    raise ValueError("invalid reconciled A/AAAA address")
                if type(family) is not int or family not in (4, 6):
                    raise ValueError("invalid reconciled address family")
                if type(addr_ttl) is not int or not 0 <= addr_ttl <= 0xFFFFFFFF:
                    raise ValueError("invalid reconciled A/AAAA TTL")
                if addr_at > snapshot_at or addr_origin not in (
                    "same-mdns-response", "cross-mdns-response",
                ):
                    raise ValueError("invalid address record provenance")
                try:
                    parsed = ip_address(raw)
                except ValueError as exc:
                    raise ValueError("invalid reconciled IP address") from exc
                if parsed.version != family or str(parsed) != raw:
                    raise ValueError("mismatched reconciled address family")
                if addr_origin == "cross-mdns-response":
                    has_cross_response = True
                addresses.append({
                    "address": raw, "family": family,
                    "ttl": addr_ttl, "observed_at": addr_at,
                    "origin": addr_origin,
                })
            targets.append({
                "target": name, "port": port, "ttl": ttl,
                "observed_at": observed_at, "origin": origin,
                "addresses": addresses,
            })
        if not has_cross_response:
            raise ValueError("no cross-message evidence in reconciliation")

        key = (interface, service_type.lower(), instance.lower())
        entry = self._instances.get(key)
        if entry is None or entry["last_seen"] != ptr_at:
            # Never create a service without a PTR or attach an outdated PTR
            # epoch to a newer instance. A bounded service cap may omit PTRs.
            return False
        previous_at = entry.get("reconciled_as_of")
        if previous_at is not None and snapshot_at < previous_at:
            return False
        entry["reconciled_targets"] = targets
        entry["reconciled_as_of"] = snapshot_at
        if omitted:
            self.truncated = True
        return True

    def clear_reconciliation(self, message: dict, interface: str) -> bool:
        """Explicitly retract a previously joined overlay when it is invalid."""
        if message.get("interface") != interface:
            raise ValueError("reconciliation clear outside capture interface")
        service_type = message.get("service_type")
        instance = message.get("instance")
        if not all(isinstance(value, str)
                   and 1 <= len(value) <= MAX_NAME_LENGTH
                   and value.isprintable()
                   for value in (service_type, instance)):
            raise ValueError("invalid reconciliation clear name")
        ptr_at = _time(message.get("ptr_observed_at"))
        as_of = _time(message.get("as_of"))
        if ptr_at > as_of:
            raise ValueError("invalid reconciliation clear chronology")
        key = (interface, service_type.lower(), instance.lower())
        entry = self._instances.get(key)
        if entry is None or entry["last_seen"] != ptr_at:
            return False
        if as_of < entry.get("reconciled_as_of", Decimal(0)):
            return False
        if "reconciled_targets" not in entry:
            return False
        del entry["reconciled_targets"]
        del entry["reconciled_as_of"]
        return True

    def decode_error(self) -> None:
        self.decode_errors += 1

    def snapshot(self, at: Decimal) -> tuple[dict, tuple]:
        if not isinstance(at, Decimal) or not at.is_finite():
            raise ValueError("snapshot time must be finite")
        instances = []
        signature = []
        for entry in sorted(
            self._instances.values(),
            key=lambda x: (x["service_type"].lower(), x["instance"].lower()),
        ):
            fresh = entry["ttl"] > 0 and (
                entry["last_seen"] <= at <
                entry["last_seen"] + Decimal(entry["ttl"])
            )
            targets = []
            target_signature = []
            for target in entry.get("reconciled_targets", entry["targets"]):
                target_at = target.get("observed_at", entry["last_seen"])
                srv_fresh = target["ttl"] > 0 and (
                    target_at <= at <
                    target_at + Decimal(target["ttl"])
                )
                addresses = []
                address_signature = []
                for rr in target["addresses"]:
                    address_at = rr.get("observed_at", entry["last_seen"])
                    address_fresh = rr["ttl"] > 0 and (
                        address_at <= at <
                        address_at + Decimal(rr["ttl"])
                    )
                    addresses.append({
                        **rr, "observed_at": str(address_at),
                        "fresh": address_fresh,
                        "source": rr.get("origin", "same-mdns-response"),
                        "path_fresh": fresh and srv_fresh and address_fresh,
                    })
                    address_signature.append(address_fresh)
                targets.append({
                    "target": target["target"], "port": target["port"],
                    "ttl_seconds": target["ttl"], "fresh": srv_fresh,
                    "path_fresh": fresh and srv_fresh,
                    "addresses": addresses,
                    "observed_at": str(target_at),
                    "source": target.get("origin", "same-mdns-response"),
                })
                target_signature.append((srv_fresh, tuple(address_signature)))
            instances.append({
                "service_type": entry["service_type"],
                "instance": entry["instance"],
                "last_seen": str(entry["last_seen"]),
                "ttl_seconds": entry["ttl"],
                "fresh": fresh,
                "observations": entry["observations"],
                "targets": targets,
            })
            signature.append((
                entry["service_type"], entry["instance"], fresh,
                tuple(target_signature),
            ))
        signature = tuple(signature)
        result = {
            "schema_version": 1,
            "origin": "mdns-observation",
            "messages": self.messages,
            "queries": self.queries,
            "responses": self.responses,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "ptr_advertisements": self.advertisement_count,
            "omitted_advertisements": self.omitted_advertisements,
            "decode_errors": self.decode_errors,
            "truncated": self.truncated,
            "retained_instances": len(instances),
            "fresh_instances": sum(item["fresh"] for item in instances),
            "services": instances,
            "as_of": str(at),
            "limitation": (
                "Observed PTR advertisements are not verified running "
                "services or physical device identities."
            ),
        }
        return result, signature
