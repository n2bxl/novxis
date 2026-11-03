"""Bounded, source-scoped mDNS counts and PTR-backed service observations.

This browser-side state consumes *only* normalized, bounded NDJSON; no
packet bytes, TXT values, or raw application content cross the pipe.
It is not an mDNS cache and does not infer device identity or liveness.
"""

from decimal import Decimal, InvalidOperation

MAX_ADVERTISEMENTS_PER_MESSAGE = 6
MAX_SERVICE_INSTANCES = 128
MAX_NAME_LENGTH = 180
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
        family = message.get("ip_version")
        role = message.get("role")
        count = message.get("advertisement_count")
        ads = message.get("advertisements")
        if type(family) is not int or family not in (4, 6):
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
            normalized.append((service_type, instance, ttl))

        # Validate all metadata before modifying counters or service state.
        self.messages += 1
        self.queries += int(role == "query")
        self.responses += int(role == "response")
        self.ipv4 += int(family == 4)
        self.ipv6 += int(family == 6)
        self.advertisement_count += count
        self.omitted_advertisements += count - len(normalized)
        if count != len(normalized):
            self.truncated = True

        for service_type, instance, ttl in normalized:
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
                "observations": (previous["observations"] if previous else 0) + 1,
            }

    def decode_error(self) -> None:
        self.decode_errors += 1

    def snapshot(self, at: Decimal) -> tuple[dict, tuple]:
        if not isinstance(at, Decimal) or not at.is_finite():
            raise ValueError("snapshot time must be finite")
        instances = []
        for entry in sorted(
            self._instances.values(),
            key=lambda x: (x["service_type"].lower(), x["instance"].lower()),
        ):
            fresh = entry["ttl"] > 0 and (
                entry["last_seen"] <= at <
                entry["last_seen"] + Decimal(entry["ttl"])
            )
            instances.append({
                "service_type": entry["service_type"],
                "instance": entry["instance"],
                "last_seen": str(entry["last_seen"]),
                "ttl_seconds": entry["ttl"],
                "fresh": fresh,
                "observations": entry["observations"],
            })
        signature = tuple(
            (item["service_type"], item["instance"], item["fresh"])
            for item in instances
        )
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
