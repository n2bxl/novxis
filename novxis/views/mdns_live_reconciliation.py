"""Bounded browser projection from the existing typed DNS-SD reconciliation.

The rich reconciliation engine owns captured frames on the capture side.
Only explicitly linked PTR/SRV/A/AAAA metadata can cross the local pipe.
No TXT values, frame bytes, fingerprints, topology, or device identity.
"""

import json
from ipaddress import ip_address

from novxis.protocols.dnssd import DNSSDSRV
from novxis.state.mdns_reconciliation import MDNSReconciledServiceSnapshot
from novxis.state.mdns_services import _name_key

MAX_RECONCILED_TARGETS = 2
MAX_RECONCILED_ADDRESSES = 3
MAX_RECONCILED_EVENT_SIZE = 3700
MAX_NAME_LENGTH = 180


def _safe_name(name: str) -> bool:
    return 1 <= len(name) <= MAX_NAME_LENGTH and name.isprintable()


def project_live_reconciliation(
    item: MDNSReconciledServiceSnapshot,
) -> dict | None:
    """Serialize *fresh* exact-name cross-message PTR -> SRV -> addresses.

    A standalone TXT cannot create a visible address relationship. At least
    one included SRV or A/AAAA record must come from a distinct response.
    The source-time for each record is retained for independent TTL expiry.
    """
    snap = item.snapshot
    if not snap.has_fresh_ptr or not item.cross_message_records:
        return None
    ptrs = [r for r in snap.fresh_records if r.kind == "PTR"]
    if not ptrs:
        return None
    ptr = max(ptrs, key=lambda r: r.observed_at)
    if ptr.source.interface != snap.interface:
        return None
    service_type, instance = snap.service_type.text, snap.instance.text
    if not (_safe_name(service_type) and _safe_name(instance)):
        return None

    result = {
        "type": "mdns_reconciliation",
        "interface": snap.interface,
        "service_type": service_type,
        "instance": instance,
        "ptr_observed_at": str(ptr.observed_at),
        "targets": [],
        "relationships_omitted": False,
    }

    srvs = sorted(
        snap.fresh_targets,
        key=lambda r: (r.observed_at, r.key),
        reverse=True,
    )
    for srv in srvs:
        if len(result["targets"]) >= MAX_RECONCILED_TARGETS:
            result["relationships_omitted"] = True
            break
        if not isinstance(srv.value, DNSSDSRV):
            continue
        name = srv.value.target.text
        if not _safe_name(name):
            result["relationships_omitted"] = True
            continue
        service_record = {
            "target": name,
            "port": srv.value.port,
            "ttl": srv.record.wire.ttl,
            "observed_at": str(srv.observed_at),
            "origin": (
                "same-mdns-response" if srv.source is ptr.source
                else "cross-mdns-response"
            ),
            "addresses": [],
        }
        eligible = [
            r for r in snap.fresh_addresses
            if _name_key(r.record.wire.name) == _name_key(srv.value.target)
        ]
        eligible.sort(key=lambda r: (r.observed_at, r.key), reverse=True)
        for address in eligible:
            if len(service_record["addresses"]) >= MAX_RECONCILED_ADDRESSES:
                result["relationships_omitted"] = True
                break
            value = address.value
            if not isinstance(value, str):
                continue
            try:
                parsed = ip_address(value)
            except ValueError:
                continue
            normalized = {
                "address": str(parsed),
                "family": parsed.version,
                "ttl": address.record.wire.ttl,
                "observed_at": str(address.observed_at),
                "origin": (
                    "same-mdns-response" if address.source is ptr.source
                    else "cross-mdns-response"
                ),
            }
            service_record["addresses"].append(normalized)
        if not (
            service_record["origin"] == "cross-mdns-response"
            or any(a["origin"] == "cross-mdns-response"
                   for a in service_record["addresses"])
        ):
            # Same-response claims already appear in the Phase 1N-I view.
            continue

        proposed = [*result["targets"], service_record]
        if len(json.dumps({**result, "targets": proposed},
                          ensure_ascii=True)) > MAX_RECONCILED_EVENT_SIZE:
            result["relationships_omitted"] = True
            continue
        result["targets"].append(service_record)

    if not result["targets"]:
        return None
    if len(json.dumps(result, ensure_ascii=True)) > MAX_RECONCILED_EVENT_SIZE:
        # A boolean truncation indicator must not break the pipe boundary.
        return None
    return result
