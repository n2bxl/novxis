"""Conservative terminal summaries for aggregated, TTL-aware DNS-SD facts."""

from novxis.state.mdns_services import MDNSServiceInstanceSnapshot
from novxis.protocols.dnssd import DNSSDSRV


def _remaining(expires_at, as_of) -> str:
    remaining = max(0, expires_at - as_of)
    return f"{remaining}s"


def format_mdns_service_snapshot(snapshot: MDNSServiceInstanceSnapshot) -> str:
    """Format claimed services; never print 'online' or guessed app ownership."""
    s = snapshot
    ptr_fresh = "fresh-advertisement" if s.has_fresh_ptr else "no-fresh-ptr"
    lines = [
        f"service={s.service_type.text} instance={s.instance.text}",
        f"  interface={s.interface} observations={s.observation_count}"
        f" status={ptr_fresh} last_seen={s.last_seen}",
    ]
    if not s.has_fresh_ptr:
        lines.append("  no-current-service-claim (historical observations retained)")
        return "\n".join(lines)

    if not s.fresh_targets:
        lines.append("  target=not-freshly-observed")
    else:
        if s.has_conflicting_fresh_srv:
            lines.append("  conflicting-SRV-targets=observed (not resolved)")
        for target in s.fresh_targets:
            assert isinstance(target.value, DNSSDSRV)
            srv = target.value
            lines.append(
                f"  target={srv.target.text}:{srv.port}"
                f" srv_ttl_remaining={_remaining(target.expires_at, s.as_of)}"
            )
            ips = [
                record for record in s.fresh_addresses
                if tuple(part.lower() for part in record.record.wire.name.labels)
                == tuple(part.lower() for part in srv.target.labels)
            ]
            for record in ips:
                lines.append(
                    f"    address={record.value}"
                    f" ttl_remaining={_remaining(record.expires_at, s.as_of)}"
                )
            if not ips:
                lines.append("    addresses=not-freshly-observed")
    txt_count = sum(1 for r in s.fresh_records if r.kind == "TXT")
    lines.append(f"  fresh_txt_records={txt_count}")
    return "\n".join(lines)
