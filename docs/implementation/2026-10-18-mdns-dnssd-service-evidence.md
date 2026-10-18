# Phase 1M-C: Native DNS-SD Service Type and Per-Response Evidence

**Date:** 2026-10-18  
**Status:** Feature branch ready for local Python 3.14.6 test acceptance;
not yet merged or validated on private captures.  
**Scope:** Interpret DNS-SD PTR → SRV/TXT → A/AAAA evidence **within each
observed mDNS response**. No application fingerprint database, automatic
name translation, or network inventory heuristics.

> The network's own language is the interface. Keep the observed service
> type in its native form, such as `_spotify-connect._tcp.local`.

## Starting point

- Phase 1M-A merged via PR #27 (mDNS QU/QM, known-answer distinction,
  cache-flush and goodbye *candidate* semantics).
- Phase 1M-B merged via PR #28 (passive IPv4 and IPv6 UDP/5353 live capture
  and PCAP replay, including real Apple/Spotify lab observations). Earlier
  user acceptance: **390/390 full regression tests**, dual-interface live
  capture **40/40 observations with zero errors on each**, and private
  replay of **115 + 215** mDNS packets with zero errors.

## Why native labels matter

The native DNS-SD service type is already meaningful evidence.
Maintaining a lookup table from `_spotify-connect._tcp.local` to a
friendly product name is optional **presentation work**, not a
requirement for discovery state, and is intentionally absent here.

Keep these concepts separate:

1. A **query** seeks service instances; the source is an observer or seeker,
   *not* necessarily a provider.
2. A response **PTR** with a service-type owner and matching instance name
   is an *advertisement claim*. Its sender is retained, but the sender
   may advertise on behalf of another target.
3. A matching **SRV** for the instance names an advertised target host,
   priority, weight and port; it does not prove that port is open.
4. Matching **TXT** strings describe service metadata; each string is a
   length-prefixed, byte-preserving field. Never guess character encodings.
5. Matching **A/AAAA** associates a name with an address observed **in the
   same response**. This is a claim, not proof of durable device identity.

## Implementation architecture

```text
MDNSMessageObserved (Ethernet, IP, UDP, raw mDNS message)
            ↓
novxis.protocols.dnssd
  parse_dnssd_srv(message_bytes, wire_rr)
  parse_dnssd_txt(wire_rr)
            ↓
novxis.views.mdns_services.project_dnssd_advertisements(observed)
            ↓
DNSSDServiceAdvertisement (immutable)
  service_type ← PTR owner (native DNSName)
  instance     ← PTR target (native DNSName)
  ptr_record   ← original observed MDNSRecord
  targets[]    ← SRV target + port + same-response A/AAAA records
  txt_records[]← original TXT record + byte-preserving strings
            ↓
novxis.presentation.mdns_service_console
            ↓
Opt-in `--services` replay / live terminal presentation
```

The existing `DNSResourceRecord` keeps the original class, RDATA,
RDATA offset and per-record TTL. A bounded
`read_dns_name_rdata(message, start=..., end=...)` safely handles
**message-relative compression** in SRV and PTR names using the same
limits as the existing DNS parser. The original DNS parser still treats
SRV/TXT as opaque unless the DNS-SD-specific interpretation is requested.

The projection joins records by DNS label arrays (ASCII-insensitive
comparison) and uses **original spelling for display**. An instance name
may contain an escaped period within its first label; splitting the
rendered text on `.` would misinterpret that boundary, so joining never
does that.

### Strict evidence boundaries

- **Responses only:** query Answer Section entries are *known-answer
  hints*. They are never advertised services.
- **Service-type PTRs only:** `_name._tcp.local` or
  `_name._udp.local` with a PTR target formed as
  `<one instance label>.<service type>`. Unrelated reverse PTR
  records, `_services._dns-sd._udp.local` enumeration and subtype-specific
  browsing are not promoted to instance advertisements in this slice.
- **Same-message only:** no inter-packet joins, cache updates, TTL
  freshness state, device fusion or guessed response-to-query pairing.
  Partial PTR-only advertisements remain visible as *partial evidence*.
- **Independent provenance and TTL:** each PTR, SRV, TXT and A/AAAA record
  keeps its original `MDNSRecord`, section, class, cache-flush semantics,
  timestamp (via enclosing `MDNSMessageObserved`), and TTL.
- **No inferred endpoint:** a response's source IP is displayed as
  `sender`; only a matching SRV target and A/AAAA records can supply
  a claimed service endpoint.
- **Malformed typed RDATA:** reject incomplete compressed SRV targets or
  length-prefixed TXT strings and report a decoder error in service mode,
  never fabricate a valid endpoint.
- **No TXT fingerprinting:** the display shows a TXT record count,
  not private contents by default. Unknown key/value bytes remain
  recoverable in the typed records.
- **No active traffic:** `--services` is a passive output filter,
  not a discovery query.

## Run focused and complete tests on Mac

```bash
python -m pytest tests/protocols/test_dnssd.py \
  tests/views/test_mdns_services.py \
  tests/cli/test_dnssd_cli.py -q

python -m pytest
```

Tests cover compressed and uncompressed SRV target names, invalid pointer
boundaries, bytes/empty TXT values, malformed lengths, service-instance
label escaping, partial PTR evidence, unrelated PTR rejection, known
answers not treated as advertisements, exact target/address matching,
TTL=0 goodbye candidates, immutable projections and opt-in live/replay
CLI controls.

**Acceptance is pending.** No test pass or successful private-PCAP
projection is claimed until the user's MacBook checks the branch.

## Private lab capture experiments (after tests pass)

From the local NOVXIS checkout, with existing private capture files
outside the public repository:

```bash
python -m novxis.cli.mdns_replay \
  "/path/to/spotify 2.pcapng" --services

python -m novxis.cli.mdns_replay \
  "/path/to/spotify.pcapng" --services --summary-only

sudo .venv/bin/python -m novxis.cli.mdns_events en5 \
  --services --count 40 --timeout 60
```

The default mDNS console still displays packet-level observations.
The opt-in `--services` view instead emits only the native DNS-SD PTR
advertisement facts and related same-message records. `--summary-only`
suppresses individual lines but counts projected advertisements.

Expect multiple observations of the *same service* across IPv4/IPv6
and time. This slice does not aggregate those into unique discovered
devices or service instances. Compare the output against the captured
PTR/SRV/TXT/A/AAAA records in Wireshark rather than assuming one
network packet equals one unique service.

## Next slice (1M-D)

Only after confirming the per-message facts should we implement
**bounded, historical service evidence**, per-record TTL freshness,
cross-message assembly, conflict handling and a renderer-independent
subnet/service graph. This is where distinct observations may combine
with ARP/DHCP/DNS evidence, preserving uncertainty about physical hosts.

## References

- [RFC 6763 — DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc6763.html)
- [RFC 6762 — Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762.html)
- [Phase 1M-A](2026-10-18-mdns-message-semantics.md)
- [Phase 1M-B](2026-10-18-mdns-dual-stack-observation.md)
