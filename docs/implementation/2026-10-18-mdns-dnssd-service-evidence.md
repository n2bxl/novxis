# Phase 1M-C: Native DNS-SD Service Type and Per-Response Evidence

**Date:** 2026-10-18  
**Status:** Both private PCAPNG captures have passed opt-in service projection with zero decode errors. Focused/full automated tests not shown in the provided acceptance log; PR not merged.  
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

**Automated test acceptance is still pending confirmation.** The submitted
MacBook output includes successful private capture replay, but **does not
include the focused or full pytest results** for this Phase 1M-C branch.
Do not claim those tests passed or merge on replay evidence alone.

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

## Private PCAPNG service-projection validation — 2026-10-18

The user's M5 MacBook Air ran the new `--services` projection against
both existing private Spotify captures.

| Metric | Capture 1 | Capture 2 |
| --- | ---: | ---: |
| Frames replayed | 2,766 | 1,188 |
| mDNS message observations | 115 | 215 |
| IPv4 mDNS messages | 50 | 119 |
| IPv6 mDNS messages | 65 | 96 |
| DNS-SD service PTR advertisement observations | **30** | **87** |
| Decode errors | **0** | **0** |

Across these runs, NOVXIS produced **117 service PTR observations** with
zero decode errors. This is the count of *advertisement observations*,
not distinct services, endpoints, hosts or verified running software.

The second capture's full per-advertisement console lines show:

| Raw DNS-SD type | Advertisements | Distinct instance names in this capture |
| --- | ---: | ---: |
| `_spotify-connect._tcp.local` | 71 | 2 |
| `_apple-mobdev2._tcp.local` | 8 | 1 |
| `_companion-link._tcp.local` | 4 | 1 |
| `_googlecast._tcp.local` | 3 | 2 |
| `_googlerpc._tcp.local` | 1 | 1 |
| **Total** | **87** | **7** |

The first capture was run with `--summary-only`, so its individual
service-type/instance distribution is **not** inferred from its output.

Important evidence examples from the second capture:

- Two different Spotify Connect instance names were observed repeatedly,
  with SRV-advertised target ports 4070 and 45528 and per-response matching
  address claims. Multi-address IPv4/IPv6 advertisements must not be
  promoted to distinct physical devices.
- The same service type appeared repeatedly over time and IP families;
  the 71 Spotify Connect observations represent only **two observed
  instance names** in this capture.
- Four Companion Link PTR advertisements had **no matching SRV target
  in their individual responses**. These remained explicitly incomplete.
- Two Apple mobile-device service PTR records carried **TTL=0** and
  were marked `goodbye-candidate`, not `offline`. These PTR-only
  goodbye observations also lacked same-message target claims.
- SRV record TTLs and service PTR TTLs may differ; preserve each record's
  independent freshness rather than inheriting the longer PTR lifetime
  for a host/port relationship.

The original addresses, private local hostnames, instance UUIDs, raw TXT
content and entire capture traces stay outside the public repository.
These test observations support *typed per-response evidence extraction*,
not process attribution, runtime reachability, or physical-device mapping.

**Next acceptance still needed:** focused Phase 1M-C pytest tests and
the complete regression suite on the feature branch. An additional
live `--services` capture can provide evidence of the optional console
path, but offline replay already validates its real-packet output.

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
