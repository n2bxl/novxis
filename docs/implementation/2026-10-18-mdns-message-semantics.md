# mDNS Phase 1M-A — Capture-Neutral Message Semantics

**Date:** 2026-10-18  
**Status:** Implemented, tested and squash-merged via [PR #27](https://github.com/n2bxl/novxis/pull/27) (`cc48f4a`); post-merge `main` tests passed 353/353 (2026-10-18).  
**Scope:** Passive **wire-message interpretation only**; no capture provider,
IPv6 parser, service inventory, GUI, active multicast queries, or state.

## Why this is the first mDNS slice

Classic DNS Phase 1A–1D-C already established a bounded DNS wire parser,
conservative evidence architecture and renderer-independent relationship
snapshots. mDNS speaks a DNS-derived wire format, but uses different
class-field and message-section semantics. Reusing the classic DNS
correlator or treating every Answer Section record as an authoritative
advertisement would manufacture relationships.

This first slice prevents that problem before building service discovery.

### Architecture

```text
Complete DNS-format UDP/5353 payload  (caller supplies transport provenance)
      ↓
parse_dns(..., interpret_mdns_class_bit=True)
      ↓
immutable DNSMessage with original class fields and RDATA
      ↓
parse_mdns() contextual interpretation
      ↓
MDNSMessage + MDNSQuestion + MDNSRecord
      ↓
future normalized observation / DNS-SD service projection / UI adapter
```

The original `parse_dns(bytes)` default path is unchanged, including its
strict classic-DNS `IN=1` record-class behavior. mDNS mode alone masks the
high RRCLASS bit *for interpretation*, never for stored wire evidence.

## Exact message-level behavior

- `MDNSQuestion.question_class = qclass & 0x7fff`. Question high bit
  indicates a **QU** (unicast-response requested) query; otherwise **QM**.
  Preserve `DNSQuestion.qclass` unchanged.
- `MDNSRecord.record_class = rclass & 0x7fff`, while
  `MDNSRecord.wire.rclass` retains every original bit.
- An RR high class bit is interpreted as **cache-flush only in responses**.
  It is not mistaken for the question QU bit or silently applied to
  query packets.
- Query **Answer Section** records are **known-answer hints**. They are
  evidence of the querier's claimed prior knowledge, *not* responder
  advertisements and should not populate authoritative relationship state.
- Query Authority Section records remain **query authority evidence**
  (often used in probing); we do not assert the name has been successfully
  claimed.
- In responses, Answer/Authority/Additional sections remain distinct.
  A record's TTL=0 is a **goodbye candidate**, not proof that recipients
  immediately forgot the record or that the sender is authenticated.
- A response with no questions is **not automatically called unsolicited**:
  an mDNS response to an earlier query may have no Question Section.
- Raw content, timestamps (in future observation wrappers), type/class,
  per-RR TTL, unknown types, name spelling and section position survive.

No mDNS cache/coherency engine is created by this slice. Cache-flush and
goodbye are **observed wire signals**, not already-applied state changes.

## Implementation

- `novxis.protocols.dns.parse_dns` gains keyword-only optional
  `interpret_mdns_class_bit=False`. Existing classic DNS callers need no
  change.
- `novxis.protocols.mdns` defines frozen dataclasses:
  `MDNSQuestion`, `MDNSRecord`, `MDNSMessage`, and a pure
  `parse_mdns(data: bytes)` function.
- `parse_mdns` expects a complete DNS message payload isolated by a
  future UDP/5353 observation path; it does **not** validate IP family,
  multicast address, hop limit, UDP ports, or original capture source.

## Tests

```bash
python -m pytest tests/protocols/test_mdns.py tests/protocols/test_dns.py -q
python -m pytest
```

Synthetic tests cover QU/QM, question QCLASS IN/ANY, responder
cache-flush, query known-answer suppression hints, query Authority
evidence, response section separation, zero-TTL goodbye candidates,
address/PTR decoding with high RRCLASS bit, classic DNS regression
behavior, unknown types, raw SRV/TXT preservation, and hostile or
incomplete messages.

### Local acceptance — 2026-10-18

On M5 MacBook Air, macOS (Darwin), Python **3.14.6**,
pytest **9.1.1** and pluggy **1.6.0**:

- Focused tests: `tests/protocols/test_mdns.py` and
  `tests/protocols/test_dns.py`: **42/42 passed in 0.04s**.
- Full regression suite: **353/353 passed in 0.44s**.
- Previous merged-`main` baseline: **335/335**. This adds
  **18 tests** with no observed regressions.
- Only capture-neutral synthetic parsing semantics have been validated;
  the new mDNS path has **not** yet been exercised with live or replayed
  traffic, which belongs to Phase 1M-B.

**Acceptance conclusion:** Focused and full automated tests passed.
PR #27 was squash-merged. Subsequent local `main` testing reported
**353/353 passed in 0.36s**. Live observation/replay and DNS-SD service
semantics remain separate follow-on slices.

## Next slices (deliberately separate)

**Phase 1M-B: mDNS observation transport.** Add a read-only UDP/5353 path
with normalized `CapturedFrame` provenance, PCAP/PCAPNG replay and finite
live console capture. Support IPv4 and IPv6; the existing
`UDPEventPipeline` is IPv4-only, so don't route IPv6 data through it or
quietly ignore more than half of an otherwise visible mDNS environment.
The future IPv6 parser must bound payload lengths, safely reject or
explicitly handle extension/fragment headers, and preserve observed
hop limit/destination. Consider both multicast and unicast mDNS responses;
flag anomalies rather than fabricating successful link-local discovery.

**Phase 1M-C: DNS-SD record typing.** Add safe message-relative compressed
name decoding for SRV targets and length-prefixed byte-preserving TXT
strings. Interpret PTR service type → instance, SRV instance → target
host:port, TXT service metadata and A/AAAA target address evidence.
Preserve unknown and malformed records without guessing. A/B multicast
class flags and section semantics from this phase remain available.

**Phase 1M-D: semantic local-service grouping.** Per-record TTL freshness,
bounded historical source evidence, and UI-neutral groups preserving
ambiguous instances, shared targets and multiple IP addresses, without
asserting active reachability or physical topology. Make a grouped
terminal view first; graphical rendering is a separate phase.

### Real-capture acceptance

Two privately held `spotify.pcapng` samples were captured during a
Spotify relaunch experiment. They contain both IPv4 and IPv6 mDNS,
known-answer query sections, QU questions, and DNS-SD PTR/SRV/TXT traffic.
Use them *locally*, alongside synthetic byte fixtures, when the actual
transport/replay path is in place. Do **not** add raw PCAP files,
organization/account-specific service labels, MACs, or browsing history to
this public repository. Synthetic `example.test` / `.local` fixtures
belong in the test suite.

## Standards

- [RFC 6762 — Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762.html),
  including QU questions (§5.4), known-answer suppression (§7.1),
  probing (§8) and cache-flush (§10.2).
- [RFC 6763 — DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc6763.html),
  including PTR browsing, SRV target/port and TXT metadata.
- [Classic DNS closeout](2026-10-17-classic-dns-milestone-closeout.md).
