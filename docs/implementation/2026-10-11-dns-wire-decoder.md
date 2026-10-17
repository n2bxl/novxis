# DNS Phase 1A: Wire Decoder

**Date:** 2026-10-11  
**Status:** Implemented, validated and merged via [PR #20](https://github.com/n2bxl/novxis/pull/20) (`8977efd`).

## Intent

Extend the existing Ethernet -> IPv4 -> UDP foundation with a pure, bounded
DNS wire parser before adding transport dispatch, correlation, and network
state. This mirrors the staged DHCPv4 implementation and keeps packet evidence
separate from interpretations about hosts.

This is an intentionally **passive decoder**. It sends no DNS requests, probes,
or scans.

## Supported wire evidence

- DNS header: 16-bit ID and flags, query/response, opcode, TC bit, base
  4-bit RCODE, and all four section counts
- Questions: raw label bytes, QTYPE, QCLASS
- Resource records: NAME, TYPE, CLASS, TTL, RDLENGTH, raw RDATA and its
  message-relative offset
- All four sections: questions, answers, authorities, additionals
- Compression pointers, including backward references to earlier compressed
  names, with backward-only offset validation and loop protection
- Decoded presentation values for IN A, AAAA, CNAME, PTR, and NS records
- Unknown types/classes (including OPT) retained as opaque raw RDATA
- Additional bytes after the declared DNS sections preserved as
  `DNSMessage.trailing_bytes`

Names remain byte-preserving tuples of labels; `.text` is an escaped
presentation, not a normalized DNS identity key. DNS comparisons are ordinarily
case-insensitive, but raw evidence must not be destroyed by normalization.

## Security and evidence boundaries

The parser rejects truncated headers, labels, fields, RDATA, invalid reserved
label encodings, pointers into the header, non-backward pointers, names longer
than 255 expanded octets, and malformed known IN record lengths.

Compression offsets are **relative to the start of the DNS message**, not the
Ethernet or UDP packet. Names decoded from compressed RDATA must consume exactly
the declared RDLENGTH on the original wire path. References may point backward
elsewhere in the DNS message; those referenced bytes are not counted as part of
RDATA's wire length.

The parser intentionally does **not**:

- determine which endpoint owns a name or address;
- assert that an A/AAAA/PTR record proves a host is currently present;
- cache names, enforce TTL freshness, validate DNSSEC, or validate provenance;
- correlate queries and responses;
- decode EDNS extended RCODE or EDNS option payloads;
- accept TCP length-prefixed DNS messages;
- reassemble fragmented IPv4 packets or DNS-over-TCP streams;
- parse mDNS or DNS-SD semantics (separate future discovery slice).

A truncated (TC=1) flag is reported, but a message whose declared record
sections are not fully present is rejected as structurally incomplete. This is
appropriate for a pure parser; truncated/partial message handling policy can
be evaluated when the event pipeline is added.

**Do not feed every UDP payload into this parser.** The next pipeline must
explicitly gate classic DNS using UDP source or destination port 53 and reuse
the existing UDP evidence pipeline's unfragmented-only policy. Port 5353 is
reserved for a separate mDNS interpretation path.

## Proposed follow-on slices

1. **Phase 1B: Observation path:** UDP port-53 gating, `DNSMessageObserved`
   with the original capture/Ethernet/IPv4/UDP objects, replay and optional
   finite live capture console views, and synthetic Ethernet integration tests.
2. **Phase 1C: Correlation:** Conservative query-response matching scoped to
   interface, endpoint addresses/ports, DNS transaction ID, and question
   identity. Retries, unsolicited responses, multiple responses, and
   mismatched queries stay visible instead of being forced into a pair.
3. **Phase 1D: Network-state evidence:** Timestamped, source-tagged name/address
   assertions from appropriate responses with TTL and freshness policy.
   Preserve multi-address, alias, reverse-record, stale, and conflicting
   evidence separately; do not merge physical hosts just because names match.
4. **Later:** Local mDNS (UDP 5353), DNS-SD services, IPv6 scope,
   DNS-over-TCP support, and selected active investigation through the
   separately authorized discovery controller.

## Developer checks

After checking out the feature branch and installing editable dependencies:

```bash
python -m pytest tests/protocols/test_dns.py -q
python -m pytest
```

Synthetic tests exercise header parsing, packet counts/sections, compressed
question/record names, A/AAAA/CNAME/NS/PTR presentation, unknown record
preservation, trailing bytes, and truncated or hostile compression input.

**Validation status (2026-10-11, local M5 MacBook Air):**

- Environment: macOS (Darwin), Python 3.14.6, pytest 9.1.1, pluggy 1.6.0.
- Focused command: `python -m pytest tests/protocols/test_dns.py -q` — **24 passed in 0.02s**.
- Full command: `python -m pytest` — **211 passed in 0.41s** (211 collected).
- No failures reported by the local test run.

The Phase 1A acceptance above covered synthetic parser tests. Later phases
added live capture and independent application-level checks. PR #20 was
squash-merged; see [DNS milestone closeout](2026-10-17-classic-dns-milestone-closeout.md).

## References

- RFC 1035, especially §4.1.1–4.1.4:
  https://www.rfc-editor.org/rfc/rfc1035
- RFC 9267, compression offset-validation pitfalls:
  https://www.rfc-editor.org/rfc/rfc9267
