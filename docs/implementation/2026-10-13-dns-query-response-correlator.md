# Phase 1C: Conservative DNS Query/Response Correlation

**Date:** 2026-10-13  
**Status:** Feature branch implementation; local tests and live acceptance pending

## Scope and motivation

Phase 1B confirmed 236 regression tests and successful passive observation of
real DNS requests/replies on the developer's `en5` interface. The October 11
live captures included simultaneous A and TYPE65 (HTTPS) questions for the
same hostname on distinct client ports and transaction IDs; CNAME chains,
short and varied TTLs, and PTR negative answers were also observed.

The new `DNSCorrelator` consumes already-normalized
`DNSMessageObserved` values and emits `DNSExchangeCorrelated` **only** for
unambiguous request/reply observations. Raw observations are always preserved.
No network traffic or host-identity inference is introduced.

## Exact matching contract

The correlation key, expressed in request direction, contains:

1. Captured interface label
2. Request source and destination IPv4 addresses (reversed from reply)
3. Request source and destination UDP ports (reversed from reply)
4. 16-bit DNS transaction ID
5. DNS opcode (standard QUERY opcode 0 only)
6. All DNS questions in original order: QNAME labels, QTYPE, QCLASS

QNAME labels are ASCII case-folded **for matching only**. Original wire-case
and bytes remain intact in the observations. For a response to match, it must
have an identical nonempty question tuple and arrive no earlier than the
request and within the configurable time window (default 10 seconds).

Requests must target UDP destination port 53, and responses must originate
from UDP source port 53. TCP DNS, mDNS, and DNS-over-HTTPS/TLS are not handled.

## Conservative treatment of ambiguity and timing

- **No matching request:** a response is preserved as a standalone observation
  but no synthetic exchange is created.
- **Concurrent identical requests:** if the full key is repeated while the
  first request is pending, the pair is ambiguous. The key is quarantined
  until the latest matching request's configured window expires; a response
  in that interval cannot be attributed confidently to either request.
- **Unrelated queries for the same hostname:** distinct QTYPE, QCLASS,
  transaction ID, interface, IP, or port remain separate candidates.
- **Late response / out-of-order timestamps:** no completion if outside
  the response window or earlier than the request. A monotonic timestamp
  watermark prevents resurrection of stale requests during PCAP replay.
- **Memory bounds:** the pending request list is capped (default 1,024);
  oldest unmatched candidates are evicted if full. The ambiguity quarantine
  has age-based expiry; see follow-up note for future bounded-cache hardening.
- **Negative DNS answer:** an RCODE 3 / NXDOMAIN reply can still form a
  correlated exchange. This conveys an observed DNS result, not absence
  of a device or service.
- **Future work:** repeated responses, recycled identifiers after successful
  matches, non-monotonic replay timestamps, and duplicate-response hardening
  warrant additional experimentation before treating pairings as durable
  associations.

No answer authentication, DNSSEC, trust, cache freshness, CNAME following,
name→address mapping, or device ownership inference occurs in this phase.

## Console use

Live capture on the actual network interface:

```bash
sudo .venv/bin/python -m novxis.cli.dns_events en5 --count 20 --timeout 60 --correlate
```

Replay a local capture without requiring live-network permission:

```bash
python -m novxis.cli.dns_replay /path/to/capture.pcapng --correlate
```

In both commands, `--correlate` is optional and additive. Every individual
`DNSMessageObserved` still prints, with a separate
`DNSExchangeCorrelated` line when and only when the criteria match.
Duration is an **observed inter-packet interval**, not necessarily DNS server
processing time or a validated round-trip measurement.

Example based on synthetic documentation-safe records:

```text
DNSMessageObserved ... query ... id=0x1234 ... q=example.test/A/class1
DNSMessageObserved ... response ... id=0x1234 ... q=example.test/A/class1
DNSExchangeCorrelated ... id=0x1234 q=example.test/TYPE1/class1 ... duration=5.000ms evidence=observed-only
```

`--count` applies to captured BPF-matching frames, not correlated exchanges.
The command remains passive and sends no DNS queries.

## Tests and local acceptance

```bash
python -m pytest tests/events/test_dns_correlator.py tests/cli/test_dns_correlation_cli.py -q
python -m pytest
```

Synthetic test scenarios include:
- Positive request/response correlation and exact Decimal interval
- Same-hostname A vs HTTPS/TYPE65 concurrent queries
- NXDOMAIN response pairing
- Interface, reversed IP/UDP endpoints, ID, opcode, QNAME, QTYPE/QCLASS
- Case-insensitive DNS label match without altering original wire evidence
- Expired, premature, out-of-order, duplicate and unsolicited responses
- Bounded pending request capacity and invalid configuration
- Live/replay CLI opt-in vs default observation-only compatibility

The last independently reported Phase 1B local regression baseline:
**236/236 passing**. There is **no claim that Phase 1C tests have run**
until the developer executes these commands locally.

## Later NOVXIS work

- Phase 1D: independent timestamped DNS name/address evidence, per-RR TTL
  freshness and conflict handling; no physical device inference from DNS alone
- Differentiate decoded CNAME logical links from observed communication paths
- Surface ambiguity and raw BPF-match counts in user-facing telemetry
- Separate interpretation of HTTPS/SVCB record type 65 and mDNS/DNS-SD
