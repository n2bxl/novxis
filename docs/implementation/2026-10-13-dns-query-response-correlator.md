# Phase 1C: Conservative DNS Query/Response Correlation

**Date:** 2026-10-13  
**Status:** Validated and merged via [PR #22](https://github.com/n2bxl/novxis/pull/22) (`e6cce03`).

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
- **Memory bounds:** the pending request list and ambiguity keys are capped
  (default 1,024 each). Oldest pending candidates are evicted if full.
  If ambiguity keys exceed capacity, the correlator clears pending state and
  conservatively suppresses all pairings for one full window rather than
  discarding an ambiguous key and potentially fabricating a match.
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

### Accepted locally on 2026-10-13

On macOS (Darwin), Python 3.14.6, pytest 9.1.1:

- Focused Phase 1C suite: **38 passed in 0.30s**.
- Complete regression suite: **274 passed in 0.27s**.
- Phase 1B baseline: 236 passed; 38 new tests and no regressions.

### Successful live capture on en0

```bash
sudo .venv/bin/python -m novxis.cli.dns_events en0 --count 20 --timeout 60 --correlate
```

- **20 DNSMessageObserved** observations, **0 decode errors**.
- **9 DNSExchangeCorrelated** pairs covering 18 observations.
- **2 pending requests** at capture termination: the frame-count limit was
  reached after two additional queries but before observing replies.
  This alone does **not** indicate a failed resolver or missing response.
- Correlator observed an A query with two answers and **30.092 ms** interval;
  the corresponding standalone `dig` output reported the matching
  transaction ID (hexadecimal/decimal), two A records and **30 ms**.
- Correlator observed a PTR reverse query with one answer and **13.375 ms**
  interval; standalone `dig -x` reported matching ID, PTR answer,
  and **14 ms** query time.
- Background traffic included parallel queries for the same name with
  QTYPE=65 (HTTPS/SVCB) and QTYPE=1 (A), different ports and transaction IDs;
  the correlator matched them separately. The type-65 exchange had RCODE=0
  and zero answer records, which is not NXDOMAIN.
- The original DNS observations still printed alongside the additional
  correlation summary lines as designed.

Application/service hostnames, the user's queried organization domain,
the private client IP, and exact resolver address are deliberately omitted
from this public acceptance document. Displayed IDs and timings are
sufficient to document the correlations without publishing browsing history.

**Caveat:** The captured interface for this run was `en0`, whereas an
earlier run used `en5`. Interface names must be checked per session.
The `--count 20` limit counts BPF-matching frames, not exchanges.

**Acceptance conclusion:** Automated tests and live DNS correlation pass.
This is correlation of observed packets, **not** DNS response
authentication, reachability testing, or a DNS cache. PR #22 was squash-merged; later merged-`main` tests passed 335/335 on 2026-10-17.

## Later NOVXIS work

- Phase 1D-A through 1D-C completed: per-record TTL evidence, immutable
  presentation-independent snapshots and scoped DNS chain grouping.
- Differentiate decoded CNAME logical links from observed communication paths
- Surface ambiguity and raw BPF-match counts in user-facing telemetry
- Separate interpretation of HTTPS/SVCB record type 65 and mDNS/DNS-SD
