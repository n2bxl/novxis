# Phase 1D-A: Timestamped DNS Relationship Evidence

**Date:** 2026-10-13
**Status:** Validated and merged via [PR #23](https://github.com/n2bxl/novxis/pull/23) (`ed2b4cf`).

## Why this slice exists

Phase 1C demonstrated 274 passing tests and 9 real DNS query-response
correlations on the Mac, verified against independently generated dig output.
Phase 1D turns **individual resource records in conservatively correlated
positive answers** into typed, timestamped evidence.

The design is deliberately separate from NOVXIS's physical network topology:
a DNS CNAME is a logical naming relation, an A or AAAA address is a resolver's
observed assertion, and a PTR answer is reverse-naming evidence. None proves
host ownership, actual connection to an IP, or that a device is alive.

## Data flow

```text
CapturedFrame
    ↓
DNSEventPipeline → DNSMessageObserved
    ↓
DNSCorrelator → DNSExchangeCorrelated (only unambiguous pairs)
    ↓
DNSRelationshipState.observe_exchange()
    ↓
DNSRecordEvidence (one per supported answer RR)
    ↓
bounded history / latest-per-scoped-RR / explicit-time freshness view
```

`DNSStatePipeline` composes these layers into one opt-in programmatic path
without changing Phase 1B's raw observation consoles or Phase 1C's optional
`--correlate` mode. `NetworkState` exposes `dns_relationships` as a
separate state namespace; ARP/DHCP records do not inherit DNS identities.

## What creates a relationship

Only the **answer section** of a **matched, non-truncated, NOERROR**,
standard-opcode DNS response creates positive relationship evidence.
Eligible RR types are:

| DNS type | Meaning | What is actually stored |
|---|---|---|
| A (1) | name → IPv4 | The decoded address reported by the resolver |
| AAAA (28) | name → IPv6 | The decoded IPv6 address reported by the resolver |
| CNAME (5) | alias → name | The naming relationship, **not** a network hop |
| PTR (12) | reverse name → target name | Reverse-DNS assertion, not device reachability |

Unknown/opaque records, unsupported DNS classes, authority and additional
records are left in the source `DNSMessageObserved` but create no
`DNSRecordEvidence`. We are not yet interpreting HTTPS RR type 65.

NXDOMAIN, SERVFAIL, NODATA (NOERROR without relevant answers) and truncated
responses **do not** create positive A/CNAME/PTR/etc relationships.
They remain available at the query-response evidence layer. A missing PTR
does not establish that the device does not exist.

## Per-record TTL and freshness

Every evidence record holds its own received TTL, response-capture timestamp,
and `expires_at = observed_at + Decimal(TTL)`. The caller supplies
`as_of` explicitly to `fresh_records(as_of)`; there is no implicit wall
clock or background expiration process.

TTL=0 still creates a historical record, but it never qualifies as fresh.
At the exact expiration timestamp, the record is no longer fresh. This
models **freshness of an observation**, not guaranteed residency in any
DNS cache. Recursive resolvers can return already-reduced TTLs. A TTL
expiration never implies that the address/device/service went offline.

Example using synthetic values patterned on the previously observed CNAME
chain:

| Answer RR | Observed TTL | Relative expiry |
|---|---:|---:|
| first CNAME | 130s | T + 130s |
| second CNAME | 1208s | T + 1208s |
| third CNAME | 38s | T + 38s |
| final A record | 8s | T + 8s |

At T+9s, the A record has expired while all three CNAMEs may still qualify
as fresh. Do not treat that as proof the destination IP changed.

## Provenance, identity and bounded memory

Every `DNSRecordEvidence` points back to its original resource record and
`DNSExchangeCorrelated` source. Latest-record keys are scoped by:

- observed interface;
- requester and replying resolver IPv4 addresses;
- normalized (ASCII-lowercase) owner labels, RR type, RR class;
- normalized decoded RR value (IP or alias).

The original DNSName and decoded original text remain untouched.

Multiple IP answers to the same hostname are stored independently. Distinct
resolvers, clients, interfaces, and record types do not collapse into one
"device." A newer observation of the exact same scoped record updates its
latest snapshot, but older versions remain accessible via bounded history.

Memory is bounded (default 2,048 latest records, 4,096 history entries).
An older replay observation cannot overwrite a newer latest record; it is
still retained in the history until the history cap evicts it. On eviction,
the model simply has less local evidence; it does not declare any record
incorrect or expired.

**Important:** This is not an authoritative DNS cache, resolver state, or
full historical database. Its "fresh" view is based on previously observed
individual RRs, not proof those RRs remain current on the DNS server.
The current layer does not synchronize RRsets, validate DNSSEC, observe
encrypted DNS, or persist across restarts.

## Run Phase 1D-A tests

```bash
python -m pytest tests/integration/test_dns_state_evidence.py -q
python -m pytest
```

Test cases include full Ethernet/IPv4/UDP/DNS synthetic packets, a four-link
CNAME/A chain with varying TTLs, A and AAAA answers, PTR, multi-A responses,
exact TTL boundary, TTL=0, NXDOMAIN/SERVFAIL/truncation rejection,
opaque/unsupported records, missing exchanges, repeated observations,
out-of-order replay, scoping by interface/resolver/client, provenance,
memory limits, and invalid configuration.

### Local acceptance (2026-10-13)

- **22/22** focused DNS state/evidence integration tests passed in **0.04s**.
- **296/296** full regression tests passed in **0.28s**.
- Platform: macOS/Darwin, Python **3.14.6**, pytest **9.1.1**.
- Previous Phase 1C baseline: 274 passing; **22 new tests, no failures**.

This is automated validation of synthetic network evidence. The Phase 1D-A
state layer is not yet exposed through a live relationship presentation
console, so no live DNS state display is claimed or required for this PR.
PR #23 was squash-merged. Later merged-`main` tests passed 335/335 on 2026-10-17.

## Follow-up outcome

Phase 1D-B implemented the optional relationship console and immutable view
snapshots; 1D-C added scoped name-chain grouping. They preserve the boundary
between historical observation, TTL-relative freshness and reachability.
See [milestone closeout](2026-10-17-classic-dns-milestone-closeout.md).
