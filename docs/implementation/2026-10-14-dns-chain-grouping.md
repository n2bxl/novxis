# DNS Phase 1D-C — Grouped Naming Relationships

**Date:** 2026-10-14  
**Status:** Validated and merged via [PR #25](https://github.com/n2bxl/novxis/pull/25) (`6d21823`). Merged `main`: 335/335 passing (2026-10-17).

## Purpose

Phase 1D-B separated immutable `DNSRelationshipSnapshot` view data from
terminal formatting. Phase 1D-C builds **read-only grouping on those snapshots**,
not on console output, packet bytes or mutable network state.

```text
CapturedFrame → DNSStatePipeline → DNSRelationshipState
                   ↓
             project_dns_relationships()
                   ↓
       DNSRelationshipSnapshot (unchanged)
                   ↓
              group_dns_relationships()
                   ↓
        DNSGroupedSnapshot (immutable)
                ↙              ↘
       grouped terminal       future graph UI
```

Grouping is an optional **view projection**: no DNS decoder, correlator,
state model, capture provider, or existing flat renderer was modified.

## Core contract

- `DNSGroupedSnapshot` contains explicit `as_of`, view mode, groups and
  conserved fresh/expired relationship counts.
- `DNSRelationshipGroup` holds `kind`, interface, requester/resolver IPs,
  root names, participating name nodes, original `DNSRelationshipView` records,
  alias-cycle flag and whether at least one A/AAAA answer was observed.
- All group and snapshot objects are frozen, immutable dataclasses. DNS packet
  timestamps and per-record TTLs remain unchanged.
- Every input relationship appears **exactly once** across output groups.
  Grouping neither invents nor deletes DNS records.
- Records are only joined within the same captured interface, querying
  client IPv4 address and responding resolver IPv4 address.
- CNAME name → name links form the directed alias relation; connected
  components group shared targets and chains. A/AAAA values are address
  records attached to the owner name, **never** graph vertices that link
  unrelated hostnames by a shared IP.
- PTR relationships are separated into reverse-name groups and never
  treated as forward CNAME edges.
- Groups may have **multiple roots** when independent aliases point at
  the same target. The shared target's A/AAAA answer is not duplicated.
- A missing intermediate CNAME or A record is not synthesized.
- Contradictory, stale, and historical CNAME relationships are presented as
  *observed evidence*, not reconciled into one authoritative/current RRset.
- Alias cycles are flagged with an iterative, bounded graph algorithm rather
  than followed indefinitely. Root names may be absent in a fully cyclic
  component.
- Sorting follows alias chains when possible and is deterministic, but is
  merely a presentation ordering hint, **not** hop count or evidence of a
  path taken by an IP packet.

### Why group scope matters

A name may resolve differently for distinct clients or resolvers, or at
different times. Mixing these records into one asserted live resolution would
be misleading. Phase 1D-C preserves the client/resolver/interface scope.
Within one scope, older and expired observations may coexist with newer data;
no consistency or authoritative-resolution guarantee is implied.

## CLI

The existing flat view remains the default. Use optional `--group` for
human-readable name groups:

```bash
sudo .venv/bin/python -m novxis.cli.dns_relationships live en0 --group --count 40 --timeout 60
```

For a private local capture:

```bash
python -m novxis.cli.dns_relationships replay /path/to/private.pcapng --group
```

`--group --history` is supported and retains each repeated record
observation. `--as-of UNIX_SECONDS` retains Phase 1D-B's explicit-time
freshness semantics. The command is passive and does not issue queries.
Use the correct currently active capture interface, which may differ
between sessions.

The terminal prints a header per group plus **every** supported record
with per-record TTL, remaining lifetime, observed time, transaction ID and
freshness. The structured group objects themselves contain none of that
terminal-specific text.

## Tests and acceptance

```bash
python -m pytest tests/views/test_dns_groups.py tests/cli/test_dns_relationships_cli.py -q
python -m pytest
```

Test categories:
- CNAME→CNAME→A/AAAA chains with distinct record TTLs
- Multi-address answers and shared targets with multiple roots
- Scope isolation between interfaces, requesters and resolvers
- PTR separate from forward name alias graphs
- Cyclic/self-referential and contradictory CNAME evidence
- Incomplete chains without synthetic address records
- Retained history and original case preservation
- Deterministic results, conservation of every input record, empty captures
- Optional live/replay `--group` while default CLI remains flat

### Local acceptance (2026-10-14)

On macOS/Darwin, Python **3.14.6**, pytest **9.1.1**:

- Focused `test_dns_groups.py` + `test_dns_relationships_cli.py`: **27/27 passed in 0.24s**.
- Complete regression suite: **335/335 passed in 0.29s**.
- No regression failures reported.

### Live passive grouped capture

Command:

```bash
sudo .venv/bin/python -m novxis.cli.dns_relationships live en0 --group --count 40 --timeout 60
```

| Metric | Observed |
|---|---:|
| Captured frames | 40 |
| Decoded DNS messages | 40 |
| Correlated exchanges | 18 |
| Supported answer-record observations | 59 |
| Latest distinct scoped relationships | 45 |
| Naming groups | 7 |
| Fresh latest relationships | 43 |
| Expired latest relationships | 2 |
| Pending requests at capture cutoff | 1 |
| Decode errors | 0 |

The difference between 59 record observations and 45 latest distinct
relations is consistent with repeated observations of identical scoped
record keys. The outstanding request at the finite 40-frame cutoff cannot
by itself be interpreted as a DNS failure; not all other non-paired
observations need have been correlated.

Important real-world grouping cases (anonymized):

1. Two separate service aliases each had CNAME chains converging on one
   shared service target. NOVXIS displayed a **single 14-record forward
   group with two roots**, preserving both independent naming chains and
   two A answers at the shared target.
2. One CDN returned a three-relationship chain where the long-lived
   initial CNAME remained fresh while an intermediate CNAME and terminal
   A record had expired by the snapshot timestamp (**1 fresh, 2 expired**).
   The grouping retained all three records without declaring the CDN
   unreachable.
3. A plain A lookup produced two distinct address records in one group.
   Its client-side `dig` transaction ID matched the NOVXIS hex ID
   exactly after decimal-to-hex conversion. The two A values agreed.
4. An independently executed `nslookup` showed the same logical
   CNAME→CNAME→A chain that NOVXIS grouped for the CDN. This comparison
   validates name-chain grouping, not an IP packet path or authoritative
   resolver-cache state.

The capture supports grouped projection, source provenance, TTL aging,
and terminal rendering on real observed DNS data. Individual response
authenticity, physical device identity, and networking routes remain
outside scope.

**Privacy:** Public notes intentionally omit organization-specific
hostnames, browsing/service hostnames, private client IPs, resolver
address, and raw capture logs. Do not commit raw private PCAP files.

**Acceptance:** Focused tests, full suite and live grouped capture passed.
PR #25 was squash-merged. Merged-`main` tests passed **335/335** on 2026-10-17.
See [milestone closeout](2026-10-17-classic-dns-milestone-closeout.md).

## Later visualization

The eventual cyberspace renderer can arrange the semantic `nodes` and
the original `relationships` into a spatial graph. Rendering style,
layout, navigation, animation, highlighting and Q/E interaction remain
outside the grouping/data modules. Future graph identity/delta modeling
should be designed explicitly; group boundaries can change when additional
CNAME evidence is observed, so a group is not a stable physical device ID.
