# Phase 1D-B: UI-Neutral DNS Relationship View

**Date:** 2026-10-13  
**Status:** Feature branch, Mac regression and live/replay acceptance pending

## Architecture decision

**Do not make the terminal the presentation API.** We have separated:

```text
Capture Provider (live or replay)
          ↓  CapturedFrame
DNSStatePipeline
          ↓  DNSRelationshipState (raw source evidence)
novxis.views.dns_relationships.project_dns_relationships()
          ↓  immutable DNSRelationshipSnapshot
      ┌───┴──────────────┐
      ↓                  ↓
Plain console renderer  Future graphical / cyberspace renderer
```

A future interactive interface consumes typed immutable snapshot objects,
**not console text, stdout, Scapy packets, or a shared mutable DNS state**.
No graphical dependency, ANSI escape code, curses widget, terminal-width
assumption, timer, thread, or implicit wall clock enters the view model.

`DNSRelationshipView` includes:
- `owner`, `record_type` and semantic `relationship_kind`
  (`ipv4`, `ipv6`, `alias`, `reverse_name`) plus `target`;
- record-specific `ttl_seconds`, `observed_at`, `expires_at`,
  `remaining_seconds`, `freshness`;
- `interface`, `requester_ipv4`, `resolver_ipv4`,
  and `transaction_id` for explainable, scoped provenance.

`DNSRelationshipSnapshot` contains `as_of`, `mode`,
`relationships`, `fresh_count`, and `expired_count`.
Both are frozen/slots dataclasses; all fields are primitive values or
immutable tuples. A GUI can adapt these directly to edge/node models or
serialize them via a dedicated transport adapter later. Decimal timestamps
remain exact in the domain-facing view; no premature JSON format decisions.

### Semantics

- `mode="latest"` selects the last retained observation for each scoped
  record identity **at or before** the explicit `as_of` timestamp.
- `mode="history"` retains each historical observation still in the bounded
  evidence buffer, up to `as_of`; repeated names are not accidentally merged.
- Freshness is evaluated per individual record's received TTL and timestamp,
  never from a shared domain-level TTL.
- `remaining_seconds` is nonnegative and zero on/after expiration.
- Exact boundary (TTL=0 or `as_of >= expires_at`) is expired.
- Requested time before an observation hides that future observation.
- Sorting is deterministic; the projection never mutates the evidence.
- Because `DNSRelationshipState` has bounded history, asking for arbitrary
  old timestamps does not guarantee complete past-state reconstruction.
- An expired record is **still historically observed**, not a disappeared host.
- DNS aliases, IPv4/IPv6 addresses, and reverse names are semantic
  associations, not physical topology links or router hops.

## Terminal adapter

`novxis.presentation.dns_relationship_console` is the **only** place
where labels, arrows, numeric formatting, and human-readable layout appear.
It accepts a `DNSRelationshipSnapshot` and returns/prints text. Its output
is a read-only aggregated view, not a wire format or data API.

The dedicated CLI `novxis.cli.dns_relationships` uses existing
`DNSStatePipeline` and the same passive capture/replay providers. Existing
`dns_events` and `dns_replay` remain unaffected.

Live, with an actual currently active capture interface:

```bash
sudo .venv/bin/python -m novxis.cli.dns_relationships live en0 --count 40 --timeout 60
```

Replay a **private, locally stored** classic DNS PCAP:

```bash
python -m novxis.cli.dns_relationships replay /path/to/capture.pcapng
```

Add `--history` to either subcommand to show separate retained observations.
The `--as-of` option accepts an explicit Unix timestamp (Decimal seconds)
for repeatable replay, e.g. `--as-of 1791943200.125`.

Without `--as-of`, the view uses the maximum **captured frame timestamp**,
not your computer's present time. This allows replay to be deterministic and
does not suggest that a days-old PCAP still describes today's DNS answers.
If no frames and no explicit `--as-of` exist, no freshness view is generated.

The CLI prints an aggregated relationship snapshot after the capture/replay
completes and a summary of frames processed, DNS observations, correlated
exchanges, individual resource records, unmatched pending requests and
decode errors. It intentionally does **not** generate per-packet windows,
one new node per CNAME, or active DNS probes.

## Acceptance tests

```bash
python -m pytest tests/integration/test_dns_state_evidence.py tests/cli/test_dns_relationships_cli.py -q
python -m pytest
```

Focus covers:
- Four-record CNAME→A chain with distinct TTLs
- Per-record fresh/expired states, zero TTL and exact expiration
- A multi-answer RRset without forced single host ownership
- Historical vs latest views and replay's earlier `as_of` time
- No future observation leakage, immutability and semantic relationship types
- Display as downstream terminal-only formatting
- Live/replay CLI aggregation, explicit replay timestamps and zero-frame input
- Validation of invalid capture/clock parameters

**No automated local test pass is claimed until validated on macOS Python 3.14.6.**
Current merged baseline is **296 passed** from Phase 1D-A.

## Next graphical integration

An interactive UI can use `project_dns_relationships(state, as_of=...)`
to retrieve frame-independent relationships. Its rendering adapter can
map `relationship_kind` to visual node/edge styles and `freshness`
to color or opacity without modifying capture or protocol interpretation.
Animation/interpolation, rendering cadence and Q/E menu navigation belong
in the future UI layer, not the protocol or state layer.

No DNS answer should be promoted to a physical device without independent
network evidence. Future follow-up options: snapshot delta model for
animations, frontend transport serialization, evidence grouping and
nonblocking state update distribution.
