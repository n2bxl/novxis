# Phase 1M-D-A: Bounded mDNS/DNS-SD Service Evidence State

**Date:** 2026-10-18  
**Status:** Feature branch prepared for macOS validation; not merged.
**Baseline:** Phase 1M-C squash-merged as `c590908`; user's local
post-merge full suite **422/422 passed in 0.44s** on Python 3.14.6.

## Goal

Turn repeated *native DNS-SD service evidence* into a small,
deterministic and renderer-independent observation state. The network's
own vocabulary remains visible: `_spotify-connect._tcp.local`, not an
inferred vendor/software identity.

The private second Spotify capture previously had **87** PTR-backed
advertisement observations representing **seven distinct service
instance names across five native service types**. Phase 1M-D-A
should be capable of projecting a similar small set of observed instance
views without discarding the 87 individual source observations.

## Architecture

```text
PCAP/PCAPNG → MDNSEventPipeline → MDNSMessageObserved
                                ↓
              project_dnssd_advertisements()  [Phase 1M-C]
                                ↓
           MDNSServiceEvidenceState.observe(source, advertisement)
                                ↓
                  Bounded history, record-latest maps
                                ↓
             snapshots(as_of=explicit capture timestamp)
                                ↓
             format_mdns_service_snapshot()
                                ↓
                novxis-mdns-state-replay
```

The new state is **separate from classic DNS correlation/cache evidence**.
It ingests already-bounded Phase 1M-C PTR-backed service projections.
The state uses a case-insensitive **DNS label-byte key** consisting of:

```text
(capture interface, DNS-SD service type, service instance name)
```

This intentionally unifies repeated IPv4/IPv6 observations of an instance
on the same capture interface, but does not merge identities between
interfaces or infer a single physical device from matching names.

Each service instance preserves:

- Native service type and instance names from the first observation.
- First/last observed capture timestamps and advertisement-observation
  count, including repeated advertisements.
- Bounded original packet history retaining source interface, network
  sender, IPv4/IPv6 and raw packet provenance.
- Latest evidence for independent *semantic RR values* (PTR target,
  SRV target/port/priority/weight, TXT bytes, and A/AAAA address).
  Different DNS compression encodings do **not** create different
  logical SRV/PTR record variants.
- Per-RR `observed_at`, original TTL, `expires_at`, fresh/not-fresh
  as-of a supplied **capture-time** timestamp, and original mDNS
  class/cache-flush/goodbye flags.
- Multiple distinct fresh SRV targets are retained and flagged as
  `conflicting-SRV-targets=observed`, **not resolved by guessing**.

The public immutable snapshot includes `has_fresh_ptr`,
`fresh_targets`, `fresh_addresses` and the original record evidence.

## Independent TTL treatment

If a PTR was advertised with TTL 4500 but the corresponding SRV had
TTL 120, **the target claim is not treated as fresh for 4500 seconds**.
A/AAAA and TXT similarly keep their own time-to-live.

When a TTL=0 PTR is received for the same semantic record key, the
latest PTR becomes a **goodbye candidate** and is not fresh. No
record is labeled `device-offline`; other associated records remain
separate timestamped evidence and may have distinct expiration times.

This is not a faithful simulation of Bonjour's complete mDNS cache:
cache-flush does **not** destructively remove other conflicting
record variants, and goodbyes are not authenticated. Contradictory
observations remain visible as contradictions.

## Time and boundedness

- `max_instances=256`; discard oldest last-observed instance when cap
  exceeded (including its latest-record map).
- `max_records_per_instance=128`; discard the oldest latest-record
  variant as needed. For very low custom caps, PTR evidence itself can
  be evicted; snapshots then conservatively show `no-fresh-ptr`.
- `max_history=4096`; bounded FIFO of original PTR-backed
  advertisement observations. Repeated observations update the same
  logical record rather than growing its latest-record map indefinitely.
- Explicit snapshot timestamp must be a finite Decimal that is **not
  before the latest ingested event**, since latest-only state cannot
  reconstruct arbitrary earlier snapshots.
- Out-of-order older evidence is retained in bounded history but cannot
  replace a newer latest record of the same semantic key.
- A snapshot that has no currently fresh PTR is **not** a proof that
  a device is offline. Expired observations remain viewable within
  the state bounds.

## Exact scope of supported cross-message aggregation

A fresh PTR, SRV, TXT, A or AAAA fact can remain available in later
snapshots and be refreshed by a later *PTR-backed response*. This
first slice does **not** import an isolated SRV, TXT or A/AAAA response
if that packet has no matching service-type PTR. Implementing safe
cross-message assembly of independent records is a separate follow-on
with explicit provenance and collision-handling rules.

The `--after` flag evaluates a snapshot at a chosen number of seconds
after the **last frame timestamp in the capture**, not after the user's
current wall-clock time. This prevents historic captures from being
wrongly labeled universally expired.

## Run on the MacBook

```bash
python -m pytest tests/state/test_mdns_service_state.py \
  tests/cli/test_mdns_state_replay_cli.py -q
python -m pytest
```

**Tests not yet run on this feature branch.** Baseline 422/422 refers
to previously merged `main`.

Then replay the two existing private Spotify captures **locally**:

```bash
python -m novxis.cli.mdns_state_replay \
  "$HOME/Documents/spotify 2.pcapng"

python -m novxis.cli.mdns_state_replay \
  "$HOME/Documents/spotify.pcapng"
```

Try explicit TTL aging on the second capture without generating network
traffic:

```bash
python -m novxis.cli.mdns_state_replay \
  "$HOME/Documents/spotify 2.pcapng" --after 200

python -m novxis.cli.mdns_state_replay \
  "$HOME/Documents/spotify 2.pcapng" --after 5000
```

The output is a bounded console snapshot of native service types,
instances, advertisement observation counts, status
(`fresh-advertisement` or `no-fresh-ptr`), claimed target/port
and fresh matching addresses where they can be supported.

## Interpretation and acceptance

The second private capture's earlier service-only output included:
five distinct raw service types, seven distinct service-instance
names, 87 advertisement observations, two TTL=0 goodbye candidate
observations. The new command should retain approximately that
relationship structure, but exact counts must be **reported from
this new command** before marking this phase accepted. Boundedness,
capture timestamps and repeated same-interface advertisements can
affect the precise number of retained service-instance views.

The new CLI does **not** perform DNS-SD multicast queries or check
open ports. Physical devices, vendors, software identity and media
playback are **not** inferred. Full network topology still needs
multiple independent passive and eventually opt-in active sources.

## Design parking lot: lexical affinity

An optional future view may show `google*` as a substring/prefix
similarity between `_googlecast._tcp.local` and
`_googlerpc._tcp.local`. This must remain **presentation-only**:
no effect on canonical state keys, TTL freshness, host relationships,
device identity, or confidence in protocol evidence.

## Later 1M-D work

- Import and reconcile standalone SRV/TXT/A/AAAA responses without
  PTR in the same message, with provenance and bounded retention.
- Carefully consider known mDNS cache-flush update/grace semantics,
  conflict handling and subtype PTRs (RFC 6762/6763).
- Expose source/provenance detail in a renderer-independent grouping
  API and optionally integrate passive live capture with snapshots.
- Keep network-native service names as first-class labels.

References: [Phase 1M-C](2026-10-18-mdns-dnssd-service-evidence.md),
[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html),
[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html).
