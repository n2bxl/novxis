# Phase 1M-D-B — Optional Cross-Message DNS-SD Evidence Reconstruction

**Date:** 2026-10-18  
**Status:** Focused/full macOS tests, initial second-capture reconciliation, and +200-second TTL-aging replay all passed with zero decode errors. Independent Wireshark verification of one linked record is still pending; PR not merged.  
**Baseline:** Phase 1M-D-A merged to `main` as `71c7320`, after which the user's macOS/Python 3.14.6 environment passed **458/458** tests in 0.40s.

## Purpose

A valid DNS-SD service may advertise PTR, SRV, TXT, A, and AAAA records
in *different packets*. Phase 1M-D-A conservatively aggregates repeated
PTR-backed, same-response projections and keeps per-RR TTL evidence, but
does not assemble those independent responses. Phase 1M-D-B offers a
separate, **opt-in** reconstruction view.

**The network's own language remains the identifier.** Service-type
and instance labels are never renamed by application dictionaries,
vendor guesses, or string-similarity scoring.

## Model

```text
capture → MDNSEventPipeline → MDNSMessageObserved
                                  |
                   +--------------+--------------+
                   |                             |
             PTR-backed mDNS response      PTR-less mDNS response
                   |                             |
        Existing Phase 1M-D-A state       bounded typed orphan pool
                   |                             |
                   +-------- snapshot(as_of) ----+
                                  |
                  explicit, evidence-limited join:
                    same capture interface
                    same DNS label bytes (ASCII-case-insensitive)
                    fresh service-type PTR
                    SRV/TXT owner = service instance
                    A/AAAA owner = fresh SRV target
                    each record must respect its own TTL
                                  |
                MDNSReconciledServiceSnapshot
                     original source + joined facts
```

- `MDNSServiceReconciliation` **wraps** the already validated
  `MDNSServiceEvidenceState`; it does not alter the trusted baseline
  behavior, observation counts, canonical service instance keys,
  raw `DNSName` bytes, or existing CLI defaults.
- `--reconcile` enables the overlay for
  `python -m novxis.cli.mdns_state_replay`. Without the switch, the
  previously accepted replay behavior remains unchanged.
- The independent RR buffer is bounded by `--max-unassociated`
  (default 2048), separate from max service instances, latest records
  and Phase 1M-D-A history.
- Orphan **SRV** and **TXT** RRs join only when their owner is the
  exact observed service instance name on the same capture interface.
- Orphan **A/AAAA** joins only when its owner matches the target
  DNSName of a **fresh, matched SRV** on that interface. Sharing the
  source IP, subnet, software-looking prefix, or host-name fragment
  is insufficient.
- **Before or after PTR:** the orphan can have been observed before
  the PTR response, if its original record TTL is still fresh at the
  explicit snapshot timestamp. No historical clocks are fabricated.
- Multiple matching SRV targets, including conflicts, remain separate
  facts; the system does not choose a winner. Similarly, a target
  DNSName may be referenced by more than one service and any matching
  address claim is evidence associated with each *claim*, not proof
  that the services share a physical device.
- Repeated semantic RR values use latest-observed evidence; the original
  raw records and packet timestamps stay available. Distinct RR values
  remain independently observable.
- A newer **TTL=0** standalone record can supersede an older matching
  value as a non-fresh goodbye candidate, but never becomes positive
  or trusted evidence of offline device state.
- Query-side known answers, query authority/probe RRs, unmatched
  service names and unrelated interface observations never create
  cross-packet service evidence.
- All age checks use **capture timestamps**, not system wall-clock.

### Explicit omissions

This slice only buffers **response messages with no projected service
type PTR**. It does not harvest arbitrary extra SRV/TXT/A/AAAA data
from responses that happen to contain *another* valid service PTR;
handling those mixed packets would require a broader per-record
extraction layer.

It also does not model Bonjour's full cache-flush grace period, service
subtypes, negative responses, authenticated ownership, host
reachability, or physical device identity. TCP connection or media
playback state is not inferred.

## CLI usage

With the feature branch checked out:

```bash
python -m pytest tests/state/test_mdns_reconciliation.py \
  tests/cli/test_mdns_reconciliation_cli.py -q
python -m pytest

# New behavior, explicitly enabled:
python -m novxis.cli.mdns_state_replay \
  "$HOME/Documents/spotify 2.pcapng" --reconcile

# Compare with previously validated baseline:
python -m novxis.cli.mdns_state_replay \
  "$HOME/Documents/spotify 2.pcapng"

# Time-based evaluation on the replay clock:
python -m novxis.cli.mdns_state_replay \
  "$HOME/Documents/spotify 2.pcapng" --reconcile --after 200
```

The result retains the familiar service-state display, plus
`separately-observed-RRs-linked=N` beneath each instance when
`--reconcile` is enabled, and the bounded count of orphan response
records held. `N` is the number of **fresh, separately observed**
semantic RR values contributing to this snapshot, not the number of
network devices, application processes, or packet connections.

## MacBook acceptance results — 2026-10-18

The user checked out the Phase 1M-D-B feature branch on the M5 MacBook
Air with macOS, Python **3.14.6**, pytest **9.1.1**, pluggy **1.6.0**.

- **20/20 focused tests passed in 0.08s**.
- **478/478 full regression tests passed in 0.36s** — up from
  the Phase 1M-D-A merged baseline **458/458**.
- The second private Spotify PCAPNG was replayed both with and without
  `--reconcile` (same capture-time snapshot).

| Captured metric | Baseline | `--reconcile` |
| --- | ---: | ---: |
| Frames replayed | 1,188 | 1,188 |
| mDNS observations | 215 | 215 |
| DNS-SD PTR observations | **87** | **87** |
| Retained service instances | **7** | **7** |
| Fresh PTR instances | 6 | 6 |
| No-fresh-PTR instances | 1 | 1 |
| Decode errors | **0** | **0** |
| Standalone RR evidence buffered | n/a | **19** |
| Additional fresh RR associations | n/a | **4** |

The seven native service instances remain unchanged. Four separately
observed RRs contributed fresh matches, distributed across three
instances:

| Native service type | Additional evidence |
| --- | --- |
| `_companion-link._tcp.local` | 1 TXT RR |
| `_googlecast._tcp.local` | 1 newer A RR refresh |
| `_googlerpc._tcp.local` | 1 SRV and 1 A RR |

The Companion Link instance gained **TXT evidence** while remaining
without a fresh SRV target. The associated A record of one Google
Cast instance now has approximately **113.8s** of freshness at capture
end versus approximately **65.5s** in the baseline, due to a later
standalone A observation. The Google RPC instance gained an independently
observed SRV claim and matching address evidence.

These are **reconstruction results from the program output**, not
claims that the underlying services are reachable, owned by particular
software, or tied to verified physical devices. No raw private IPs,
hostnames, MAC addresses, TXT contents or instance identifiers were
committed.

The user's interactive zsh printed `command not found: #` when pasted
shell comment lines were interpreted as commands; actual replay
commands executed successfully. This is not a NOVXIS error.

### Capture-clock TTL-aging validation (+200 seconds)

The user subsequently replayed the second private capture with
`--reconcile --after 200`. These are **actual output values**:

| Metric | Reconciled at capture end | Reconciled at +200s |
| --- | ---: | ---: |
| Frames replayed | 1,188 | 1,188 |
| mDNS observations | 215 | 215 |
| DNS-SD PTR observations | **87** | **87** |
| Retained service instances | **7** | **7** |
| Fresh PTR instances | **6** | **2** |
| No-fresh-PTR instances | 1 | 5 |
| Orphan response RRs retained | **19** | **19** |
| Fresh extra RR associations | **4** | **1** |
| Decode errors | **0** | **0** |

At +200 seconds, only the companion-link service and one Spotify
Connect service still had fresh PTR claims. Exactly one additional
cross-message TXT association remained fresh for the companion-link
service, even though its SRV target was still not freshly observed.
The long-lived Spotify Connect PTR still outlived its SRV target
evidence and acquired **no** new cross-message RR in this run.

The other three extra associations from capture end were no longer
presented because the relevant service instances did not have fresh
PTRs. **This is a prerequisite/gating result:** it does *not*
independently prove that every underlying SRV/A record had itself
expired. Previously observed RRs remain historical evidence subject
to bounded retention, and no offline-device conclusion is made.

**Still pending:** Independent Wireshark inspection of at least one
previously standalone response RR. Verify that it is a response
record with exactly matching DNS labels on the correct capture
interface and confirm its original TTL. Do not claim the packet-level
verification has happened until the user reports it.

**Important:** Phase 1M-D-B remains opt-in; Phase 1M-D-A results and
default CLI output are unchanged.

## Acceptance plan

1. Focused tests and the complete pytest suite on the feature branch.
2. Repeat the private second-capture replay with default and
   `--reconcile` mode. Compare instance/PTR/decode counts and the
   cross-message evidence counts.
3. Repeat with `--after 200` to ensure expired records do not
   reappear as fresh.
4. Review at least one novel attached record, if any, against its
   independent original mDNS response in Wireshark before claiming
   a successful newly reconstructed relationship.

Only mark results actually observed; do not invent expected
cross-message findings.

References: [Phase 1M-D-A](2026-10-18-mdns-service-state-aggregation.md),
[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html),
[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html).
