# Phase 1M-D-B — Optional Cross-Message DNS-SD Evidence Reconstruction

**Date:** 2026-10-18  
**Status:** Feature branch submitted for user MacBook validation. Neither focused/full tests nor real PCAPNG replay have yet been run against this new branch.  
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

In the existing private second capture, previously accepted baseline
counts were **87 PTR observations → seven service instances**. The
new reconciling mode must not manufacture additional PTR instances;
whether it finds extra independently advertised SRV/TXT/A/AAAA
relationships remains subject to real replay evidence.

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
