# Phase 1N-K Stage 2: Interface-Scoped IPv6 Neighbor Evidence

Date: 2026-11-07
Status: Draft implementation; M5 focused/full pytest and local PCAP replay pending.
Baseline: PR #43 Stage 1 squash-merged to main (6cbc757); 711 passing M5 tests.

## Goal

Preserve independent, bounded IPv6 Neighbor Discovery evidence without
misrepresenting the 2D debugger as a discovered physical topology or
creating a kernel neighbor cache. NS and NA packets are decoded and
validated by the existing Stage 1 pipeline, then projected into typed
evidence observations with source-specific provenance.

Stage 3 will be a separate browser integration milestone; this stage
does not alter the 2D graph, DNS-SD service map, ARP model, or capture
privilege boundaries.

## Evidence model

Code: novxis/state/ndp.py and novxis/pipeline/ndp_state.py.

**NS with exactly one usable Ethernet SLLA:**

- Record an NS source-LLA claim keyed by capture interface, IPv6
  SOURCE address, option's Ethernet address, and kind ns_source_slla.
- Preserve original NS target *only* as packet context in the
  latest observation. Do not associate the queried target IPv6
  address with the SLLA or Ethernet frame sender.

**NA with exactly one usable Ethernet TLLA:**

- Record a target-LLA claim keyed by capture interface, IPv6
  TARGET address, option's Ethernet address, and kind na_target_tlla.
- Keep the NA sender and Router/Solicited/Override flags in original
  message provenance. No Override=1 claim overwrites another
  incompatible packet assertion or proves address ownership.

**Everything else remains unlinked evidence:**

- Source :: and valid solicited-node NS is a DAD/tentative address
  probe, not a sender-to-MAC binding.
- NS without SLLA, or NA without TLLA, has no option-backed MAC
  association. Do NOT borrow the Ethernet frame source MAC.
- Duplicate same-type link-layer options are ambiguous even when
  identical. Non-Ethernet-sized options remain opaque. Zero or
  multicast/group address options do not create individual unicast
  Ethernet address claims.
- A multicast NS source is not promoted into a source-address
  association. The original Stage 1 parser enforces ICMPv6
  wire-validity; Stage 2 conservatively interprets semantics.
- Distinct claims for the same scoped IPv6 address and different
  Ethernet addresses remain distinct; the snapshot counts
  multiple-link-layer **assertions**, not proven IP collisions.
- No time-to-live, reachability, SLAAC state or device identity is
  inferred. NS/NA contain no simple DNS-style TTL for address
  mappings. Instead the state preserves first/last captured times
  and per-claim observation counts.

The retention limits default to 256 distinct claims, 256 distinct
unlinked observations, and 512 raw typed packet observation-history
entries. Oldest retained items are evicted when an independent cap is
reached, and omitted counts/history truncation are exposed.
Records are immutable frozen dataclasses. Same-interface and
different-interface claims are never coalesced.

## New passive replay command

python -m novxis.cli.ndp_state_replay /path/to/capture.pcapng --summary-only

The command uses PcapReplayProvider and the new NDStatePipeline.
It reports aggregate NS, NA and DAD counts, number of retained
option-backed packet claims (NS source vs NA target), unlinked reason
counts, conflicting advertised LLAs, bounded evictions and decode
errors. The summary-only mode prints **no IPv6 or MAC addresses**;
removing the option shows limited local evidence records only.
Arguments include --count, --interface-label (fallback), --limit,
--max-claims, --max-unlinked and --max-history. The option caps are
validated and bounded. No active probing or OS network changes.

This command is separate from the existing
python -m novxis.cli.ndp_replay
Stage 1 packet-counting command.

## Reference material and capture observations

Stage 1 validation reviewed private, user-authorized PCAPNG captures
from Wi-Fi and Ethernet. Only 1 of 34 observed Neighbor Advertisements
included TLLA, while all 34 Neighbor Solicitations contained
one-unit SLLA options. This motivated explicit missing-TLLA evidence:
we must not invent a target-to-MAC mapping when an NA has no TLLA.

RFC 4861 (Neighbor Discovery): https://www.rfc-editor.org/rfc/rfc4861
RFC 4443 (ICMPv6): https://www.rfc-editor.org/rfc/rfc4443

Note: NS SLLA claims alone do not prove an advertised service's target
has the same Ethernet address. The IPv6 source address is the claimed
address. The link-layer option is untrusted on-wire metadata.

## M5 validation

~~~bash
git fetch origin
git switch --track origin/ai/phase1n-k-ndp-evidence-state-2026-11-07
python -m pytest tests/state/test_ndp_evidence_state.py \
  tests/cli/test_ndp_replay.py tests/pipeline/test_ndp_pipeline.py -q
python -m pytest
~~~

Then replay each authorized local PCAPNG without address output:

~~~bash
python -m novxis.cli.ndp_state_replay /path/to/wifi.pcapng --summary-only
python -m novxis.cli.ndp_state_replay /path/to/ethernet.pcapng --summary-only
~~~

Expected: Stage 1 NS/NA message counts remain unchanged,
option-backed claims and unlinked reasons reflect real packets.
Claim counts are **not** the same as packet counts: repeated
advertisements aggregate by interface/IP/LLA/kind. The captures
have different durations, so do not infer that one interface
carries more ND traffic in general. A MAC address may appear
in an on-wire claim but is not a verified host identity.

Privacy: Never publish raw private PCAPs, device hostnames, MACs,
IPv4/IPv6 addresses or source Ethernet captures to GitHub.
Synthetic tests use documentation IPv6 and invented Ethernet
addresses only.

## Deferred

Stage 3 2D read-only IPv6 address evidence, AAAA cross-reference,
any service/device identity fusion, live unprivileged NDP stream,
IPv6 routing/prefix interpretation (RA/RS), DAD lifecycle,
NDP cache semantics and reachability, IPv6 extension traversal
or active network querying.
