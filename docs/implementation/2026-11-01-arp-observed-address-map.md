# Phase 1N-A: Renderer-Neutral Observed ARP Address Map

Date: 2026-11-01
Status: M5 focused/full test and public sanitized replay acceptance passed; ready for PR review.
Baseline: 478 tests passed on the previously merged Phase 1M-D-B milestone.

## Purpose

NOVXIS needs a stable, UI-independent way to draw actual observed facts.
This first slice uses only latest ARP sender bindings to create a graph
of address claims, not presumed physical hosts or cables.

Flow:

    PCAP -> ARP events -> NetworkState.arp_bindings
                                    |
                          project_arp_address_map
                                    |
                         ARPAddressMapSnapshot
                           /                 \
                     console --map      future graphics

## Evidence boundary

- Each address node retains interface, hardware type, protocol type, raw
  address bytes, and deterministic ID.
- Each directed protocol-address -> hardware-address association is
  explicitly labeled as an ARP sender claim.
- Claims retain first-seen, last-seen and observation-count metadata.
- The same address on different observed interfaces is kept separate.
- Multiple IPs sharing one hardware-address node are just matching
  address bytes within the same ARP scope, not verified device identity.
- ARP target fields never become address claims.
- No active status, physical links, subnet grouping, identity matching,
  invented expiration timer, or arbitrary history reconstruction is done.
- The optional CLI view does not alter the existing default replay output.

## Commands to test on the development Mac

    python -m pytest tests/views/test_arp_address_map.py tests/cli/test_arp_address_map_cli.py -q
    python -m pytest

    python -m novxis.cli.arp_state_replay tests/fixtures/arp_phase0_sanitized.pcap --interface-label fixture --map

The public sanitized fixture should yield 8 frames and 6 retained ARP sender
bindings/claims. No zero sender protocol address is mapped. Exact number
of distinct hardware nodes depends on observed values.

## Actual acceptance on the M5 development Mac (2026-11-02)

- macOS Darwin, Python 3.14.6, pytest 9.1.1.
- **9/9 focused tests passed in 0.10s.**
- **487/487 full regression tests passed in 0.43s.** The previous
  accepted baseline was 478; this slice added nine tests.
- Sanitized replay with `--map`: **8 frames; 6 ARP sender bindings;
  12 address nodes; 6 sender claims**. Six unique IP addresses and
  six unique MAC addresses account for these twelve address nodes;
  none are asserted to be twelve physical devices.
- The repeated sender `192.0.2.70` reported two observations;
  the `0.0.0.0` sender did not become a binding.
- The fixture timestamps start 100 seconds after the Unix epoch,
  which explains the 1969-12-31 local-time presentation and is not
  an incorrect live-clock interpretation.
- Default output absence of the map was verified by an automated CLI
  test. A separate manual replay without `--map` was not reported.
- Private/live-capture validation was not performed for this sprint;
  it is optional and must not leak source addresses or PCAP data.


## Follow-on: first usable 2D evidence map

Build a minimal 2D view of the frozen graph, using offline/replay data
first. It should render **observed address claims**, not physical topology,
with pan/zoom, selection, and an evidence inspector. A deterministic layout
and explicit edge types are required; no graph relationships should be
manufactured from spatial proximity.

The next evidence increment should add read-only host interface/prefix/route
observations so NOVXIS can show the capture host's *reported* network context.
Then add separately typed ICMP observed exchanges, DNS naming, DHCP ACK
configuration, and mDNS service advertisement relationships. Individual
protocol scope and freshness rules must survive each projection.

A shared renderer-neutral semantic graph should feed 2D first and a later
3D scene; no 3D-only identity or layout assumptions belong in the core.

