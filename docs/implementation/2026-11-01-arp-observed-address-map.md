# Phase 1N-A: Renderer-Neutral Observed ARP Address Map

Date: 2026-11-01
Status: Feature branch, local acceptance pending.
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

## Acceptance still needed

1. Verify the focused tests and full suite (do not count 478 as new result).
2. Replay the sanitized fixture with and without --map.
3. Review a private PCAP optionally. Never commit real device identifiers,
   private PCAPs, or sensitive capture data to the public repository.

## Follow-on

Read-only local interface/prefix/route evidence should establish the host's
reported capture boundary. Add separate typed DHCP, mDNS and DNS evidence
relationships next, without inferring physical topology from protocol hints.
