# Phase 1N-F: Evidence-backed IPv4 Subnet Lens

Date: 2026-11-02
Status: Draft implementation PR; M5 regression and Safari acceptance pending.
Baseline: Phase 1N-E merged (#37) and 560/560 tests validated on M5.

## Goal

Build a conservative subnet-oriented presentation of current ARP sender
address evidence, using the host OS's configured IPv4 prefixes as a
second, independent source. This is not an active scanner, a physical
topology engine, a reachability map, or a complete host inventory.

## Evidence contract

The existing evidence sources remain separate:
- Host configuration: local macOS reports interface IPv4 addresses,
  configured prefixes, and a point-in-time default route with its
  actual interface. Collected only by the unprivileged web process.
- ARP observations: bounded, authorized live capture yields interface
  scoped sender IP/MAC claims, without verifying host identity or liveness.

The renderer-neutral project_subnet_evidence function accepts an immutable
ARP address map and a host-context snapshot. It produces an additive
subnet_evidence JSON field in live mode only.

The projection requires local-os provenance, schema version 1 and the
exact capture interface scope. Each host prefix must be internally
consistent: normalized IPv4 interface address + prefix length +
corresponding canonical network, verified with Python ipaddress. Invalid
configuration is rejected instead of leading to an inferred prefix.

Only ARP IPv4 protocol nodes with four-byte addresses, protocol type
0x0800 and matching capture interface are considered. For each valid
host-configured prefix, NOVXIS lists observed ARP sender addresses
numerically contained within it. Multiple overlapping prefixes are
permitted, so a single observed sender can appear under more than
one configured prefix, but counts of unique ARP IPv4 addresses are
not duplicated.

Observed IPv4 senders outside every reported prefix are reported
separately as an address containment result, **not remote hosts**.
If the OS reports no valid prefix, observed senders remain unclassified.
Neither situation is proof of physical LAN boundaries.

A gateway cross-reference is emitted only if the selected OS IPv4
default route uses the capture interface AND an observed ARP sender
protocol address matches the route's gateway IP. The comparison adds
no ARP claim, verified gateway identity, inferred physical cable or
route-hop edge. Mismatched route interface disables the cross-reference.

## Local 2D browser

A Subnet evidence lens panel appears beneath Host IPv4 context,
grouping observed IP addresses into collapsible configured prefixes.
Each address button selects the original scoped ARP graph node
and existing claim(s); the Evidence Inspector can display the separate
OS gateway-address cross-reference. The UI caps each expanded address
list to 64 visible entries to remain bounded and uses textContent
rather than inserting untrusted HTML.

The prefix lens does not alter the existing graph nodes or claims,
node layout, inspector provenance, live capture privileges or network
settings. It requires no additional HTTP endpoints or active probes.
The panel is hidden in sanitized offline replay.

## M5 validation instructions

    git fetch origin
    git switch --track origin/ai/phase1n-subnet-evidence-lens-2026-11-02
    python -m pytest tests/views/test_subnet_evidence.py tests/web -q
    python -m pytest

Run an authorized bounded live capture:

    sudo .venv/bin/python -m novxis.cli.arp_live_stream en0 --count 2000 --timeout 120 \
      | .venv/bin/python -m novxis.cli.web_live

Open http://127.0.0.1:8765/ in Safari. Check that:
- Host IPv4 context remains separately labeled with OS provenance.
- The Subnet evidence lens shows the configured CIDR from macOS and
  observed same-interface ARP sender IP addresses falling inside it.
- Prefix counts refer to observed addresses, not subnet size or devices.
- Expanding groups and clicking addresses selects existing ARP evidence.
- A matching gateway address produces a separate OS route comparison,
  but only if the OS route interface matches the capture interface.
- Other configured prefixes can overlap; unmatched observed addresses
  are described as outside reported prefixes, not remote.
- Pan, zoom, selection, manual arrange and live polling still work.
- Offline replay (python -m novxis.cli.web_preview) keeps the sanitized
  fixture's 12 address nodes, 6 ARP sender claims and 8 frames, while
  both local OS context and subnet lens are hidden.

Avoid committing local live IP/MACs, screenshots or full OS outputs to
public GitHub documentation. Tests use documentation-only IP ranges.

## Initial M5 live Safari observation (2026-11-02)

The developer supplied a screenshot of a live, localhost, `en0`
capture with the new **Subnet evidence lens** displayed beneath
Host IPv4 context. The snapshot shows:

- An expanded OS-configured IPv4 **/22** prefix group.
- **11** distinct observed, interface-scoped IPv4 ARP sender addresses,
  all **11** numerically contained in the reported prefix.
- **Zero** observed IPv4 sender addresses outside reported prefixes.
- A separate OS default-route gateway address cross-reference, with
  the observed gateway address also represented in the existing ARP
  graph and its protocol node visibly selected.
- The distinct host-context provenance and ARP evidence visualization
  remain on the screen together.
- The developer reported no unusual UI behavior during this initial
  visual check.

This validates the principal **live rendering and grouping** path,
but does **not** independently establish every gesture, expanded-group
persistence through future live updates, or the offline isolation
check. No Python test results for this feature branch have yet been
supplied; PR stays in draft until focused/full test results and any
remaining browser checks are reported.

Private local IP, gateway and MAC address values in the screenshot
are intentionally **not recorded** in this public repository note.

## Deferred

Multi-interface fusion, full route tables, gateway and L2 link
inference, multi-protocol host identities, TTL/liveness aging, active
inventory/scans, persisted subnet layouts, physics-based animation,
and 3D presentation. This first lens only compares numerical address
containment against validated OS-reported configuration.
