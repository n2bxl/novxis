# NOVXIS

**Network Observation, Visualization, eXploration Interface System**

NOVXIS is an open-source project for understanding networks through observed
packet evidence. It captures or replays traffic, decodes protocols, retains
bounded and provenance-aware observations, and makes those observations
inspectable in a local 2D debugger. It is designed for networking education,
exploration, and troubleshooting.

> **Evidence before interpretation.** An address claim is not a verified
> device, an ARP/NDP relationship is not a physical cable, and a service
> advertisement is not proof that a service is reachable.

## What works today

- **Passive capture and replay:** Ethernet/ARP, IPv4, ICMPv4, UDP, DHCPv4,
  classic DNS, mDNS/DNS-SD, IPv6 framing, and ICMPv6 Neighbor Discovery
  (NS/NA). Protocol coverage differs between standalone CLIs and the
  live browser view.
- **Local 2D evidence debugger:** live ARP IPv4-to-MAC sender claims, a
  separate IPv6 NDP evidence tab, DNS-SD service records with matching
  IPv4-to-ARP and IPv6-to-NDP inspection shortcuts, and camera/layout
  controls. The 2D debugger remains a permanent reference surface.
- **Separate host context:** locally reported macOS interface/prefix and
  selected IPv4 default-route context. This is **OS-reported** data,
  not passive packet evidence.
- **Known limitations:** a capture interface has incomplete visibility;
  a matching MAC or IP does not establish physical identity, topology,
  reachability, or the configured settings of other endpoints.
  Encrypted DNS/application traffic is not decrypted.

**Latest M5 acceptance (2026-11-07): 895 passing Python tests in 4.57s** following the Stage 3 layout refinement. Live Safari graph, MAC-first arrangement, and typed edge inspection were observed; PR #49 awaits owner squash-merge.
This is an observed test baseline, not a claim of an automated CI run
for every subsequent documentation change.

## Quick start

Requirements: Python 3.14 and an environment that can install the
dependencies from `pyproject.toml`. Commands below assume macOS/Linux
and a local checkout:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
```

**Offline, sanitized ARP preview** (no network capture):

```bash
python -m novxis.cli.web_preview
```

**Authorized, finite live ARP + mDNS + IPv6 NDP capture** (macOS example):

```bash
sudo .venv/bin/python -m novxis.cli.network_live_stream en0 --count 2000 --timeout 120 \
  | .venv/bin/python -m novxis.cli.web_live
```

Choose the interface actually carrying the traffic (for example `en0`
for Wi-Fi or `en5` for dock Ethernet). The capture producer needs packet
capture permissions; the browser server on the right side of the pipe
remains **unprivileged** and bound to
[http://127.0.0.1:8765/](http://127.0.0.1:8765/).
The default live capture is finite. Stop the local debugger with Ctrl+C.
Do not publish raw captures, private device identifiers or screenshots.

For protocol-specific CLI entry points, consult `pyproject.toml`
and the linked implementation records below.

## Architectural principles

```text
capture / replay                   separately sourced local OS context
       |                                      |
   protocol decoders                   reported configuration
       |                                      |
   typed observations / events / scoped evidence
                         |
       immutable, renderer-neutral graph projections
                         |
             permanent 2D reference debugger
                         |
              future 3D renderer (deferred)
```

- Preserve **protocol, capture interface/source, observation time,
  and evidence type** for each relationship.
- Keep ARP/NDP associations, DNS-SD records, DHCP advertisements,
  and OS-reported settings distinguishable. When evidence is incomplete
  or contradictory, retain the uncertainty.
- Passive observation is the default. Future **active investigation**
  requires explicit authorization, a narrow target/scope, and a record
  of which evidence it solicited.
- Visual layout must not invent physical devices, network links,
  or default-gateway ownership.

## Current milestone: Phase 1N-L

**Stages 1 and 2 merged; Stage 3 Unified addresses 2D mode validated on its feature branch, PR #49 ready for owner review.** Reuse
existing ARP sender and ICMPv6 NS-source/NA-target observations to show
**separate IPv4 and IPv6 address nodes** connected to shared,
**capture-scope/interface-qualified hardware-address nodes**, with
provenance-aware typed edges and an independent unified 2D view.
Preserve conflicts and the existing ARP-only debugger. This milestone
does **not** add DNS-SD graph nodes, gateway/topology inference, LLDP,
active probing, or device identity fusion.

- [Stage 3 unified 2D visualization and manual acceptance](docs/implementation/2026-11-07-unified-address-graph-stage3.md)
- [Stage 2 live metadata adapter and validation](docs/implementation/2026-11-07-unified-address-graph-stage2.md)
- [Stage 1 projection handoff and tests](docs/implementation/2026-11-07-unified-address-graph-stage1.md)
- [Phase 1N-L implementation scope and acceptance](docs/implementation/2026-11-07-phase1n-l-unified-address-graph-scope.md)
- [ADR 0002: Evidence-first address relationships](docs/architecture/0002-evidence-first-address-relationships.md)
- [ADR 0001: Permanent 2D reference and shared semantic graph](docs/architecture/0001-permanent-2d-reference-and-shared-graph.md)

## Detailed documentation

- [Latest live IPv6/NDP implementation and validation](docs/implementation/2026-11-07-live-ndp-ipv6-sidebar.md)
- [Implementation reports and milestone records](docs/implementation/)
- [Architecture decisions](docs/architecture/)
- [Validation records](docs/validation/)
- [Archived long-form README milestone log](docs/archive/README-milestone-history-through-2026-11-07.md)

For ideas beyond the near-term evidence graph, see the OAIOS
`NOVXIS - Project Parking Lot` note. This README is the short
entry point; detailed decisions and historical milestone accounts live
under `docs/`.
