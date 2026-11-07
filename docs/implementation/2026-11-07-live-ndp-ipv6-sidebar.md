# Phase 1N-K Stage 3: Live IPv6 Neighbor Evidence in the 2D Debugger

Date: 2026-11-07
Status: Draft PR; M5 pytest and Safari live validation pending.
Baseline: PR #44 Stage 2 squash-merged on main at 21ca821;
the developer's most recent full test run had 759 tests passed in 4.01s.

## Goal

Expose **independent, interface-scoped IPv6 Neighbor Discovery
observations** in the local 2D evidence debugger. Preserve the
original ARP graph and DNS-SD service semantics while adding an
optional same-interface **AAAA → IPv6 NDP evidence inspection**
shortcut. This is not a device inventory or a topology reconstruction.

## Architecture

    sudo network_live_stream: en0 / en5, bounded capture
        Ethernet II
            +-- ARP -> original bindings
            +-- IPv4/IPv6 UDP 5353 -> original mDNS/DNS-SD
            +-- IPv6 ICMPv6 135/136 -> Stage 1 checked decoder
                    |
                 Stage 2 NDStatePipeline (bounded typed evidence)
                    |
                ndp_message: one sanitized event per NS/NA
                    |   source/target IPv6, packet kind,
                    |   claim kind and advertised LLA or
                    |   unlinked reason, frame sender and capture time
                    |   NO raw packet/option bytes
                    v
                NDJSON localhost pipe, 4096-char line ceiling
                    |
       unprivileged LiveARPGraphState
          +-- unchanged ARP SVG / independent graph_revision
          +-- existing LiveMDNSState
          +-- NEW LiveNDPState with validation and retention
                    |
             /api/graph (same existing endpoint)
                    |
              local Safari IPv6 tab
                    |
            exact-scope DNS-SD AAAA shortcut

The existing combined capture's BPF becomes
`arp or udp port 5353 or icmp6`, preserving the
`--count` and `--timeout` bounds. Only direct IPv6
Next Header=58 NS/NA messages enter the new NDP evidence
state; other ICMPv6 types, Router Advertisements and
extension-header chains are not interpreted as neighbor
address claims. A malformed NDP candidate increments a
bounded decode-error count without aborting the ARP or
DNS-SD stream.

The new session format advertises protocols
`["arp", "mdns", "ndp"]` and is opt-in. The receiver
also continues to accept legacy `["arp"]` and
`["arp", "mdns"]` sessions; those do not activate the
IPv6 tab. Offline ARP fixtures do not fabricate IPv6
observations or load locally configured host values.

## Evidence semantics and uncertainty

- **NS SLLA**: one IPv6 *source* address has an observed
  source-link-layer option. The NS *target* is not inferred to
  possess the source LLA.
- **NA TLLA**: one IPv6 *target* has an observed
  target-link-layer option. The original Ethernet sender
  is independently preserved and is never substituted for
  a missing TLLA.
- **DAD**, empty or ambiguous options and invalid Ethernet
  addresses: keep unlinked observations only. A DAD target
  may be tentative and must not become an address-MAC claim.
- Repeated statements are counted; mutually inconsistent
  link-layer claims remain separate, with an ambiguity count.
  This is **not proof of duplicate physical devices**.
- No NDP TTL, freshness, reachability or host identity is
  derived from NS/NA. The original first/last capture times
  and evidence kind remain visible.

The unprivileged receiver atomically validates the entire
single-event payload before mutation, including canonical
IPv6 and Ethernet addresses, finite timestamps, interface
scope, message and evidence kind, DAD provenance, and
NS-source vs NA-target address association. It cannot
create an option-backed binding from an unlinked event.

Maximum 128 distinct claim records and 128 distinct
unlinked records are retained for the browser, with
omission counts. All advertised MAC/IP values are private
local evidence; real captures and device names remain
outside GitHub.

## IPv6 sidebar and exact DNS-SD cross-reference

- A fifth accessible tab, **IPv6**, is offered only when the
  live session advertises NDP evidence. It shows option-backed
  claims separately from unlinked observations, counters,
  MAC option values, first/last observation times and
  explicit provenance limitations.
- AAAA shortcuts appear only for an **exact IPv6 address**
  in a DNS-SD address record matching an independently
  observed **same-interface** option-backed NDP claim.
  They navigate to an existing IPv6 evidence entry, not a
  new graph node or edge. Independent Source SLLA evidence
  refers to the *source*, not the NS target.
- NAs with no TLLA, tentative DAD, and IPv6 addresses with
  no same-interface option-backed claim show no jump.
  If multiple independent LLAs were asserted, both remain
  inspectable, without verifying device identity.
- Existing IPv4 A-to-ARP navigation, Evidence inspector,
  Subnet, Host, Services, panning, zoom and manual node
  arrangement retain their behavior. One-second API
  polling uses separate `graph_revision`, so NDP updates
  cannot rearrange the ARP drawing.

## M5 acceptance

~~~bash
git fetch origin
git switch --track origin/ai/phase1n-k-live-ipv6-neighbors-2026-11-07
python -m pytest tests/web/test_ndp_live.py \
  tests/web/test_ndp_sidebar.py tests/cli/test_network_live_stream.py \
  tests/web -q
python -m pytest
~~~

Then launch the existing bounded capture on the
currently authorized interface:

~~~bash
sudo .venv/bin/python -m novxis.cli.network_live_stream en5 \
  --count 2000 --timeout 120 \
  | .venv/bin/python -m novxis.cli.web_live
~~~

Open http://127.0.0.1:8765/.

Check that:
1. **IPv6** tab shows separate NS-source and NA-target claims
   and missing-TLLA/DAD entries only when observed.
2. **Services** preserves PTR/SRV/A/AAAA and independently
   timestamps records. AAAA gains an IPv6 shortcut only for
   an exact, option-backed same-interface NDP match.
3. A screenshot with no cross-reference is a valid outcome
   when no matching NDP address was observed.
4. Existing ARP nodes, selected Evidence inspector, camera,
   Subnet/Host, and old IPv4-to-ARP jump are unaffected.
5. Legacy ARP-only capture and sanitized offline replay
   show no IPv6 tab. No packet bytes/TXT/options leave the
   capture process and no active probes run.
6. A captures-only NDP observation advances the API
   semantic revision but **not** graph_revision.
7. No claims of verified device identity, physical links,
   IPv6 address ownership or online/offline status appear.

The tests use documentation IPv6 addresses and synthetic
Ethernet values. Do not publish raw private PCAPs, device
IP/MAC addresses, screenshots or service-instance names.

## Deferred

ICMPv6 Router Advertisements, Router Solicitation,
IPv6 prefix information, OS neighbor cache comparison,
extension headers and fragments, address-liveness model,
persistent evidence, cross-interface device identity,
automatic topology, active NDP querying, and 3D views.
