# Classic DNS Milestone Closeout (Phase 1A–1D-C)

**Reviewed:** 2026-10-17  
**Status:** Complete and merged on `main` for the agreed **passive IPv4 / classic DNS over UDP port 53** scope.  
**Latest acceptance:** macOS, Python 3.14.6, pytest 9.1.1 — **335/335 full regression tests passing** on merged `main`, confirmed 2026-10-17. This is not a claim of exhaustive DNS protocol support.

## Product boundary

NOVXIS is a **network observation and visualization system**. Its collected
evidence supports truthful views of network activity and relationships; users
may investigate what they see, but a general-purpose OSINT / application
fingerprinting / threat verdict engine is **not** part of this milestone.

> Visualization is the product. Evidence is the foundation. Investigation is
> something users can accomplish with both.

The original cyberspace goal remains a navigable world in which devices,
traffic, protocols, and *supported* relationships are visible. A DNS name
association is **not** a physical cable, verified service installation,
process identity, guaranteed current resolver state, or proof a device is alive.

## Implemented and merged

| Slice | PR | Merge commit | Main capability |
|---|---|---|---|
| 1A | [#20](https://github.com/n2bxl/novxis/pull/20) | `8977efd` | Bounded DNS wire decoder; all sections; compression; known A/AAAA/NS/CNAME/PTR RDATA; opaque unknown types |
| 1B | [#21](https://github.com/n2bxl/novxis/pull/21) | `1695814` | Passive UDP/53 observation, local PCAP/PCAPNG replay and live event console |
| 1C | [#22](https://github.com/n2bxl/novxis/pull/22) | `e6cce03` | Conservative query/response correlation, interface/endpoints/ports/ID/question matching |
| 1D-A | [#23](https://github.com/n2bxl/novxis/pull/23) | `ed2b4cf` | Scoped, bounded A/AAAA/CNAME/PTR answer evidence with per-record TTL, provenance and explicit-time freshness |
| 1D-B | [#24](https://github.com/n2bxl/novxis/pull/24) | `d62acbf` | Frozen UI-independent `DNSRelationshipSnapshot`; flat read-only console; live and replay view |
| 1D-C | [#25](https://github.com/n2bxl/novxis/pull/25) | `6d21823` | Frozen `DNSGroupedSnapshot`; logical CNAME component grouping, multi-root convergence, isolated PTR groups, optional grouped console |

The complete architecture is:

```text
CapturedFrame
   ↓
Ethernet → IPv4 → UDP/53 → DNS parser
   ↓
DNSMessageObserved → DNSCorrelator → DNSExchangeCorrelated
   ↓
DNSRelationshipState (source evidence, bounded history, per-RR TTL)
   ↓
project_dns_relationships(as_of=...) → DNSRelationshipSnapshot
   ↓ optional
group_dns_relationships(...) → DNSGroupedSnapshot
   ↓
Console today / future graphical cyberspace adapter
```

The `novxis.views` objects contain typed semantic data, not terminal strings.
Future graphics and HUD layouts must consume those objects rather than parse
stdout or embed UI assumptions in packet parsers or state.

## Validation ledger

| Slice | Reported full regression baseline | Key additional acceptance |
|---|---:|---|
| 1A | 211 passing | DNS parser synthetic tests |
| 1B | 236 passing | Live UDP/53 on the actual carrying interface; independent `dig`/`nslookup` cross-check |
| 1C | 274 passing | 20 live DNS observations, 9 correlated pairs, zero decode errors |
| 1D-A | 296 passing | 22 focused evidence tests, independent RR TTL and bounded history |
| 1D-B | No separate full-suite count reported in the conversation | 34 live DNS observations, 17 correlated pairs, 48 eligible RR observations, 45 latest relationships (26 fresh / 19 expired), zero errors |
| 1D-C | 335 passing | 27 focused group/CLI tests; 40 live frames, 18 correlations, 59 eligible RR observations, 45 latest relationships in seven groups (43 fresh / 2 expired), zero decode errors |
| **Post-merge main** | **335 passing** | Confirmed **2026-10-17**, Python 3.14.6, **0.40s**, working local `main` |

Do not infer from a finite-capture pending request that resolution failed:
the response may arrive after the capture stops. Record-observation counts
include repeat observations; `latest` groups only scoped record identities.

The real-world grouping test preserved **two independent naming roots
converging on one DNS target**, plus an independent short-TTL CNAME→CNAME→A
chain with expired intermediate/terminal evidence. Individual record
freshness is relative to received TTL at the capture timestamp, not wall
clock certainty or current network reachability.

**Privacy:** These public documentation files intentionally omit client
addresses, organization-specific query names, service-specific browsing
history, and raw packet captures. Raw PCAPs remain private/local.

## How to reproduce

Run the regression suite on `main`:

```bash
python -m pytest
```

A finite passive capture on whichever interface **actually carries** DNS:

```bash
sudo .venv/bin/python -m novxis.cli.dns_relationships live en0 --group --count 40 --timeout 60
```

`en0` is an example; use interface enumeration and routing context to choose
correctly. Classic event-only and correlated consoles still work:

```bash
sudo .venv/bin/python -m novxis.cli.dns_events en0 --count 20 --timeout 45 --correlate
python -m novxis.cli.dns_relationships replay /path/to/private-capture.pcapng --group --history
```

The grouping option is **opt-in**. `--history` retains recorded repeats
within the bounded buffer; `--as-of` evaluates freshness at an explicit
capture-clock Unix timestamp. Replaying old packets does not update the
present network.

## Boundary: not yet implemented

- **mDNS (UDP/5353) and DNS-SD:** local multicast name and service
  advertisements are separate protocol/discovery semantics, not gaps that
  should delay closing classic DNS. **Recommended next discovery vertical slice.**
- **DNS over TCP** including stream framing and reassembly; IPv4 fragment
  reassembly.
- **DNS HTTPS/SVCB (TYPE65)** semantic RDATA interpretation, extended EDNS,
  DNSSEC verification and special record/response extensions.
- **IPv6 packet/capture context**, mDNS IPv6 semantics; encrypted DoH/DoT
  payload visibility is intentionally limited without decryption.
- Comprehensive resolver-cache tracking, live status of devices, DNS ownership
  or authenticity, application identification and threat scoring.

Follow-on support should be justified by a concrete **visualization benefit**
and supported by actual evidence, rather than pursuing protocol completeness
for its own sake.

## Next Phase 1 direction

1. Implement mDNS and DNS-SD discovery evidence, starting with passive
   decoding and deterministic validation.
2. Add local interface/prefix/route/neighbor context necessary to define
   the observed subnet boundary.
3. Explore optional additional local discovery (SSDP, LLMNR, NetBIOS, etc.)
   only where it improves the local network map and available evidence.
4. Combine ARP/DHCP/DNS/discovery evidence conservatively into a
   renderer-independent **observed local subnet graph**.
5. Treat Q/E interface mechanics and navigable cyberspace graphics as later
   UI work; the data model should remain usable independently.

## Detailed reference notes

- [Phase 1A: DNS wire decoder](2026-10-11-dns-wire-decoder.md)
- [Phase 1B: UDP observations and validation](../validation/2026-10-11-dns-udp-observation-plan.md)
- [Phase 1C: correlation](2026-10-13-dns-query-response-correlator.md)
- [Phase 1D-A: timestamped relationship evidence](2026-10-13-dns-relationship-evidence.md)
- [Phase 1D-B: presentation-independent snapshot](2026-10-13-dns-relationship-view-adapter.md)
- [Phase 1D-C: naming chain grouping](2026-10-14-dns-chain-grouping.md)
