# Phase 1N-H: Passive Live mDNS Handoff to Local 2D Debugger

Date: 2026-11-03
Status: Draft implementation PR, M5 regression and live Safari acceptance pending.
Base: Phase 1N-G merged in PR #39 (49881f3).

## Objective

Add the **first passive live mDNS/DNS-SD observation path** to the
existing ARP-powered 2D debugger. Preserve ARP capture/state semantics
and source separation. The initial browser interface is intentionally
a **small read-only Services summary**, not a network service topology.

The capture side reuses existing MDNSEventPipeline and
project_dnssd_advertisements rather than implementing a new decoder.
This first integration sends **PTR-backed, same-message service
evidence only**. The full SRV/TXT/A/AAAA service-state reconciliation
from Phase 1M remains available independently for replay and later
integration.

## Process split and data flow

    Authorized en0 / en5 capture: ARP or UDP/5353 (IPv4 and IPv6)
                         |
               ScapyCaptureProvider
                    /           \
              ARPStatePipeline  MDNSEventPipeline
                    |            |
          binding observations  PTR-backed response projections
                    \           /
                 Bounded NDJSON pipe
                         |
              Unprivileged web_live
                /               \
         Current ARP state   LiveMDNSState
                \               /
                /api/graph live snapshot
                         |
              2D Map + Services tab

The new producer is launched with:

    sudo .venv/bin/python -m novxis.cli.network_live_stream en0 --count 2000 --timeout 120 \
      | .venv/bin/python -m novxis.cli.web_live

Do not launch the entire pipeline under sudo. The existing
novxis.cli.arp_live_stream en0 command and offline preview are
unchanged. The entire server remains loopback-only with its current
read-only HTTP and Content Security Policy controls.

## Stream schema and evidence rules

One combined session explicitly opts in with protocols=["arp","mdns"].
ARP still sends the original typed binding messages. Each decoded
mDNS UDP/5353 message adds a bounded event containing:

- Exact capture interface, IPv4 vs IPv6 source-family designation
- Capture-clock Unix timestamp
- Message role: query or response
- A count of PTR-backed DNS-SD advertisements
- Up to four service type/instance names with original PTR TTLs

No captured packet bytes, HTTP content, media payloads, arbitrary TXT
record bytes or private raw PCAP content cross into the web process.
Nonprintable/malformed or long instance names are omitted from the
limited view, with a separate omission/truncation indicator.

**Queries, including known-answer hints, never become advertisements.**
PTR-backed response claims are not proof of a running service or
physical host identity. mDNS and ARP remain separate sources and are
not merged based on naming similarity or sender IP addresses.

The receiver validates all untrusted fields before state mutation:
interface scope, timestamp range, IP version, query/response role,
bounded advertisement counts, printable name lengths, PTR TTL and
max records. A malformed pipe record still triggers the existing
stream-error protection. A malformed mDNS packet produces an explicit
mDNS decode-error *counter*, without aborting valid ARP capture.

The current service-state projection keeps at most 128 distinct
service type/instance keys on one capture interface; it marks missing
records as truncated rather than implying exhaustive discovery.

## TTL freshness and browser rendering

The mDNS state uses per-advertisement capture timestamps and original
PTR TTL. **Fresh** means a currently unexpired PTR claim by TTL,
not that the advertised service is online or responding.

The reader injects an explicit clock for deterministic tests and uses
current Unix time on the live M5. Snapshots recalculate freshness
even after the producer ends, and bump the API revision when any
retained PTR crosses its expiry boundary without new captured packets.

The live API remains schema version 1 and retains mode "live-arp" for
compatibility. It adds only optional mdns_evidence and graph_revision.
Graph rendering uses graph_revision to avoid unnecessary SVG redraws
on mDNS-only updates. Service tab switching retains pan, zoom and
the original selected ARP address.

The Services tab displays message counts, IPv4/IPv6 breakdown, query
and response counts, PTR counts, bounded retained service names, TTL
freshness, capture timestamps, decode errors and truncation notices.
It is disabled in ARP-only sessions and offline PCAP preview.

## M5 acceptance

    git fetch origin
    git switch --track origin/ai/phase1n-live-mdns-summary-2026-11-03
    python -m pytest tests/cli/test_network_live_stream.py tests/web -q
    python -m pytest

Run the combined capture command above on en0, open
http://127.0.0.1:8765/, and check:

1. ARP address map builds and inspector/pan/zoom/Rearrange work as before.
2. Services tab becomes available and shows queries/responses separately.
3. Ordinary multicast mDNS on the chosen interface produces IPv4
   and/or IPv6 observation counts; count depends on traffic present.
4. PTR-backed *response* advertisements appear with native service names
   and TTL freshness, if such a response is observed.
5. No observed PTR-backed response yields an honest empty service list;
   it must not create names from queries.
6. Session ends after timeout/frame limit; current graph remains visible.
7. Host/Subnet/Evidence tab data remains unchanged.
8. Old ARP-only producer keeps Services disabled.
9. Offline sanitized replay still shows 12 address nodes and six
   ARP sender claims with Services, Host and Subnet disabled.
10. Final mDNS TTL expiry updates status without new packets, where
    the observed PTR's TTL permits that check.

Before collecting screenshots or posting GitHub commentary, redact
real host names, service instance labels, local IPs and MACs.

## Deferred

No mDNS active queries, application fingerprints, verified endpoints,
automatic service-to-ARP identity fusion, arbitrary TXT content,
cross-message SRV/TXT/A/AAAA graph relationships, generalized
IPv6 network context, TLS inspection, remote control, or 3D views.
The existing richer mDNS state engine can be adapted in a future
scoped integration rather than bypassing its provenance requirements.
