# Phase 1M-B: Passive IPv4/IPv6 mDNS Observation, Live Capture and Replay

**Date:** 2026-10-18  
**Status:** Focused/full regression tests, two private real-PCAPNG replays, and passive live capture on both Wi-Fi and Ethernet interfaces validated on macOS; [PR #28](https://github.com/n2bxl/novxis/pull/28) squash-merged as `69e65a8`. No separate post-merge pytest result is claimed.  
**Scope:** Decode Ethernet II → IPv4/IPv6 → UDP/5353 → mDNS message evidence;
console-only, no active queries or service-inventory inference.

## Why this slice

In Phase 1M-A the capture-independent `parse_mdns()` interpreter learned
mDNS-specific QU questions, known answers, query Authority records,
responder cache-flush and zero-TTL goodbye candidate semantics. It passed
353/353 tests on merged `main` as of 2026-10-18.

The next requirement is to see the **real packets** that support eventual
network visualization, while preserving network family, source/destination,
captured interface and original bytes. Prior private Spotify experiment
captures included substantial IPv6 mDNS activity; restricting observation
to our existing IPv4-only UDP pipeline would miss those packets.

## New capture-neutral components

- `novxis.protocols.ipv6.IPv6Datagram` and `parse_ipv6`: strict fixed
  40-byte header; traffic class, flow label, declared length, next header,
  hop limit and 128-bit addresses; preserves trailing evidence.
- `ETHERTYPE_IPV6 = 0x86DD` in `novxis.protocols.ethernet`.
- `novxis.pipeline.mdns.MDNSEventPipeline`: reuses owned Ethernet,
  IPv4, UDP and mDNS parsers, plus the new IPv6 parser. Routes by
  EtherType; gates on UDP source or destination port 5353 before parsing
  candidate datagrams; ignores unrelated UDP/TCP and unsupported link types
  without inventing DNS messages.
- `novxis.events.mdns.MDNSMessageObserved`: immutable aggregate of
  `CapturedFrame`, decoded Ethernet, IPv4/IPv6, UDP and `MDNSMessage`.
- `novxis.presentation.mdns_console`: human-readable, bounded observation
  formatter distinguishing queries, responses, QU, known answers,
  responder cache-flush flags and TTLs.
- `novxis.cli.mdns_replay`: PCAP/PCAPNG replay and per-family/query/response
  counts; option `--summary-only`.
- `novxis.cli.mdns_events`: finite, passive live capture with
  `udp port 5353` BPF; same interpretation and counters as replay.

The existing classic DNS UDP/53 decoder, correlator and evidence state
remain unchanged. Neither CLI emits discovery requests.

```text
Scapy capture (live) / Raw PCAP reader (offline)
                   ↓
              CapturedFrame
                   ↓
             Ethernet II
                ↙     ↘
          IPv4          IPv6 fixed header
                ↘     ↙
                 UDP/5353
                   ↓
              parse_mdns()
                   ↓
             MDNSMessageObserved
                   ↓
              console view
```

## Explicit boundaries

- Ethernet **DLT_EN10MB** frames only. Other known link types fail
  explicitly; VLAN-tagged frames and interface-specific encapsulations
  are not handled in this slice.
- IPv4 fragments are skipped. For IPv6, the parser preserves fixed-header
  `next_header` and this pipeline only decodes direct UDP (17).
  Extension headers, fragment reassembly and IPv6 jumbograms are **not**
  supported. A later implementation must traverse extension headers
  safely rather than searching arbitrary payload bytes for UDP ports.
- IPv4 TTL and IPv6 hop limit are preserved as observed, not treated as
  definitive source authentication. IPv6 source/destination addresses
  remain byte-accurate, and 5353 may be unicast or multicast.
- UDP checksum values are carried but **not validated** against an IP
  pseudo-header. No claim of authenticated, successful or trustworthy
  mDNS advertisement follows from a decoded packet.
- mDNS records' PTR, A and AAAA interpretation is available from 1M-A,
  but **SRV target/port and TXT semantics remain raw** until Phase 1M-C.
- The observation layer does not invent device identities or match a
  query with one chosen response. Multiple responders and unsolicited
  announcements are normal mDNS behavior.
- The CLI `--count` applies to captured BPF-matching frames (live) or
  **all** input frames (replay), not the number of decoded mDNS records.
- Replay does not contact the network. A capture from one Ethernet
  interface is not a complete inventory of switched traffic.

## Synthetic validation (required before merge)

```bash
python -m pytest tests/protocols/test_ipv6.py \
  tests/integration/test_mdns_evidence.py \
  tests/integration/test_mdns_pcap_replay.py \
  tests/cli/test_mdns_cli.py -q

python -m pytest
```

Coverage includes IPv6 version/length bounds, addresses, flow label,
trailing evidence and unsupported next headers; dual-stack UDP/5353
query/response handling; normalized frame provenance; IPv4 fragment
exclusion; IPv6 extension-header non-interpretation; malformed message
errors; and offline/live CLI error/summary behavior.

### Local acceptance — 2026-10-18

On M5 MacBook Air, macOS/Darwin, Python **3.14.6**, pytest **9.1.1**:

- Focused IPv6, mDNS integration, synthetic PCAP replay, and CLI suites: **37/37 passed in 0.27s**.
- Complete regression suite: **390/390 passed in 0.32s**.
- Previous merged-`main` baseline: 353 passing tests. The feature branch adds **37 tests** with no observed regressions.

The focused suites include a synthetic on-disk PCAP replay test; the
separate private real-PCAPNG results are recorded below.

The mocked live-CLI tests validate the command contract. Subsequent
**real live captures on both Wi-Fi and Ethernet also passed**; see the
observations below. These runs validate passive capture on the tested
interfaces only, not other link types or routed subnets.

## Private real-capture acceptance

Keep the `spotify.pcapng` and `spotify 2.pcapng` files **outside** the
public repo. From your NOVXIS virtual environment, use paths to your
own local files:

```bash
python -m novxis.cli.mdns_replay "/path/to/spotify.pcapng" --summary-only
python -m novxis.cli.mdns_replay "/path/to/spotify 2.pcapng" --summary-only
```

### Real private PCAPNG replay acceptance — 2026-10-18

The MacBook ran the new NOVXIS replay CLI against **both local private
captures** using `--summary-only`. The resulting counts **exactly matched**
the independent Wireshark/frame-level reference for both files:

| Metric | First Spotify capture | Second Spotify capture |
| --- | ---: | ---: |
| Frames replayed | 2,766 | 1,188 |
| mDNS observations | 115 | 215 |
| IPv4 mDNS | 50 | 119 |
| IPv6 mDNS | 65 | 96 |
| Queries | 76 | 109 |
| Responses | 39 | 106 |
| Decode errors | **0** | **0** |

Combined: **330 observed mDNS packets** (169 IPv4, 161 IPv6),
**185 queries and 145 responses**, and **zero decode errors**.
These are results produced by NOVXIS on private captures, not merely
expected values. Per-packet text and service relationships are separate
future review topics; matching these counts does not establish that the
software observed all traffic on the local network or that any Spotify
playback handoff occurred.

No private filesystem path, MAC/IP list, service identifiers or raw PCAP
data has been committed to this public repository.

Inspect a bounded subset without printing hundreds of records:

```bash
python -m novxis.cli.mdns_replay "/path/to/spotify 2.pcapng" --count 100
```

For new passive live traffic, select the interface that actually carries
the multicast packets:

```bash
sudo .venv/bin/python -m novxis.cli.mdns_events en0 --count 40 --timeout 60
```

`en0` is an example; your Wi-Fi/Ethernet routing and interface assignment
can change between sessions. Opening Spotify on a different device is a
possible test trigger, not a requirement for decoding.

## Real passive live-capture acceptance — 2026-10-18

The MacBook ran `sudo .venv/bin/python -m novxis.cli.mdns_events`
with `--count 40 --timeout 60` on **both `en0` (Wi-Fi)** and
**`en5` (Ethernet)**. Each stopped after forty captured matching
frames and completed with **zero decoder errors**.

| Metric | Wi-Fi (en0) | Ethernet (en5) |
| --- | ---: | ---: |
| mDNS observations | **40** | **40** |
| IPv4 | 23 | 19 |
| IPv6 | 17 | 21 |
| Queries | 16 | 27 |
| Responses | 24 | 13 |
| Decode errors | **0** | **0** |

The raw console log demonstrated **QU and QM questions**, **known-answer
lists attached to queries**, **probe-like Authority Section assertions**,
**multicast and unicast destinations**, **cache-flush bits** in response
records, and **PTR/TXT/SRV/A/AAAA records** carried in answers or additional
sections. The console intentionally leaves SRV/TXT details raw in this
slice; TYPE47/NSEC was observed as uninterpreted RDATA.

### Controlled application relaunch observation

During the `en5` capture, the operator relaunched a media application
on a second local Mac. That Mac sent an mDNS PTR query for **Google Cast**,
then sent IPv4 and IPv6 PTR queries for **Spotify Connect**.
Two *different network addresses* subsequently advertised Spotify Connect
instances about **189 ms** and **228 ms** after the first observed IPv4
Spotify Connect query. Follow-on searches for another Spotify-named
service type were also observed.

This supports the observation that **local service discovery coincided
with the known relaunch event**, not a claim that any particular process
emitted each packet, that an advertised endpoint is currently reachable,
or that media playback was transferred. A separate service type is not
proof of an active listening session.

Wi-Fi traffic additionally showed independent local-device advertisements
and queries containing known answers. Addressing across both Mac
interfaces must **not** be counted as distinct physical devices without
explicit identity evidence. No hostname, IP address, UUID, raw capture
or personally identifying instance label is copied to this public note.

### Acceptance interpretation

- This validates **both** transport families and the actual live Scapy
  capture adapter in addition to offline PCAPNG replay.
- Aggregate counts are **packet observations**, not counts of distinct
  services or hosts; a 40-frame BPF capture limit does not represent all
  traffic during the full 60-second timeout.
- The same service may be advertised on IPv4 and IPv6 and repeated over
  time. Do not create a new node per packet or infer identities from
  matching names alone.
- SRV target/port and TXT parsing, NSEC meaning and service graph
  construction are intentionally not implemented here.

## Exit criteria

- Focused new tests and full regression suite pass on macOS Python 3.14.6.
- Both local PCAPNG files replay without unexpected errors.
- NOVXIS IPv4/IPv6 mDNS counts and representative queries/answers can be
  independently compared to Wireshark.
- No application behavior, user action, unique physical device or playback
  transfer is inferred from discovery traffic.
- Documentation records actual results, discrepancies and any limitations.

## Next work

Phase 1M-C: safe DNS-SD SRV/TXT decoding, service type→instance→
host/port/address semantics, then bounded evidence and renderer-independent
groups. Do not implement a Spotify-specific fingerprinting engine.

References:
- [Phase 1M-A message semantics](2026-10-18-mdns-message-semantics.md)
- [RFC 8200: IPv6](https://www.rfc-editor.org/rfc/rfc8200.html)
- [RFC 6762: mDNS](https://www.rfc-editor.org/rfc/rfc6762.html)
- [RFC 6763: DNS-SD](https://www.rfc-editor.org/rfc/rfc6763.html)
