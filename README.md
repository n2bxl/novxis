# NOVXIS

**Network Observation, Visualization, eXploration Interface System**

NOVXIS is an open-source networking education, exploration, visualization, and troubleshooting project focused on making abstract network behavior visually concrete.

Phase 0 established the console-first ARP vertical slice: NOVXIS can capture or replay real traffic, decode protocol evidence, produce normalized events, correlate exchanges, and present them clearly.

Phase 1 begins the network-state layer that turns a stream of observations into a conservative current view of what NOVXIS has actually learned.

## Phase 0 Development Environment

The initial development baseline is Python 3.14.

Create and activate a virtual environment:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
```

Install NOVXIS and the development dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest
```

## Interface Enumeration

Ask Scapy which interfaces are available to NOVXIS:

```bash
python -m novxis.cli.interfaces
```

After installation, the equivalent console command is:

```bash
novxis-interfaces
```

## Live Capture Smoke Test

NOVXIS now includes its first capture-provider implementation backed by Scapy. The provider converts Scapy packets into neutral `CapturedFrame` evidence objects before handing them to the rest of the application.

A finite ARP-only smoke capture can be started with:

```bash
sudo .venv/bin/python -m novxis.cli.capture en5 --filter arp --count 5 --timeout 30
```

or with the installed console command:

```bash
sudo .venv/bin/novxis-capture en5 --filter arp --count 5 --timeout 30
```

The smoke command currently reports capture metadata only. Protocol decoding belongs to the next layer and is intentionally not performed by the capture provider.

Example output:

```text
NOVXIS live capture
interface=en5 filter=arp count=5 timeout=30.0s

[2026-10-04T11:15:42.123-05:00] en5 captured=74 bytes original=unknown
```

On platforms that require elevated packet-capture privileges, run the virtual environment's Python or console script explicitly through `sudo` so the correct environment is used.

## Capture Boundary

```text
Scapy / platform capture
        ↓
ScapyCaptureProvider
        ↓
CapturedFrame
  - timestamp
  - interface
  - raw bytes
  - captured length
  - original length when available
        ↓
Protocol interpretation
```

Scapy packet objects should remain inside the Scapy capture implementation. Protocol parsers and event models should consume NOVXIS-owned evidence types instead.

## ARP Evidence Decoding

The next Phase 0 layer decodes the captured bytes without asking Scapy to interpret the protocol for NOVXIS:

```text
CapturedFrame
     ↓
parse_ethernet()
     ↓
EthernetFrame
     ↓
parse_arp()
     ↓
ARPMessage
```

Run the live ARP evidence decoder with:

```bash
sudo .venv/bin/python -m novxis.cli.arp_capture en5 --count 5 --timeout 30
```

After reinstalling the editable package so the new console entry point is registered, the equivalent command is:

```bash
python -m pip install -e ".[dev]"
sudo .venv/bin/novxis-arp-capture en5 --count 5 --timeout 30
```

The decoder reports packet facts such as Ethernet source/destination, EtherType, ARP header fields, sender/target addresses, opcode, and the exact number and contents of bytes that remain after the logical ARP message.

The ARP parser calculates its offsets from the packet's own `HLEN` and `PLEN` fields. It does not assume Ethernet/IPv4 address sizes internally, and it preserves all trailing bytes without assigning them a meaning.

This layer intentionally stops at decoded evidence. Classifications such as ARP probe, announcement, cache validation, or completed resolution belong to later interpretation and correlation layers.

## ARP Observations and Correlation

NOVXIS can now normalize decoded ARP evidence into observations and conservatively correlate matching request/reply pairs:

```text
ARPMessage
    ↓
observe_arp()
    ↓
ARPRequestObserved / ARPReplyObserved
    ↓
ARPCorrelator
    ↓
ARPExchangeCompleted
```

Run the live event view with:

```bash
sudo .venv/bin/python -m novxis.cli.arp_events en5 --count 10 --timeout 30
```

The corresponding installed console command is `novxis-arp-events` after reinstalling the editable package.

Every observation retains the original `CapturedFrame`, decoded `EthernetFrame`, and `ARPMessage`, so higher-level events remain traceable to the exact packet evidence that produced them.

A request/reply exchange is completed only when the observations occur on the same interface, fall within the configured correlation window, use matching ARP address types and lengths, reverse the sender/target protocol addresses, and the reply targets the requester's hardware address.

The default correlation window is five seconds. This is a configurable NOVXIS implementation policy, not a property guaranteed by ARP itself. Unmatched requests and replies remain unmatched rather than being forced into an inferred conversation.

This layer still does not classify higher-level behaviors such as probes, announcements, cache validation, address conflicts, or resolution failures.

## PCAP/PCAPNG Replay

Live capture and file replay now converge on the same ARP processing pipeline:

```text
ScapyCaptureProvider ──► CapturedFrame ──┐
                                         ├──► ARPEventPipeline ──► console
PcapReplayProvider  ──► CapturedFrame ───┘
```

Replay a capture with:

```bash
python -m novxis.cli.arp_replay path/to/capture.pcapng
```

After reinstalling the editable package, the equivalent console command is:

```bash
novxis-arp-replay path/to/capture.pcapng
```

Replay does not require elevated packet-capture privileges because it reads an existing file rather than opening a live network interface.

The replay provider uses Scapy's raw PCAP reader so the original packet bytes are preserved. Classic PCAP timestamps, captured lengths, original wire lengths, and link type are converted into `CapturedFrame` metadata. For PCAPNG, per-packet link type and interface names are preserved when available.

Phase 0's ARP pipeline currently supports Ethernet captures (DLT 1). A capture that explicitly declares another link type is rejected rather than being guessed as Ethernet.

The optional `--interface-label` argument supplies a fallback label for formats such as classic PCAP that do not encode a capture interface name. PCAPNG interface names take precedence when present.

```bash
python -m novxis.cli.arp_replay capture.pcap \
  --interface-label en5 \
  --correlation-window 5
```

## Phase 1: ARP-Derived Network State

Phase 1 begins by deriving scoped address bindings from normalized ARP observations:

```text
CapturedFrame
     ↓
ARPEventPipeline
     ↓
ARPMessageObserved
     ↓
NetworkState
     ↓
ARPBindingLearned
ARPBindingRefreshed
ARPBindingChanged
```

An ARP binding records the currently observed relationship between one protocol address and one hardware address on one interface, together with first-seen, last-seen, and observation-count metadata.

NOVXIS deliberately does not equate an ARP binding with a physical host identity. Technologies such as proxy ARP, virtual addressing, interface changes, and address reuse can make that inference unsafe. Host identity can be layered on later when multiple sources of evidence support it.

Only the ARP sender fields establish state in this first slice. Target fields are not treated as proof of a binding. Sender protocol address `0.0.0.0` and all-zero sender hardware addresses are preserved in packet/event evidence but do not create state entries.

A hardware-address change for the same protocol address and interface produces `ARPBindingChanged`. It is not automatically labeled an address conflict.

Replay the sanitized Phase 0 fixture through the new state layer with:

```bash
python -m novxis.cli.arp_state_replay \
  tests/fixtures/arp_phase0_sanitized.pcap \
  --interface-label fixture
```

After reinstalling the editable package, the equivalent command is:

```bash
novxis-arp-state-replay \
  tests/fixtures/arp_phase0_sanitized.pcap \
  --interface-label fixture
```

The final snapshot should contain six ARP-derived bindings. The `0.0.0.0` sender does not become a binding, while the repeated `192.0.2.70` observation refreshes the existing binding rather than creating a duplicate.

## Phase 0 Completed Boundary

```text
LIVE CAPTURE ─────┐
                  ├──► PROTOCOL INTERPRETATION ──► NORMALIZED EVENTS ──► CONSOLE
PCAP/PCAPNG ──────┘
```

The first supported protocol vertical slice is ARP.

## Live ARP Network State

The same Phase 1 state pipeline can now consume live ARP capture:

```text
ScapyCaptureProvider ──► CapturedFrame ──► ARPStatePipeline ──► NetworkState
PcapReplayProvider  ───► CapturedFrame ──────────┘
```

Run a finite live state capture with:

```bash
sudo .venv/bin/python -m novxis.cli.arp_state_live en0 \
  --count 20 \
  --timeout 30
```

After reinstalling the editable package, the equivalent console command is:

```bash
sudo .venv/bin/novxis-arp-state-live en0 \
  --count 20 \
  --timeout 30
```

The command prints packet/event evidence as it arrives, prints any derived
`ARPBindingLearned`, `ARPBindingRefreshed`, or `ARPBindingChanged`
state changes, and prints the current ARP-derived state snapshot when capture
ends.

Live capture and file replay therefore share the same state-building logic.
Only the source of `CapturedFrame` evidence differs.

## IPv4 Evidence Decoding

The second protocol path begins with IPv4 as a reusable Layer 3 boundary rather
than jumping directly from Ethernet into a transport or application protocol:

```text
CapturedFrame
     ↓
parse_ethernet()
     ↓
EthernetFrame
     ↓
parse_ipv4()
     ↓
IPv4Datagram
```

Run a finite live IPv4 evidence capture with:

```bash
sudo .venv/bin/python -m novxis.cli.ipv4_capture en0 \
  --count 5 \
  --timeout 30
```

After reinstalling the editable package, the equivalent console command is:

```bash
sudo .venv/bin/novxis-ipv4-capture en0 --count 5 --timeout 30
```

The IPv4 decoder derives the header length from IHL, respects the datagram's
declared total length, preserves IPv4 options, exposes fragmentation fields,
and keeps any bytes beyond the logical IPv4 datagram as trailing evidence.
It does not yet validate the IPv4 header checksum or interpret the upper-layer
payload.

This establishes the boundary needed for the next vertical slice: ICMP can
consume `IPv4Datagram.payload` without depending on Scapy protocol objects.

## Current Phase 1 Boundary

```text
PACKETS
   ↓
EVIDENCE
   ↓
NORMALIZED EVENTS
   ↓
NETWORK STATE
   ↓
PRESENTATION
```

Phase 1 currently stops at ARP-derived address-binding state. It does not yet infer durable host identity or render a graphical network world.
