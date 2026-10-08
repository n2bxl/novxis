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

This establishes a reusable Layer 3 boundary: upper-layer protocol decoders can
consume `IPv4Datagram.payload` without depending on Scapy protocol objects.

Live validation on 2026-10-06 exercised real TCP, UDP, unicast, and multicast
IPv4 traffic. Captured Ethernet and IPv4 lengths agreed exactly, no unexpected
trailing bytes were observed, and protocol/TTL/DSCP/ECN/fragmentation fields
varied plausibly across live packets.

## ICMP Echo Events and Correlation

ICMPv4 now builds directly on the IPv4 evidence boundary:

```text
CapturedFrame
     ↓
EthernetFrame
     ↓
IPv4Datagram
     ↓
ICMPMessage
     ↓
ICMPEchoRequestObserved / ICMPEchoReplyObserved
     ↓
ICMPEchoCorrelator
     ↓
ICMPEchoExchangeCompleted
```

Run the live ICMP event view with:

```bash
sudo .venv/bin/novxis-icmp-events en5 --count 6 --timeout 30
```

Use the interface that actually carries the traffic being tested. On macOS, the
default-route interface can be checked with:

```bash
route -n get default | grep interface
```

The Echo correlator requires the same capture interface, reversed IPv4
source/destination addresses, matching Echo identifier and sequence fields,
matching echoed payload, and a reply within the configured correlation window.
Unmatched observations remain unmatched rather than being forced into an
exchange.

Fragmented IPv4 datagrams are deliberately skipped by the ICMP event pipeline
for now because NOVXIS does not yet reassemble IPv4 fragments.

A live Ethernet validation on 2026-10-06 captured three requests and three
replies generated by `ping -c 3 1.1.1.1`. NOVXIS correlated all three exchanges
with observed capture-boundary RTTs of 12.972 ms, 13.322 ms, and 13.059 ms, and
finished with zero pending unmatched Echo Requests.

The RTT reported by NOVXIS is an observed capture-boundary interval. It can
differ slightly from the RTT printed by the originating `ping` process because
the two measurements begin and end at different points in the host networking
stack.

Detailed acceptance evidence is recorded in
`docs/validation/2026-10-06-ipv4-icmp-live-validation.md`.

## ICMP Error Events and Quoted IPv4 Evidence

ICMP error handling now extends the same IPv4 evidence path with semantic
observations for Destination Unreachable and Time Exceeded:

```text
IPv4Datagram
     ↓
ICMPMessage
     ↓
ICMPDestinationUnreachableObserved / ICMPTimeExceededObserved
     ↓
IPv4DatagramQuote
```

The quoted IPv4 model is intentionally distinct from a complete `IPv4Datagram`.
ICMP errors may include the entire original datagram, only the original IPv4
header plus a transport prefix, or additional bytes beyond the original
datagram's declared total length. NOVXIS preserves those cases without forcing
them into one representation.

Live validation on 2026-10-06 exercised both implemented error families:

- `traceroute -m 4 1.1.1.1` produced Time Exceeded / TTL Exceeded in Transit
  responses from successive hops.
- `traceroute -m 2 192.168.4.1` produced Destination Unreachable / Port
  Unreachable responses from the local gateway.
- The quoted original packets reported IPv4 protocol 17, confirming real UDP
  traceroute probes.
- Quotes were observed as complete, truncated to the IPv4 header plus eight
  transport bytes, and complete with additional trailing evidence.

The console reports both the quoted payload-prefix length and any preserved
trailing-byte count. The extra bytes remain uninterpreted evidence until a
future ICMP-extension parser can identify them safely.

## Current Phase 1 Boundary

```text
PACKETS
   ↓
EVIDENCE (Ethernet / ARP / IPv4 / ICMP / UDP)
   ↓
NORMALIZED EVENTS
   ↓
NETWORK STATE (currently ARP-derived bindings only)
   ↓
PRESENTATION
```

Phase 1 currently maintains persistent network state only for ARP-derived
address bindings. The protocol/event stack also supports IPv4 evidence, ICMP
Echo correlation, ICMP Destination Unreachable / Time Exceeded error evidence,
and individual UDP datagram observations. ICMP and UDP observations **do not**
yet establish additional persistent network state or imply durable physical-host
identity. The next planned protocol slice is DHCP over UDP to collect local
network configuration evidence toward a conservative local subnet map.

NOVXIS does not yet reassemble IPv4 fragments, validate UDP checksums, infer
UDP sessions or application-layer identity from port numbers, or render a
graphical network world.


## UDP Evidence and Live Observations

UDP uses the existing Ethernet and IPv4 decoding boundary:

```text
CapturedFrame → EthernetFrame → IPv4Datagram → UDPDatagram → UDPDatagramObserved
```

The UDP parser decodes source/destination ports, declared UDP length, checksum,
and payload. It preserves bytes beyond the declared UDP length as separate
evidence. A malformed length or truncated header/datagram raises `UDPParseError`.
The checksum is captured but not yet verified against the IPv4 pseudoheader.

Because IPv4 reassembly is not implemented, the UDP pipeline conservatively
skips all IPv4 fragments, including first fragments with the More Fragments bit.
It does not infer UDP sessions, DNS/DHCP application semantics, or delivery.

Run unit tests:

```bash
pytest tests/test_udp.py
pytest
```

Start a finite live capture using the interface carrying the test traffic:

```bash
python -m pip install -e ".[dev]"
sudo .venv/bin/python -m novxis.cli.udp_events en0 --count 10 --timeout 30
```

Equivalent installed command: `sudo .venv/bin/novxis-udp-events en0 --count 10 --timeout 30`.

For a controlled loopback smoke test, run the live command against the macOS
`lo0` interface in one terminal (subject to link-type support), then generate
UDP traffic in a second terminal with Python's `socket` module. Note that the
current evidence pipeline only accepts Ethernet link types, so macOS loopback
may be rejected. Prefer a real Ethernet capture interface for this iteration
rather than mislabeling loopback packets as Ethernet.

UDP validation on 2026-10-07 completed an initial passive capture
(10 datagrams), a 14-test raw Ethernet/IPv4/UDP integration-and-CLI suite,
and the 129-test full regression suite, all passing. A controlled two-Mac
LAN exchange also succeeded: NOVXIS decoded UDP lengths of 29 and 18 bytes
for the outbound request and inbound acknowledgment. A subsequent Wireshark
PCAPNG capture independently confirmed the byte contents of two outbound
21-byte requests and a 10-byte acknowledgment, as well as the NOVXIS-reported
packet fields for both observed requests. UDP checksum verification remains
out of scope.

To restrict capture to one UDP source or destination port, add `--port`:

```bash
sudo .venv/bin/python -m novxis.cli.udp_events en0 \
  --port 49000 --count 10 --timeout 90
```

The two-Mac capture plan and packet-by-packet validation results are in
`docs/validation/2026-10-07-udp-validation.md`. Choose a capture count
larger than the expected two datagrams, because other matching UDP packets
can exhaust the limit before the acknowledgment arrives.

