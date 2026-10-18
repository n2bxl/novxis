# NOVXIS

**Network Observation, Visualization, eXploration Interface System**

NOVXIS is an open-source networking education, exploration, visualization, and troubleshooting project focused on making abstract network behavior visually concrete.

Phase 0 established the console-first ARP vertical slice: NOVXIS can capture or replay real traffic, decode protocol evidence, produce normalized events, correlate exchanges, and present them clearly.

Phase 1 begins the network-state layer that turns a stream of observations into a conservative current view of what NOVXIS has actually learned.


## Current DNS Milestone Status (2026-10-17)

**Classic DNS over IPv4/UDP port 53 is complete for the current NOVXIS
visualization scope.** DNS wire decoding, live/replay observation,
conservative query/response correlation, per-RR TTL evidence, immutable
presentation-independent snapshots and CNAME/A/AAAA/PTR grouping have all
been merged via PRs #20–#25. The merged `main` suite passes **335/335**.

Start with the [DNS milestone closeout and scope/roadmap](docs/implementation/2026-10-17-classic-dns-milestone-closeout.md).
Detailed, time-stamped implementation notes remain below as historical
records. **Next:** mDNS/DNS-SD passive local discovery and local
interface/subnet/route evidence. Later DNS extensions (TCP, HTTPS/SVCB
record decoding, EDNS, IPv6 and encrypted-transport limitations) are
**deferred**, not unimplemented blockers for this milestone.

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

Phase 1 maintains ARP-derived address bindings and a separate, conservative
snapshot of the latest **matched DHCPv4 ACK-derived configuration evidence**.
These records represent what DHCP messages said at capture time, not a verified
current lease, a physical-host identity, or a reachable host. ICMP/UDP remain
independent evidence paths, and DHCP does not overwrite ARP-derived bindings.

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

## DHCPv4 Message Observations and Offline Replay

The DHCPv4 decoder now connects to the existing Ethernet → IPv4 → UDP path:

```text
CapturedFrame → EthernetFrame → IPv4Datagram → UDPDatagram
              → DHCPv4Message → DHCPv4MessageObserved
```

The `DHCPv4EventPipeline` considers UDP datagrams only when **both** endpoint
ports are DHCPv4 ports (67/68), including relay traffic on 67/67. It inherits
the UDP pipeline's IPv4-fragment exclusion and payload-length validation. A
DHCPv4 message retains its source `CapturedFrame`, decoded Ethernet/IPv4/UDP
evidence, BOOTP fields, and ordered options. Invalid DHCP magic cookies or
truncated options raise `DHCPv4ParseError` and are reported by the replay
command without silently claiming a valid message.

Replay a private capture with:

```bash
python -m novxis.cli.dhcpv4_replay /path/to/novxis-dhcp-lab2.pcap
```

After `python -m pip install -e ".[dev]"`, an equivalent entry point is:

```bash
novxis-dhcpv4-replay /path/to/novxis-dhcp-lab2.pcap
```

The console reports individual DHCP message types, transaction IDs, requested
or assigned addresses, server identifiers, and single well-formed lease options.
A DHCPREQUEST lease option is labeled `requested_lease`; a DHCPACK lease option
is labeled `granted_lease`. All output is derived from packet bytes rather than
assumptions about the host's configured state.

A classic PCAP does not record the source interface, so the replay command uses
`replay` as a fallback label. Set `--interface-label en0` if desired.
`--count` limits the number of **captured frames**, not DHCP messages; zero
replays all frames.

The Oct 7 Intel Mac DHCP capture contains a matched REQUEST and ACK with the
same transaction ID, a requested 90-day lease and granted 8-hour lease. That
capture remains **private and is not committed** to the repository. This phase
does not correlate requests and responses into exchanges, infer INIT-REBOOT
from a single observation, manage lease state, or prove address/gateway/DNS
reachability. DHCP option-overload decoding is also deferred.

Validate with:

```bash
pytest -q tests/integration/test_dhcpv4_evidence.py tests/cli/test_dhcpv4_replay_cli.py
pytest
```

## DHCPv4 Exchange Correlation and ACK-Derived Network State

The DHCPv4 protocol pipeline now also supports conservative exchange correlation:

```text
CapturedFrame
  → Ethernet → IPv4 → UDP → DHCPv4MessageObserved
  → DHCPv4Correlator
  → DHCPv4ExchangeCompleted (DISCOVER/OFFER, REQUEST/ACK, REQUEST/NAK, INFORM/ACK)
  → NetworkState.dhcpv4_acknowledgments (REQUEST/ACK with usable yiaddr and lease)
```

Correlation requires the same capture interface, transaction ID, compatible
BOOTP hardware type/address, compatible DHCP client identifiers when both are
present, a nonnegative response interval, and the configured finite window.
It also compares requested/acknowledged addresses and selected/responding DHCP
server identifiers when those fields are available. It does **not** match on
`xid` alone. Unmatched replies do not create exchanges or address records.

DISCOVER may receive offers from multiple servers. Subsequent DHCPREQUEST
retire the pending DISCOVER stage; REQUEST/ACK and REQUEST/NAK complete their
respective request stages. INFORM/ACK is tracked but **never** treated as an
address lease. A DHCPRELEASE observation alone is not a server-confirmed
release. An observed DHCPNAK is not retroactively treated as proof that an
earlier ACK never happened.

The request-pattern field can report `INIT-REBOOT`, `SELECTING`, `RENEWING`,
or `REBINDING` when packet fields match the respective RFC 2131 patterns.
These are **evidence-based classifications**, not assertions about the client's
internal operating-system state. The correlator uses a configurable **10-second**
default window; this is NOVXIS policy, not a DHCP standard timeout.

`NetworkState.dhcpv4_acknowledgments` retains, per observed client/interface,
the latest correlated DHCPREQUEST/DHCPACK's acknowledged IPv4 address, lease
option, server identifier, subnet mask, router list, DNS server list, and
explicit renewal/rebinding times (T1/T2) if present. Missing T1/T2 values
remain missing; NOVXIS does not silently substitute default timers.

**An ACK proves an ACK was captured, not that the client accepted it, installed
the configuration, remains online, or can reach the gateway or Internet.**
Similarly, replaying an old PCAP produces a historical observation snapshot,
not current network inventory. No lease-expiration or active-host clock is
inferred in this slice.

Replay the **private local capture** (do not add it to the public repo):

```bash
python -m novxis.cli.dhcpv4_state_replay \
  ~/Desktop/novxis-dhcp-lab2.pcap --correlation-window 10
```

Or after installing the editable package:

```bash
novxis-dhcpv4-state-replay ~/Desktop/novxis-dhcp-lab2.pcap
```

For the previously dissected private capture, expect 30 replayed frames, two
DHCP observations, one correlated REQUEST/ACK with a response interval near
50 milliseconds, one latest ACK configuration record, and no decode errors.
These are validation expectations until confirmed by executing the command.
The existing `dhcpv4_replay` command continues to output individual raw
observations without correlation.

Tests:

```bash
pytest -q tests/integration/test_dhcpv4_state_evidence.py \
  tests/cli/test_dhcpv4_state_replay_cli.py
pytest
```

Deferred beyond this DHCPv4 protocol slice: decoding DHCP option-overload fields
and every vendor extension, IPv4 fragmentation/reassembly, real-time lease
expiration, multiprotocol ARP/DHCP host correlation, graphical rendering, and
DHCPv6 (which has a different wire format and behavior).

Primary protocol references: [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html),
[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html), and
[IANA BOOTP/DHCP parameters](https://www.iana.org/assignments/bootp-dhcp-parameters).


## DNS Wire Decoder (Phase 1A)

The next local-map foundation begins with a bounded, capture-independent DNS
message decoder in `novxis.protocols.dns`. `parse_dns(bytes)` decodes the DNS
header, all question and resource-record sections, safe backward-only name
compression, A/AAAA address values and NS/CNAME/PTR name values. Unknown record
types and classes retain raw RDATA, and any bytes beyond declared sections are
preserved rather than silently discarded.

This first slice deliberately stops at **decoded evidence**. It does not yet
dispatch UDP port-53 traffic, correlate questions/responses, assign host
identity, infer cache validity, or perform active DNS requests. IPv4 fragment
reassembly, DNS-over-TCP and mDNS remain separate follow-on work.

For the parser's security and data-model boundaries, planned next slices and
synthetic validation instructions, see
[`docs/implementation/2026-10-11-dns-wire-decoder.md`](docs/implementation/2026-10-11-dns-wire-decoder.md).

```bash
python -m pytest tests/protocols/test_dns.py -q
python -m pytest
```

Phase 1A local acceptance (2026-10-11): **24/24 focused DNS tests** and
**211/211 full-suite tests** passed. Live capture was completed in Phase 1B;
the full classic DNS milestone is now merged.


## Phase 1B: DNS over UDP Observation Path

The new `DNSEventPipeline` extends the existing Ethernet, IPv4, and UDP
decoders with the DNS wire decoder from Phase 1A. The normalized
`DNSMessageObserved` retains the original captured frame, timestamp,
interface, and decoded Ethernet/IPv4/UDP/DNS evidence.

Classic DNS UDP source or destination port 53 is accepted as candidate
application traffic. Other ports, TCP, mDNS port 5353, and IPv4 fragments
are not interpreted as classic DNS in this slice. Port 53 alone is not proof
of valid DNS content; malformed candidate messages produce decode errors.

Replay recorded traffic:

```bash
python -m novxis.cli.dns_replay /path/to/capture.pcapng
```

Passive live capture:

```bash
sudo .venv/bin/python -m novxis.cli.dns_events en0 --count 20 --timeout 45
```

The live command captures at most 20 matching port-53 frames or waits until
timeout. A capture can contain queries without replies if relevant packets
are not visible from the capture interface. The command does not initiate
DNS queries.

Tests for the DNS evidence path:

```bash
python -m pytest tests/integration/test_dns_evidence.py tests/cli/test_dns_replay_cli.py tests/cli/test_dns_events_cli.py -q
python -m pytest
```

Local acceptance (2026-10-11, Python 3.14.6): **25/25 focused tests**
and **236/236 full-suite tests** passed. The initial zero-observation run
targeted the wrong interface (`en0`); retesting on `en5` produced
**8 live DNS observations (4 queries and 4 responses), 0 decode errors**.
Reported DNS IDs, PTR/A results, TTLs and NXDOMAIN response agreed with
`nslookup` and `dig`. These are individual observations, not a
query-response correlator. See the Phase 1B validation plan for details.
Correlation, name-to-address state, DNS-over-TCP, mDNS and DNS-SD remain separate.


## Phase 1C: Conservative DNS Query/Response Correlation

The optional `DNSCorrelator` groups only unambiguously related DNS-over-UDP
messages by capture interface, reversed source/destination IP addresses and
UDP ports, transaction ID, opcode, and complete DNS question identity
(QNAME, QTYPE and QCLASS). DNS names are ASCII case-insensitive for comparison;
original wire bytes remain unchanged. Repeated outstanding identical queries
are quarantined rather than arbitrarily paired.

Run passive live correlation on your **actual** capture interface:

```bash
sudo .venv/bin/python -m novxis.cli.dns_events en5 --count 20 --timeout 60 --correlate
```

Or analyze a locally held capture:

```bash
python -m novxis.cli.dns_replay /path/to/capture.pcapng --correlate
```

Both consoles still print all individual observations; correlated pairings
are **additional** output and never prove DNS response authenticity, device
identity, or current reachability. Omit `--correlate` to retain Phase 1B
observation-only behavior.

```bash
python -m pytest tests/events/test_dns_correlator.py tests/cli/test_dns_correlation_cli.py -q
python -m pytest
```

See [Phase 1C implementation notes](docs/implementation/2026-10-13-dns-query-response-correlator.md)
for matching rules, ambiguity/expiry safeguards, validation and known limits.
**Local acceptance 2026-10-13:** 38/38 Phase 1C tests and 274/274
full-suite tests passed on Python 3.14.6. A live capture on `en0`
produced 20 DNS observations, 9 correlated exchanges, 2 pending
requests at the capture cutoff, and 0 decode errors. IDs, response
values, and timing were cross-checked against `dig` and `dig -x`.
See the implementation notes for details and remaining boundaries.


## Phase 1D-A: DNS Relationship Evidence with Independent TTLs

`DNSStatePipeline` composes existing packet decoding and conservative
query/response correlation with new `DNSRelationshipState`. Only supported
answer records from matched, non-truncated NOERROR responses create evidence:
A, AAAA, CNAME and PTR. Each relationship preserves the original resource
record, observed timestamp, received TTL and correlated exchange provenance.

The bounded state provides `history`, `latest_records` and
`fresh_records(as_of)`; freshness requires an explicit timestamp and is
**not** a connectivity, DNS authenticity or physical-host assertion. CNAMEs
are logical aliases, not router hops; TTL=0 answers are historical only.
Multiple answers and different resolvers remain distinct.

```bash
python -m pytest tests/integration/test_dns_state_evidence.py -q
python -m pytest
```

See [Phase 1D-A implementation and acceptance plan](docs/implementation/2026-10-13-dns-relationship-evidence.md).
**Phase 1D-A acceptance (2026-10-13):** 22/22 focused tests and **296/296**
full-suite tests passed on macOS Python 3.14.6. PR #23 merged; live
relationship console presentation followed in 1D-B.


## Phase 1D-B: Renderer-neutral DNS Relationship Snapshots

The immutable `DNSRelationshipSnapshot` and `DNSRelationshipView` models in
`novxis.views` project DNS state into framework-independent, deterministic
semantic relationships. They preserve alias/address/reverse-name relationship
types, response provenance, independent TTLs, and explicit-time freshness.
The console is an adapter that formats this data; **future GUI/cyberspace
renderers consume the same typed snapshot, never parsed stdout**.

Passive aggregated live view (select the active capture interface):

```bash
sudo .venv/bin/python -m novxis.cli.dns_relationships live en0 --count 40 --timeout 60
```

Read-only PCAP/PCAPNG replay:

```bash
python -m novxis.cli.dns_relationships replay /path/to/private-dns.pcapng
```

Use `--history` for individual retained observations instead of latest
per-record snapshots. Use `--as-of UNIX_SECONDS` for deterministic
historical freshness evaluation; otherwise the CLI uses the capture's latest
frame timestamp (never the present wall clock for old replay files).
The display is aggregated once at capture completion; existing DNS commands
are unchanged. No active probes, invented device nodes, DNS cache assertions,
or inferred physical connections.

```bash
python -m pytest tests/integration/test_dns_state_evidence.py tests/cli/test_dns_relationships_cli.py -q
python -m pytest
```

See [Phase 1D-B UI-neutral view design](docs/implementation/2026-10-13-dns-relationship-view-adapter.md).
Phase 1D-B merged via PR #24. Live relationship-view capture was validated;
the full merged-`main` regression suite later passed **335/335** on
2026-10-17. No separate 1D-B-specific full-suite result was reported.


## Phase 1D-C: Grouped DNS Naming Relationships

An optional, immutable `DNSGroupedSnapshot` groups previously projected
CNAME/A/AAAA records into scoped naming components, with PTR in separate
reverse-name groups. Each input evidence record appears exactly once.
Shared CNAME targets, multi-address answers, expired records, cycles and
missing endpoints remain visible—never promoted to verified physical
topology or live DNS cache state. The flat renderer remains the default.

Use `--group` with existing live/replay relationship commands:

```bash
sudo .venv/bin/python -m novxis.cli.dns_relationships live en0 --group --count 40 --timeout 60
python -m novxis.cli.dns_relationships replay /path/to/private.pcapng --group --history
```

The grouping adapter is in `novxis.views.dns_groups`; the console-only
formatting is in `novxis.presentation.dns_group_console`. Future graphical
renderers consume the same immutable group objects rather than parsing text.

```bash
python -m pytest tests/views/test_dns_groups.py tests/cli/test_dns_relationships_cli.py -q
python -m pytest
```

See [Phase 1D-C documentation](docs/implementation/2026-10-14-dns-chain-grouping.md).
**Phase 1D-C local acceptance (2026-10-14):** 27/27 focused tests
and **335/335** full regression tests passed on macOS Python 3.14.6.
A passive 40-frame `en0` capture produced 18 correlated exchanges,
59 eligible answer-record observations, **45 distinct relationships
grouped into seven naming groups** (43 fresh, 2 expired),
one pending request at capture cutoff, and zero decode errors.
A two-root shared-target alias group and mixed-freshness CNAME→A
chain validated grouping behavior against independent DNS lookups.
See the implementation notes for anonymized acceptance findings.
PR #25 was squash-merged. The full test suite was subsequently rerun on
merged `main` on 2026-10-17: **335/335 passed** in **0.40s** on
macOS Python 3.14.6.


## Phase 1M-A: mDNS Message Semantics (First Local-Discovery Slice)

mDNS shares the classic DNS wire format, but **its message sections and class
bits are not interchangeable with conventional DNS**. The new
capture-independent `novxis.protocols.mdns.parse_mdns(bytes)` interprets
mDNS questions (QU/QM), responder cache-flush bits, query Answer Section
known-answer hints, Authority records, response sections and zero-TTL
goodbye candidates. Raw DNS message bytes/classes, unknown records and
per-record TTLs remain accessible.

The underlying `parse_dns()` has a keyword-only mDNS class-bit option
that defaults **off**, so classic UDP/53 DNS interpretation is unchanged.
mDNS data structures are immutable and suitable for future normalized
capture observations and renderer-independent service views.

This first feature branch contains **message interpretation only**.
It does **not** yet capture or replay UDP/5353, process IPv6 packets,
decode SRV/TXT into DNS-SD service semantics, create a service inventory,
or transmit discovery queries. Existing classic DNS query/response
correlation is **not** reused for mDNS.

```bash
python -m pytest tests/protocols/test_mdns.py tests/protocols/test_dns.py -q
python -m pytest
```

See [Phase 1M-A implementation and acceptance plan](
docs/implementation/2026-10-18-mdns-message-semantics.md).
**Phase 1M-A accepted and merged:** **42/42 focused tests** passed on
2026-10-18, with **353/353 full-suite tests** on the feature branch.
[PR #27](https://github.com/n2bxl/novxis/pull/27) was squash-merged as
`cc48f4a`; the post-merge local `main` run passed **353/353 in 0.36s**
on Python 3.14.6. Message interpretation was the only capability in this
slice. Real UDP/5353 capture/replay is Phase 1M-B; DNS-SD SRV/TXT semantics
and service grouping follow in Phase 1M-C.


## Phase 1M-B: Passive Dual-Stack mDNS Observation (Merged)

This feature branch extends Phase 1M-A's capture-neutral mDNS message parser
with a separate, immutable IPv4/IPv6 observation path:
`Ethernet II → IPv4/IPv6 → UDP/5353 → MDNSMessageObserved`.
The new bounded IPv6 fixed-header decoder retains original 128-bit addresses,
hop limit, length, flow label and payload provenance.

**Offline private PCAP/PCAPNG replay:**

```bash
python -m novxis.cli.mdns_replay "/path/to/spotify.pcapng" --summary-only
python -m novxis.cli.mdns_replay "/path/to/spotify 2.pcapng" --summary-only
```

**Passive live capture:**

```bash
sudo .venv/bin/python -m novxis.cli.mdns_events en0 --count 40 --timeout 60
```

Use the interface carrying the actual traffic; the live command is **passive**
and uses `udp port 5353` BPF. Omit `--summary-only` to inspect
individual packet observations. The replay command's `--count` counts
*all file frames*; the live command's count applies to captured matching
frames. No device classification, service inventory, or active probes.

**Current boundaries:** Ethernet II only; no tagged VLAN encapsulation,
IPv4 fragments or IPv6 extension/fragment traversal; IPv6 direct UDP only.
Checksums are preserved, not verified. SRV/TXT DNS-SD interpretation and
service relationships remain Phase 1M-C. Classic DNS UDP/53 is unchanged.

```bash
python -m pytest tests/protocols/test_ipv6.py \
  tests/integration/test_mdns_evidence.py \
  tests/integration/test_mdns_pcap_replay.py \
  tests/cli/test_mdns_cli.py -q
python -m pytest
```

**Local Phase 1M-B acceptance (2026-10-18):** **37/37 focused tests**
passed in 0.27s, and **390/390 full regression tests** passed in 0.32s
on macOS Python 3.14.6. Both private Spotify PCAPNG files replayed
successfully, matching the independent mDNS reference counts exactly:
**115 observations (IPv4=50, IPv6=65; 76 queries/39 responses)** and
**215 observations (IPv4=119, IPv6=96; 109 queries/106 responses)**,
with **zero decode errors**. **Live passive capture also passed** on both `en0` and `en5`,
each with 40 observed UDP/5353 packets and **zero decode errors**.
Wi-Fi: IPv4=23, IPv6=17, 16 queries / 24 responses.
Ethernet: IPv4=19, IPv6=21, 27 queries / 13 responses.
An operator-controlled application relaunch on a separate Mac coincided
with IPv4/IPv6 mDNS Spotify Connect searches and advertisements from
two network endpoints. This is discovery evidence, not proven playback
transfer or process attribution. [PR #28](https://github.com/n2bxl/novxis/pull/28)
was squash-merged as `69e65a8`. No separately reported post-merge
full-suite run is claimed in this acceptance record.

See [Phase 1M-B implementation and real-capture acceptance notes](
docs/implementation/2026-10-18-mdns-dual-stack-observation.md).


## Phase 1M-C: Native DNS-SD Service Evidence (Under Review)

The third mDNS vertical slice uses **network-native service names**
rather than an OSINT/application-brand dictionary. With `--services`,
NOVXIS renders opt-in, per-response DNS-SD evidence:

```text
_service._tcp.local     (PTR owner / observed service type)
  → Instance._service._tcp.local  (PTR target / instance)
  → host.local:4070    (same-response SRV target and port)
  → 192.0.2.25         (same-response A or AAAA address claim)
```

These are *advertised relationships*, not verified reachability,
process identity or physical links. The source packet's sender address
remains distinct from the SRV target. Query-side known-answer records
never produce service advertisements. Unmatched PTRs remain partial.

```bash
python -m novxis.cli.mdns_replay "/path/to/private.pcapng" --services
python -m novxis.cli.mdns_replay "/path/to/private.pcapng" --services --summary-only
sudo .venv/bin/python -m novxis.cli.mdns_events en5 --services --count 40 --timeout 60
```

SRV target names are decoded with DNS message-relative compression;
TXT strings remain length-delimited **raw bytes** without fingerprint
lookups or assumed encoding. DNS-SD PTR, SRV, TXT and A/AAAA records
retain independent TTL and class/section/source provenance. Service
associations in this slice are scoped to **one response message**,
not inferred from later packets. Subtype PTR relationships, cross-message
state, grouping and device fusion remain later work.

```bash
python -m pytest tests/protocols/test_dnssd.py \
  tests/views/test_mdns_services.py \
  tests/cli/test_dnssd_cli.py -q
python -m pytest
```

**Real private-PCAPNG replay accepted (2026-10-18):** Both captures
replayed successfully in `--services` mode: **30 and 87 DNS-SD PTR
advertisement observations**, **zero decode errors**. The detailed second
capture contains **five native service types and seven distinct service
instance names**, despite 87 repeated observations. NOVXIS preserved
partial advertisements and two TTL=0 goodbye candidates without
inventing service targets or offline-device status.

**Phase 1M-C automated acceptance passed (2026-10-18):**
**32/32 focused tests** in **0.21s** and **422/422 full regression tests**
in **0.32s** on macOS Python 3.14.6, with no observed regressions.
Offline real-PCAPNG service projection also passed (30 + 87 DNS-SD PTR
observations, zero errors). Phase 1M-C was squash-merged as
`c590908` in PR #29.

**Future idea, not implemented:** Optional lexical-affinity display hints
may compare tokens and character prefixes within *raw service types*
(e.g., `_googlecast._tcp.local` / `_googlerpc._tcp.local`).
These guesses must never merge canonical service identities, endpoint
addresses, or records; full native service names remain authoritative
presentation evidence. See the
[Phase 1M-C acceptance and lexical-affinity design note](
docs/implementation/2026-10-18-mdns-dnssd-service-evidence.md).


## Phase 1M-D-A: Bounded DNS-SD Service Evidence State (Under Review)

The prior phases decoded mDNS and DNS-SD service advertisements, including
native names like `_spotify-connect._tcp.local`. This slice groups
*repeated advertisement observations* into bounded, time-aware service
instance evidence without inventing physical-device identities.

```text
Raw PTR owner/instance + source interface  (canonical service key)
  → latest typed PTR, SRV, TXT, A, AAAA observations
  → independent per-record TTL freshness at capture time
  → an immutable service-instance snapshot, with source provenance
```

Repeated IPv4/IPv6 advertisements with the **same native service type
and instance on one capture interface** accumulate one observation
count. Independent interfaces remain separate. A TTL=0 PTR is a
*goodbye candidate*, not proof of an offline device. A long-lived PTR
does not extend the freshness of a shorter-lived SRV/target or IP
address claim.

**Offline replay of local private PCAPNG files:**

```bash
python -m novxis.cli.mdns_state_replay "$HOME/Documents/spotify 2.pcapng"
python -m novxis.cli.mdns_state_replay "$HOME/Documents/spotify 2.pcapng" --after 200
python -m novxis.cli.mdns_state_replay "$HOME/Documents/spotify 2.pcapng" --after 5000
```

`--after` takes a finite number of seconds *after the capture's last
frame timestamp*, not after the current clock. `--limit` controls
display volume; `--max-instances`, `--max-records-per-instance`,
and `--max-history` bound retention.

```bash
python -m pytest tests/state/test_mdns_service_state.py \
  tests/cli/test_mdns_state_replay_cli.py \
  tests/presentation/test_dns_names.py -q
python -m pytest
```

**Real state replay validated (2026-10-18):** On the second
private Spotify capture, **1,188 frames / 215 mDNS messages** produced
**87 PTR observations consolidated into seven retained service
instances**, with **zero decode errors**. At capture end,
six instances had fresh PTR evidence; at **+200s**, only two did,
and one longer-lived service PTR had already outlasted its SRV
target evidence. TTL=0 candidates and incomplete Companion Link
advertisements remained historical or partial evidence—not device
offline verdicts.

**Automated acceptance passed (2026-10-18):** **36/36 focused tests**
in **0.07s** and **458/458 full regression tests** in **0.32s** on
macOS, Python 3.14.6. Both suites include the presentation-only
DNS-name formatting changes and the service-state test rename.

**Presentation improvement validated on the private PCAPNG replay:**
Spaces in DNS-SD instance names now render naturally, using quotes
around values containing spaces. The raw `DNSName.text` escaped
representation, canonical identifiers and record matching are unchanged.
Ambiguous or unsafe bytes remain escaped. Retested replay retained
**87 PTR observations → seven instances; six fresh PTRs; zero errors**.

Only per-message PTR-backed projections are aggregated; standalone
SRV/TXT/A/AAAA responses are *not yet* safely reconciled across
packets. Full Bonjour cache-flush and subtype semantics are future
work. Lexical service-name similarity remains an optional future
presentation hint, **not** an identity-scoring engine.

See [Phase 1M-D-A design and acceptance notes](
docs/implementation/2026-10-18-mdns-service-state-aggregation.md).


## Phase 1M-D-B: Opt-In Cross-Message DNS-SD Reconstruction (Under Review)

DNS-SD records may be advertised in **separate response packets**.
The established Phase 1M-D-A replay remains the default. Add
`--reconcile` to use a bounded overlay that relates standalone
SRV/TXT/A/AAAA claims to previously observed service instances:

```text
fresh PTR  → native DNS-SD service instance name
fresh SRV  → same instance owner → target hostname and port
fresh A/AAAA → exact SRV target hostname → address claim
TXT        → same instance owner → raw metadata evidence
```

These relationships are scoped to one capture interface and evaluated
at an explicit capture timestamp. Each original record retains its
own source packet, TTL and wire bytes. Orphan responses can precede
the PTR as long as their record TTL remains fresh at snapshot time.

```bash
# Keep the original, validated behavior:
python -m novxis.cli.mdns_state_replay "$HOME/Documents/spotify 2.pcapng"

# Explicitly enable cross-response name matching:
python -m novxis.cli.mdns_state_replay "$HOME/Documents/spotify 2.pcapng" --reconcile
python -m novxis.cli.mdns_state_replay "$HOME/Documents/spotify 2.pcapng" --reconcile --after 200

# Validate branch:
python -m pytest tests/state/test_mdns_reconciliation.py \
  tests/cli/test_mdns_reconciliation_cli.py -q
python -m pytest
```

The optional display adds `separately-observed-RRs-linked=N` for
each service instance. This is **not** a device count, application
identification, vendor label or authenticated ownership claim.
An A/AAAA record joins only through a fresh exact SRV target name,
not via packet sender IP, name resemblance or keyword scoring.

Bounded orphan evidence (`--max-unassociated`, default 2048) is drawn
only from response packets with **no PTR-backed service projection**.
Mixed-response extraction, mDNS cache-flush grace behavior, service
subtypes, and active verification are deferred.

**Phase 1M-D-B initial Mac acceptance (2026-10-18):**
**20/20 focused tests** passed in **0.08s** and **478/478 full tests**
passed in **0.36s** on macOS Python 3.14.6. Replaying the second
private Spotify capture with and without `--reconcile` retained the same
**87 PTR observations, seven instances and zero decode errors**.
Reconciliation buffered **19 standalone response RRs** and linked
**four fresh additional RR values across three native service
instances**: a Companion Link TXT, a Google Cast A, and Google RPC
SRV+A. A later standalone A observation refreshed address evidence
independently of SRV TTL.

**Remaining acceptance:** Validate `--reconcile --after 200` and
inspect one newly linked standalone RR in the original capture
to confirm its response owner/source and TTL in Wireshark. This
has not yet been reported. PR review/merge pending; no private
endpoint identifiers committed.

See [Phase 1M-D-B implementation and limits](
docs/implementation/2026-10-18-mdns-cross-message-reconciliation.md).
