# DNS Phase 1B: UDP Observation and Live Validation

**Date:** 2026-10-11  
**Status:** Live validated and merged via [PR #21](https://github.com/n2bxl/novxis/pull/21) (`1695814`).

## Implementation

```text
Scapy live capture / PCAP replay
             ↓
        CapturedFrame
             ↓
       Ethernet → IPv4
             ↓
     UDPEventPipeline
             ↓
     UDP source or destination port 53?
             ↓ yes
        parse_dns()
             ↓
     DNSMessageObserved
             ↓
        Console output
```

The DNS event model preserves the full `UDPDatagramObserved`, which contains
the captured frame, Ethernet header, IPv4 datagram, and UDP datagram. The
message parser retains DNS questions, every record section, raw RDATA and
compression decoding evidence from Phase 1A.

This path follows the existing UDP policy: it does not reassemble fragmented
IPv4 traffic. It only inspects classic DNS UDP port 53. Port 5353 multicast
DNS and DNS-over-TCP require separate future pipelines.

Every emitted `DNSMessageObserved` represents one decoded candidate message.
Responses are **not** matched to requests, answers are **not** verified, and
no name/address bindings are committed to `NetworkState`.

## Synthetic regression testing

```bash
python -m pytest tests/integration/test_dns_evidence.py -q
python -m pytest tests/cli/test_dns_replay_cli.py tests/cli/test_dns_events_cli.py -q
python -m pytest
```

Coverage includes:
- Real synthetic Ethernet/IPv4/UDP/DNS query and response bytes
- Captured-frame identity and interface/timestamp provenance
- A answer and TTL display, decoded compression pointer
- DNS UDP source/destination port selection (including port 53 to port 53)
- mDNS and unrelated ports ignored
- TCP, ARP, and both types of fragmented IPv4 skipped
- Malformed port-53 payloads surfaced as errors
- CLI provider parameters, counters, error reporting and cancellation

## Local acceptance results (2026-10-11)

On an M5 MacBook Air, macOS/Darwin, Python 3.14.6, pytest 9.1.1:

- **25/25 focused Phase 1B tests passed in 0.23s.**
- **236/236 full regression tests passed in 0.24s.**
- The previous merged Phase 1A baseline was 211 tests; no regression failures appeared.

These are automated acceptance results, not proof of live traffic coverage.

Initial wrong-interface run:

```text
sudo .venv/bin/python -m novxis.cli.dns_events en0 --count 20 --timeout 60
Capture complete. DNS observations: 0; decode errors: 0
```

This run did not yield a DNS observation. The current CLI reports successful
observations and parsing errors, but **not a raw BPF-matching packet counter**,
so the output alone does not prove no packets were captured. No full
packet-by-packet tcpdump comparison has yet been supplied. The test operator
also tried nslookup for google.com and 8.8.8.8, but transport path and whether
those lookups happened during the capture remain unverified.

### Targeted follow-up (two terminals)

Confirm egress interface:

```bash
route -n get 8.8.8.8 | grep interface
scutil --dns
```

Capture on that interface, e.g. `en0`, with NOVXIS while issuing a forced
IPv4 classic DNS UDP query in a second terminal:

```bash
dig -4 @8.8.8.8 example.com A +notcp +tries=1 +time=3
```

If NOVXIS still reports zero observations, repeat the experiment with
`sudo tcpdump -ni en0 'udp port 53'` and the same `dig` command.
This distinguishes no visible matching traffic from an IPv4 parsing/capture
problem. Do not assume that egress must be on en0 in VPN or multi-interface
setups.

Remember the BPF expression `udp port 53` can match IPv6 traffic but the
present decoder pipeline handles only Ethernet/IPv4; such traffic is skipped
without creating a DNS observation. TCP/53, mDNS/5353, DoH and DoT are outside
Phase 1B's capture/interpretation scope. Explicit `dig -4` fixes the query
transport address family and selects UDP by default in this case.

Never publish unredacted DNS PCAPs, private internal DNS names or resolver
credentials into the public repository.

## Finite passive capture (macOS)

Confirm the active/default interface before capturing:

```bash
route -n get default | grep interface
```

Capture IPv4 UDP port-53 messages (use the correct actual interface in place
of `en0`):

```bash
sudo .venv/bin/python -m novxis.cli.dns_events en0 --count 20 --timeout 60
```

In another terminal, an **explicit user-controlled** test query to your
configured resolver can create evidence. For example, after selecting an
authorized local resolver's address:

```bash
dig @YOUR_AUTHORIZED_RESOLVER example.org A
```

The capture process itself sends no probes. A normal UDP DNS query is likely
to produce a query and response when both packets traverse the observed
interface, but cache behavior, split DNS, local stub resolvers, encrypted DNS,
or capture visibility may lead to no traffic. A zero-observation capture is
not inherently a decoder failure. The bounded `--count` argument counts
matching port-53 frames, **not** only successfully decoded DNS observations.

A privacy-sensitive PCAP should remain local. Record redacted command output
rather than adding raw capture files containing real hostnames or query
history to the public NOVXIS repository.

## Offline replay

```bash
python -m novxis.cli.dns_replay /path/to/private-dns-capture.pcapng
```

The replay command uses the same `DNSEventPipeline` and preserves per-frame
timestamps and capture interface labels when present. `--interface-label`
provides a fallback for classic PCAP.

## Acceptance checklist

- [x] Focused tests pass
- [x] Full tests pass
- [x] Live IPv4 UDP query and response recognized
- [x] DNS IDs, questions, response codes and displayed A answers cross-checked against nslookup/dig (PCAP byte-level comparison optional)
- [x] Observations remain uncorrelated (as designed); no automated pair matching
- [ ] No private capture material committed
- [x] Review and squash-merge completed; later `main` regression tests passed.

## Next: DNS Phase 1C

Introduce conservative DNS query-response correlation using interface, IPv4
endpoints and UDP ports (reversed), transaction ID, question identity and
time window. Keep unmatched responses and ambiguous duplicates separate.
Name/address evidence and TTL aging belong to a later state slice.
## Live acceptance run: 2026-10-11 14:45–14:46 CDT

**Status:** Real traffic successfully decoded on the correct capture interface,
`en5`. Previous zero-observation run on `en0` resulted from selecting the
wrong interface, not a demonstrated DNS parser or BPF defect.

Command:

```bash
sudo .venv/bin/python -m novxis.cli.dns_events en5 --count 20 --timeout 60
```

**Observed:** 8 `DNSMessageObserved` events (4 queries and 4 responses),
0 decoding errors. The four transaction IDs, ports and source/destination
address reversals are consistent with four pairs; this is **human analysis**,
not automated exchange correlation (Phase 1C).

| Time (CDT) | DNS ID | Query / observed outcome | Response interval |
|---|---|---|---|
| 14:45:45 | `0xabd2` | PTR `8.8.8.8.in-addr.arpa` → `dns.google`, TTL 82612s | ~5 ms |
| 14:45:47 | `0xb3de` | A `google.com` → six A records, response TTL 204s | ~5 ms |
| 14:46:01 | `0x82fb` | A `google.com` → six A records, response TTL 3s | ~5 ms |
| 14:46:05 | `0xe05e` | A `8.8.8.8` → RCODE 3 / NXDOMAIN, no answers | ~5 ms |

Observed client address on a private `192.168.4.0/22` LAN, with an
external resolver on UDP port 53, over interface `en5`. The exact endpoint
addresses are omitted from this public validation note to minimize disclosure
of personal network context. These are observed network-layer endpoints,
not assertions of physical host ownership.

### Cross-check against user-side DNS command output

- `nslookup 8.8.8.8` shows reverse PTR `dns.google`, consistent with
  transaction `0xabd2`.
- `nslookup google.com` lists six A records, consistent with transaction
  `0xb3de` (four printed explicitly by NOVXIS; its console says
  `other_answers=2`).
- `dig google.com` reports decimal DNS ID **33531** (= `0x82fb`),
  six A records, TTL **3s**, EDNS OPT additional record, and a **5 ms**
  query time. Its six addresses agree with the four shown explicitly and
  the two remaining answer count in NOVXIS.
- `dig 8.8.8.8` reports decimal DNS ID **57438** (= `0xe05e`),
  **NXDOMAIN**, a single SOA authority record and EDNS OPT additional
  record, and **5 ms** query time.
- `dig 8.8.8.8` asks for an A record for the literal DNS name
  `8.8.8.8`; it is **not** the same operation as the reverse lookup
  performed by `nslookup 8.8.8.8`. `dig -x 8.8.8.8` is the
  corresponding reverse-DNS operation.

Both query and response traversed the chosen interface and were decoded
successfully with consistent transaction IDs, endpoint reversal, counts,
types, responses and timestamps. The `dig`/`nslookup` output provides an
independent application-level cross-check; there was **no separate packet
byte-by-byte Wireshark or PCAP comparison** in this run.

The live capture proves this protocol observation path works for the tested
IPv4 UDP port-53 traffic. It does **not** establish DNS response authenticity,
query/response correlation inside NOVXIS, durable name/address state,
DNS-over-TCP, mDNS or DNS encryption support.

### Remaining work

- [x] Focused Phase 1B tests (25 passed)
- [x] Full regression suite (236 passed)
- [x] Live IPv4 UDP port-53 query and response observed on `en5`
- [x] Command-side `dig`/`nslookup` cross-check for IDs, questions,
      response values, counts and response codes
- [ ] Optional independent packet-level Wireshark/PCAP dissection
- [x] Squash-merge PR #21; later merged `main` passed 335/335 tests (2026-10-17).

Historical observability improvement idea: track BPF-matching
captured frames separately from successfully decoded observations and errors,
to make wrong-interface or unsupported-protocol tests easier to diagnose.
