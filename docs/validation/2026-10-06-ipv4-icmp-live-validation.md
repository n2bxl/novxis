# IPv4 and ICMP Live Validation — 2026-10-06

## Purpose

Record the live acceptance evidence for the reusable IPv4 Layer 3 boundary,
the ICMP Echo request/reply vertical slice, and the follow-on ICMP error slice.

This note records what was actually observed on live traffic. It is not a claim
that every IPv4 or ICMP behavior is implemented.

## Test Environment

- Platform: macOS
- Python: 3.14.6
- Capture provider: Scapy through `ScapyCaptureProvider`
- Active routed test interface for ICMP: `en5` (Ethernet)
- Earlier IPv4 sampling also observed traffic on `en0`
- Regression suite after ICMP Echo implementation: **89 passed in 0.23s**
- Regression suite after ICMP error/quoted-IPv4 implementation: **102 passed in 0.24s**

The initial ICMP attempt on `en0` captured no ICMP frames. This was not a
decoder failure. The Mac was using Ethernet for the generated ping traffic.
Switching capture to `en5` produced the expected six ICMP frames.

This reinforces a CLI/testing rule: capture on the interface that actually owns
the route for the traffic being tested.

## IPv4 Live Validation

The IPv4 CLI successfully decoded live TCP and UDP traffic including local
unicast, internet unicast, and IPv4 multicast.

Representative observations included:

- IPv4 protocol 6 (TCP) and 17 (UDP)
- TTL values including 1, 55, 64, and 118
- DSCP values including 0 and 18
- ECN values including 0 and 2
- DF set and unset
- Zero fragment offset in the observed sample
- Zero IPv4 options in the observed sample
- Zero unexpected trailing bytes

The layer boundaries agreed exactly with captured frame lengths. Examples:

```text
Ethernet frame: 74 bytes
IPv4 total:     60 bytes
Ethernet hdr:   14 bytes
60 + 14 = 74
```

and:

```text
Ethernet frame: 176 bytes
IPv4 total:     162 bytes
Ethernet hdr:    14 bytes
162 + 14 = 176
```

A multicast packet provided a useful cross-layer check:

```text
Ethernet dst: 01:00:5e:7f:ff:fa
IPv4 dst:     239.255.255.250
TTL:          1
Protocol:     UDP
```

The Ethernet multicast destination corresponds to the observed IPv4 multicast
destination, supporting the correctness of the Layer 2 → Layer 3 decode path.

IPv4 options and live fragmented datagrams were not observed during this test.
Their parser behavior remains covered by unit tests.

## Raw ICMP Capture Validation

With NOVXIS listening on `en5`:

```bash
sudo .venv/bin/novxis-capture en5 \
  --filter icmp \
  --count 6 \
  --timeout 30
```

and a concurrent:

```bash
ping -c 3 1.1.1.1
```

the capture provider observed six 98-byte frames:

```text
3 Echo Requests
3 Echo Replies
```

The 98-byte frame size is consistent with:

```text
Ethernet header   14 bytes
IPv4 header       20 bytes
ICMP header        8 bytes
Echo payload      56 bytes
                  --------
Total             98 bytes
```

## ICMP Echo Correlation Validation

The live ICMP event CLI was then run on the same interface:

```bash
sudo .venv/bin/novxis-icmp-events en5 \
  --count 6 \
  --timeout 30
```

A concurrent `ping -c 3 1.1.1.1` generated three complete exchanges.

Observed source and destination:

```text
192.168.4.78 → 1.1.1.1 → 192.168.4.78
```

The Echo identifier remained constant at `0x24af`, while the sequence number
advanced through 0, 1, and 2.

NOVXIS correlation results:

| Sequence | NOVXIS observed RTT |
|---:|---:|
| 0 | 12.972 ms |
| 1 | 13.322 ms |
| 2 | 13.059 ms |

The originating macOS `ping` process reported:

| Sequence | ping RTT |
|---:|---:|
| 0 | 13.324 ms |
| 1 | 13.564 ms |
| 2 | 13.346 ms |

The small difference is expected because NOVXIS measures the interval between
packet capture timestamps, while `ping` measures from its own send/receive
path through the host networking stack.

For that reason, future presentation terminology should prefer **observed RTT**
or **capture-observed RTT** over implying that the value must exactly equal the
originating application's RTT measurement.

Final pipeline status:

```text
Echo Requests observed:          3
Echo Replies observed:           3
Completed Echo exchanges:        3
Pending unmatched Echo Requests: 0
```

## ICMP Error Live Validation

The follow-on ICMP error branch added semantic observations for Destination
Unreachable and Time Exceeded plus a truncation-aware `IPv4DatagramQuote`
model.

### Time Exceeded via traceroute

NOVXIS:

```bash
sudo .venv/bin/novxis-icmp-events en0 \
  --count 10 \
  --timeout 30
```

Traffic generator:

```bash
traceroute -m 4 1.1.1.1
```

Traceroute produced eight successful responses across the first four hops:

```text
hop 1: 3 replies
hop 2: 3 replies
hop 3: 0 replies
hop 4: 2 replies
```

NOVXIS observed exactly eight `ICMPTimeExceededObserved` events. Every one was
Type 11 / Code 0, TTL Exceeded in Transit, and each quoted original IPv4 packet
reported protocol 17 (UDP).

Three quotation shapes were observed:

```text
declared_total=40 available=40 payload_prefix=20 truncated=false
declared_total=40 available=28 payload_prefix=8  truncated=true
declared_total=40 available=68 payload_prefix=20 truncated=false
```

The last form preserves 28 bytes beyond the quoted IPv4 datagram's declared
Total Length. Those bytes remain trailing evidence; this validation does not
claim that they are an ICMP extension until their raw structure is inspected.

### Destination Unreachable via local gateway

NOVXIS:

```bash
sudo .venv/bin/novxis-icmp-events en0 \
  --count 3 \
  --timeout 15
```

Traffic generator:

```bash
traceroute -m 2 192.168.4.1
```

The gateway returned three Type 3 / Code 3 Port Unreachable responses. NOVXIS
normalized all three as `ICMPDestinationUnreachableObserved` and decoded the
quoted original UDP probes:

```text
192.168.4.88 → 192.168.4.1
protocol=17
ttl=1
declared_total=40
available=40
payload_prefix=20
truncated=false
```

This completes live validation of both implemented ICMP error families and
confirms that the quoted IPv4 boundary already preserves real UDP evidence for
the next transport-layer slice.

## Validated Boundary

```text
CapturedFrame
    ↓
EthernetFrame
    ├──────────────► ARP
    │                 ↓
    │              ARP events
    │                 ↓
    │              ARP state
    │
    ▼
IPv4Datagram
    ↓
ICMPMessage
    ├──────────────► Echo observations
    │                 ↓
    │              Echo correlation
    │                 ↓
    │              Observed RTT
    │
    └──────────────► ICMP error observations
                      ↓
                   IPv4DatagramQuote
                      ↓
                   quoted transport evidence
```

This validates the first upper-layer protocol composed on top of NOVXIS-owned
IPv4 evidence rather than Scapy protocol objects.

## Known Limits

- Persistent network state is still ARP-derived only.
- The ICMP parser decodes the common eight-byte prefix generically. Standard
  Echo Request and Echo Reply participate in request/reply correlation; ICMP
  errors are normalized but are not yet correlated back to originating flows.
- ICMP extension structures are not decoded. Bytes beyond a quoted IPv4
  datagram's declared Total Length are preserved as trailing evidence.
- IPv4 header checksums and ICMP checksums are exposed as evidence but are not
  yet validated.
- IPv4 fragment reassembly is not implemented.
- Fragmented IPv4 datagrams are skipped by the ICMP event pipeline.
- Live IPv4 options and fragmentation were not exercised in this validation.

## Acceptance Result

```text
IPv4/ICMP Echo suite  89/89 PASS
ICMP error suite      102/102 PASS
IPv4 live decode       PASS
TCP/UDP boundaries     PASS
Unicast/multicast      PASS
Raw ICMP capture       PASS
Echo Request parsing   PASS
Echo Reply parsing     PASS
Echo correlation       PASS
Observed RTT           PASS
Time Exceeded live     PASS
Port Unreachable live  PASS
Quoted IPv4 evidence   PASS
Quoted UDP protocol    PASS
Unmatched Echo reqs    0
```
