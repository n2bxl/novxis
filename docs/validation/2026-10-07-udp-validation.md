# UDP Validation: Initial Capture and Controlled Exchange Plan

**Date:** 2026-10-07  
**Status:** Automated testing, controlled two-Mac UDP exchange, and independent PCAPNG byte-level comparison passed. UDP checksum verification and IPv4 fragment reassembly remain out of scope.

## Observed evidence from the first UDP slice (PR #14)

On macOS, with the NOVXIS Python 3.14 virtual environment:

- `pytest tests/test_udp.py -v`: **12 passed**
- Full `pytest`: **115 passed**
- `sudo .venv/bin/python -m novxis.cli.udp_events en0 --count 10 --timeout 30`: **10 UDPDatagramObserved events**
- All ten records had **zero bytes of trailing UDP evidence**.
- Captured traffic included both directions across matching IPv4 address/port pairs and a directed-broadcast candidate.
- Representative UDP length/payload-length pairs: **49/41**, **40/32**, and **52/44** bytes.
- Initial passive capture was not compared against independently decoded packets or known controlled payloads. A subsequent controlled capture is documented below.
- UDP checksums were displayed, not verified. A zero trailing-byte count is not a substitute for checksum validation.

Only generalized packet observations are recorded here. Internal network addresses and public peer addresses from the live capture are omitted.

## Integration-test acceptance

PR #15 adds byte-level integration tests that do not mock IPv4:

```text
CapturedFrame → EthernetFrame → IPv4Datagram → UDPDatagramObserved
```

Verify parsed ports, byte lengths, bounded payload, checksum value, preservation of original evidence, layer-specific trailing bytes, and separate request/reply observations. Verify non-UDP traffic and both types of fragments are skipped. Verify invalid UDP lengths raise a parser error.

```bash
git fetch origin
git switch ai/phase1-udp-end-to-end-validation-2026-10-07
python -m pip install -e ".[dev]"
pytest tests/integration/test_udp_evidence.py tests/cli/test_udp_events_cli.py -v
pytest
```

**Executed on macOS with Python 3.14.6 and pytest 9.1.1 on October 7, 2026:**

- Targeted suite (`tests/integration/test_udp_evidence.py` and `tests/cli/test_udp_events_cli.py`): **14 passed in 0.21s**.
- Full regression suite (`pytest`): **129 passed in 0.21s**.
- Failures: **0**.
- The suite confirms Ethernet-to-IPv4-to-UDP decoding, preserved evidence, no inferred sessions, fragment filtering, malformed-length rejection, and CLI filter input handling.
- These passing tests **do not** substitute for independent live packet decoding. A controlled application-level request/reply exchange and NOVXIS packet observations were subsequently completed, as recorded below.

## Controlled UDP exchange on two Macs

The primary Mac runs NOVXIS on `en0`; a second Mac on the same LAN listens on UDP port **49000**. Confirm the real active network interface with `route -n get default | grep interface`. Running everything on `127.0.0.1` is **not** equivalent to this Ethernet experiment because current NOVXIS decoding expects Ethernet frames and macOS loopback uses a different link-layer format.

**1. On the receiving Mac:** start a Python UDP listener in Terminal:

```bash
python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind(("0.0.0.0", 49000))
    s.settimeout(45)
    print("UDP receiver listening on port 49000", flush=True)
    data, sender = s.recvfrom(4096)
    print(f"RX from {sender}: {data!r} ({len(data)} bytes)", flush=True)
    s.sendto(b"NOVXIS-ACK", sender)
PY
```

Find the receiver's actual LAN IPv4 address (for example, using System Settings or `ipconfig getifaddr en0`, substituting its Wi-Fi interface if needed). Ensure macOS firewall settings permit the receiving Python process to accept incoming packets.

**2. On the primary Mac, Terminal A:** start the filtered live capture *before* sending:

```bash
sudo .venv/bin/python -m novxis.cli.udp_events en0 \
  --port 49000 --count 10 --timeout 90
```

The filter applies to either source or destination port 49000. Allow more than two matching packets because an earlier request or repeated test can exhaust a two-packet capture limit before the reply arrives. If no traffic is captured, first confirm both the sender interface and the receiver are on the expected network.

**3. On the primary Mac, Terminal B:** replace `RECEIVER_IP` with the actual LAN IP of the receiving Mac, then send a known payload:

```bash
python3 - <<'PY'
import socket

receiver = ("RECEIVER_IP", 49000)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(5)
    s.sendto(b"NOVXIS-UDP-CONTROLLED", receiver)
    try:
        data, sender = s.recvfrom(4096)
        print(f"RX from {sender}: {data!r} ({len(data)} bytes)")
    except socket.timeout:
        print("No reply received; capture the outbound UDP evidence anyway.")
PY
```

**Expected if both datagrams are captured:**

- First observation: destination port 49000, UDP length **29** bytes, payload **21** bytes.
- Second observation: source port 49000, UDP length **18** bytes, payload **10** bytes (`NOVXIS-ACK`).
- Matching reversed IP address/port tuples. The sender's ephemeral UDP port will vary.
- Checksums are visible but their validity has **not** been determined.
- Both should have zero trailing UDP bytes.

UDP offers no guarantee that the acknowledgment arrives. Failure to receive a reply is not necessarily a parser failure. Check capture interface, receiver firewall, routing, and whether the second machine received the request.

**4. Independently compare packets:** use Wireshark with display filter `udp.port == 49000` or, in another terminal:

```bash
sudo tcpdump -i en0 -nn -vv -X 'udp port 49000'
```

Compare source/destination ports, UDP length, packet direction, and exact payload bytes. Record any disagreements rather than altering NOVXIS output to fit an assumed result.

## Controlled LAN exchange results (2026-10-07, 19:14 CDT)

**Outcome: PASS for two-way application delivery and matching NOVXIS transport-header observations.**

The user's M5 MacBook Air sent `b"NOVXIS-UDP-CONTROLLED"` to the old MacBook Air on UDP port 49000. The old MacBook application's receiver printed the exact 21-byte payload and sent `b"NOVXIS-ACK"` back to the originating ephemeral UDP port. The M5 sender printed the exact 10-byte acknowledgment received from the old MacBook.

NOVXIS captured two datagrams on the M5 MacBook's `en0` interface using:

```bash
sudo .venv/bin/python -m novxis.cli.udp_events en0 \
  --port 49000 --count 2 --timeout 90
```

| Observation (local CDT) | Direction | UDP ports (src → dst) | UDP length | Payload length | Checksum reported | UDP trailing |
|---|---|---|---:|---:|---|---:|
| 19:14:21.445 | M5 → Old Mac | 49431 → 49000 | 29 | 21 | `0xe557` | 0 |
| 19:14:21.662 | Old Mac → M5 | 49000 → 49431 | 18 | 10 | `0x96fc` | 0 |

Corresponding IPv4 endpoints: M5 `192.168.4.91`, Old Mac `192.168.4.26`, reversed between request and reply. The sender's ephemeral port was **49431** for this particular run; this should not be treated as fixed in future experiments.

**What this supports:**

- Confirmed actual application delivery in both directions, with exact expected payloads printed by the Python receiver/sender processes.
- NOVXIS decoded the same request/reply directions, ports, and UDP payload lengths (21+8=29, 10+8=18), with no trailing UDP bytes.
- The CLI's `--port 49000` filter captured the intended datagrams and stopped at `--count 2`.
- The request and reply were kept as **two independent UDP observations**, not interpreted as a transport-layer connection.

**What is not yet proved:** NOVXIS's console prints payload length, not payload bytes. Agreement with the endpoints therefore demonstrates consistent lengths and metadata, **not a byte-for-byte independent verification of the captured payload content**. There is not yet a Wireshark/tcpdump packet-by-packet comparison. Reported UDP checksum fields were not independently validated.

The timing gap between capture timestamps should not be reported as a UDP-layer RTT because processing and reply generation in the Python receiver contribute to the interval.

## Independent PCAPNG verification (2026-10-07, 19:18 CDT)

**Outcome: PASS for raw UDP header, payload-length, checksum-field, timestamp, and payload-byte comparison.**

The user supplied `UDP test 20261007.pcapng`, captured in Wireshark on the M5 MacBook's `en0` interface. The file was inspected using an independent PCAPNG/IPv4/UDP byte decoder. It contains **218 packet records** (Ethernet link type 1, microsecond timestamps), of which **33** were IPv4 UDP packets and **three** used UDP port 49000. The original full capture is **not committed to this repository**, because it contains unrelated network traffic.

| PCAP packet | Local time (CDT) | Direction | Ports (source → destination) | UDP length | Payload length | UDP checksum field | Trailing |
|---|---|---|---|---:|---:|---|---:|
| 122 | 19:18:20.376 | M5 → Intel Mac | 59724 → 49000 | 29 | 21 | `0xbd22` | 0 |
| 185 | 19:18:28.507 | M5 → Intel Mac | 63665 → 49000 | 29 | 21 | `0xadbd` | 0 |
| 188 | 19:18:28.650 | Intel Mac → M5 | 49000 → 63665 | 18 | 10 | `0x5f62` | 0 |

The two outbound UDP payloads independently decode as `b"NOVXIS-UDP-CONTROLLED"` (21 bytes, hex `4e4f565849532d5544502d434f4e54524f4c4c4544`). The inbound packet independently decodes as `b"NOVXIS-ACK"` (10 bytes, hex `4e4f565849532d41434b`).

**Comparison with NOVXIS:** both console lines from the 19:18 capture matched PCAP packets 122 and 185 in time (millisecond precision), port tuple, UDP length, payload length, checksum *field*, and zero trailing bytes. The Intel Mac's Python receiver specifically printed a datagram from sender port 63665, matching packet 185, and the M5 sender printed the expected ACK. The PCAPNG independently confirms the payload byte sequences of both requests and the acknowledgment.

**Why NOVXIS did not print packet 188:** the console was started with `--count 2` and finished after the two outbound packets. Packet 188 arrived approximately 143 milliseconds after packet 185, after the packet limit was reached. This is expected capture-limit behavior, not UDP parsing failure. Future captures should use a larger `--count` or `--count 0` with a finite timeout.

NOVXIS prints payload *length*, not raw payload bytes. Independently decoded bytes agree with the sending/receiving Python applications, while checksum fields were compared by value only and were **not mathematically validated** with the IPv4 pseudoheader. The gap between timestamps is not a UDP-layer RTT because the application and OS contribute to it.

## Exit criteria

- New end-to-end tests and full suite pass.
- The filtered CLI accurately captures controlled UDP traffic.
- Independent PCAPNG decoding confirms both outbound packets and the inbound ACK, including the exact payload bytes. **Passed**.
- Documentation clearly distinguishes observations from inferred behavior.

Out of scope: checksum verification, IP fragment reassembly, application-protocol inference, connection/session correlation, and GUI rendering.
