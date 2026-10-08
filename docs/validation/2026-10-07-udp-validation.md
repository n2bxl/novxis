# UDP Validation: Initial Capture and Controlled Exchange Plan

**Date:** 2026-10-07  
**Status:** Passive live observation and end-to-end automated testing passed; controlled two-Mac exchange and independent packet comparison pending.

## Observed evidence from the first UDP slice (PR #14)

On macOS, with the NOVXIS Python 3.14 virtual environment:

- `pytest tests/test_udp.py -v`: **12 passed**
- Full `pytest`: **115 passed**
- `sudo .venv/bin/python -m novxis.cli.udp_events en0 --count 10 --timeout 30`: **10 UDPDatagramObserved events**
- All ten records had **zero bytes of trailing UDP evidence**.
- Captured traffic included both directions across matching IPv4 address/port pairs and a directed-broadcast candidate.
- Representative UDP length/payload-length pairs: **49/41**, **40/32**, and **52/44** bytes.
- No comparison against independently decoded packets or known controlled payloads has yet occurred.
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
- These passing tests **do not** substitute for independently verified live payload bytes, which remain pending.

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
  --port 49000 --count 2 --timeout 45
```

The filter applies to either source or destination port 49000. If no traffic is captured, first confirm both the sender interface and the receiver are on the expected network.

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

## Exit criteria

- New end-to-end tests and full suite pass.
- The filtered CLI accurately captures controlled UDP traffic.
- At least one generated datagram's bytes/lengths match an independent decoder; preferably both request and response.
- Documentation clearly distinguishes observations from inferred behavior.

Out of scope: checksum verification, IP fragment reassembly, application-protocol inference, connection/session correlation, and GUI rendering.
