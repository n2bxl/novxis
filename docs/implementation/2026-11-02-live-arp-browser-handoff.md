# Phase 1N-C: Live ARP Handoff to the Local 2D Debugger

Date: 2026-11-02
Status: Feature branch; M5 tests and live Safari acceptance pending.
Baseline: Phase 1N-B was validated with 501 passing tests, ADR 0001 is merged.

## Goal

Bridge live ARP sender-binding observations to the permanent local 2D
debugging explorer. This is a bounded, explicitly launched capture session,
not an unattended daemon, remote service, or physical network inventory.

## Process and privilege separation

The left (possibly privileged) helper runs ScapyCaptureProvider and
ARPStatePipeline, then sends only normalized ARP binding facts as NDJSON
on local stdout. The right process reads the pipe **without** root
privileges and hosts the local read-only 2D browser.

From the activated virtual environment, on the M5 Mac:

    sudo .venv/bin/python -m novxis.cli.arp_live_stream en0 --count 2000 --timeout 120 \
      | .venv/bin/python -m novxis.cli.web_live

Use en0 for Wi-Fi or en5 for Ethernet when authorized and actually carrying
the observed traffic. Do not put sudo in front of the entire pipeline.
The right-hand browser process must run under the ordinary user.

The capture helper still decodes ARP while privileged; it is not yet a
least-privilege production capture service. A restricted capture agent,
secure IPC and packaged desktop behavior are deferred to later work.

Open http://127.0.0.1:8765/ in Safari. The browser polls once per second.
Press Ctrl+C in the terminal to end the two-process pipeline. Capture also
ends after 120 seconds or 2,000 captured ARP frames by default; its final
snapshot remains visible until the web server is stopped.

## Flow and data model

    Authorized interface (en0/en5)
              |
       ScapyCaptureProvider
              |
         ARPStatePipeline
              |
        scoped ARPBinding
              |
     bounded NDJSON over local pipe
              |
       LiveARPGraphState
         (lock + cap)
              |
    project_arp_address_map
              |
     same versioned graph schema
              |
    localhost-only HTTP /api/graph
              |
       2D canvas (polling)

The stream includes interface, ARP type codes, sender protocol and hardware
bytes, first/last capture-clock timestamps and observation counts. It does
not transport raw captured frames, decoded payloads, or private PCAP files.

The immutable graph projection is reused from offline replay. An ARP sender
claim is not verified physical identity, direct link or confirmed liveness.
ARP probes with zero protocol sender addresses do not produce bindings.

## Operational safety and limitations

- The web server binds only to 127.0.0.1 and preserves existing HTTP Host,
  Content Security Policy and no-store protections.
- Browser GET requests cannot start/stop capture or grant privileges.
- Producer defaults to 2,000 frames or 120 seconds; upper bounds 100,000
  frames and 3,600 seconds.
- Receiver bounds the current map to 256 protocol binding keys by default.
  Exceeding it marks the graph **truncated** rather than quietly claiming
  a complete view.
- Invalid or oversized line records are rejected; errors are surfaced to the
  browser as metadata instead of becoming network evidence.
- Snapshots are protected by a lock and include a monotonically increasing
  revision, so the browser need only rerender when data changes.
- User pan/zoom and selected address survive live graph updates.
- Rate pressure can cause capture loss. A quiet or missing node cannot be
  presumed offline. No automatic TTL aging exists yet.
- There is no external network server, WebSocket, remote login, active
  network probe or persistent capture storage.

## Acceptance on the M5

1. Fetch the feature branch, activate .venv and run focused and full tests.
2. With an authorized interface, start the two-process terminal pipeline.
3. Open Safari at http://127.0.0.1:8765/ as the normal user.
4. Confirm live interface/status and increasing binding updates, including
   at least one new/refreshed address when traffic occurs.
5. Confirm live graph node and claim inspection, stable camera/selection
   during updates and no native text highlighting while dragging.
6. After capture ends, status becomes ended and the last graph persists.
7. Confirm the right-hand HTTP process is not running under sudo.
8. Run offline preview again to ensure unchanged fixture behavior.

## Initial M5 live-browser validation (2026-11-02)

The developer supplied a screenshot of the live local Safari interface
after an authorized capture on **en5**. The web UI reports:

- Mode: `LIVE ARP`
- Capture interface: `en5`
- Terminal state: `ended`
- **17 typed address nodes**
- **9 observed ARP sender claims**
- **69 binding updates**

The developer also reported **watching the graph populate during the
capture**, which establishes first-hand manual validation of the
live capture-to-2D-graph path. The browser retained a navigable evidence
map at the end of the capture. The interface screenshot does not
independently confirm capture-helper exit code, transport loss, absence of
errors, process privilege boundaries, or the automated test suite.

The count of address nodes **does not indicate 17 devices**. Typed protocol
and hardware nodes can overlap in their claim associations. Do not
publish private interface captures, raw local MAC addresses, or home
network addressing in repository documentation or fixtures.

**Pending:** focused `python -m pytest tests/web -q`, full
`python -m pytest` results from the feature branch; final
start/stop, privilege, and in-flight inspector/camera checks.
Keep the implementation PR in draft until that acceptance is complete.

## Deferred

No direct in-browser capture controls, unrestricted continuous sessions,
live ICMP/DNS/DHCP/mDNS fusion, graph aging, persistent inventory, physical
network wiring reconstruction, production-grade privilege isolation, 3D,
or desktop packaging in this slice.
