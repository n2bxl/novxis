# NOVXIS

**Network Observation, Visualization, eXploration Interface System**

NOVXIS is an open-source networking education, exploration, visualization, and troubleshooting project focused on making abstract network behavior visually concrete.

Phase 0 is intentionally console-first. The first vertical slice uses ARP to prove that NOVXIS can capture or replay real traffic, decode protocol evidence, produce normalized events, and present those events clearly.

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

## Current Phase 0 Boundary

```text
LIVE CAPTURE ─────┐
                  ├──► PROTOCOL INTERPRETATION ──► NORMALIZED EVENTS ──► CONSOLE
PCAP/PCAPNG ──────┘
```

The first supported protocol vertical slice is ARP.
