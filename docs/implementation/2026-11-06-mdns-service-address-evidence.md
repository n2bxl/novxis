# Phase 1N-I: DNS-SD Service-to-Address Evidence in the 2D Debugger

Date: 2026-11-06
Status: Draft implementation PR; M5 live Safari evidence navigation observed, pytest pending.
Baseline: Phase 1N-H PR #40 squash-merged to main (95bbdfc).

## Goal

Expose conservative DNS-SD name and address relationships in the live
Services tab, while keeping the 2D ARP graph, source provenance,
privilege boundary, and capture contract unchanged.

This milestone extends the *existing, same-response* projector:
\`project_dnssd_advertisements()\` yields a native service type PTR,
the advertised instance, SRV target/port, and target-owner-matched
A/AAAA records when they occur in **one response message**.

**No cross-message association in this milestone**. The existing
\`MDNSServiceReconciliation\` is a richer replay-oriented capability,
but merging separately seen SRV/A/AAAA requires careful bounded,
interface-scoped state and explicit source provenance. That is deferred
until the live view proves its one-message evidence model.

## Data and trust boundaries

The privileged \`network_live_stream\` producer:

- Reuses the existing passive ARP or UDP/5353 filter and
  MDNSEventPipeline. No active queries or probes.
- Keeps original PTR service names and TTL and additionally emits at
  most 2 matching SRV records per retained PTR, and up to 3 A/AAAA
  target-owner matches per SRV. These nested assertions originate in
  the same decoded mDNS response as the PTR.
- Sends normalized SRV target name, port and record TTL, and A/AAAA
  family/address/record TTL. TXT values and raw packet bytes are never
  included in the pipe.
- Maintains an encoded event size budget below the existing 4,096
  character receiver limit. If the budget or per-message caps are
  reached, emits an explicit relationship-omission flag.

The non-root web consumer:

- Validates all nested fields (canonical IPs, IPv4 vs IPv6 family,
  finite bounded TTLs, ports, printable names and per-record caps)
  before mutating state.
- Preserves interface, mDNS response role, capture timestamp and
  same-response provenance. Query known answers do not become
  advertisements.
- Tracks current preview evidence from the **latest PTR-bearing
  response for each service instance**. A new PTR response lacking
  SRV/A/AAAA clears that instance's previously displayed target
  details, conservatively avoiding unsupported inter-response fusion.
- Computes PTR, SRV, and individual A/AAAA freshness independently
  from their original observation time and TTL. An entire relationship
  chain is fresh only if its PTR, SRV and address record are fresh.
- Updates the API revision as any constituent freshness changes
  even without new packets, but does not redraw the ARP canvas
  unless ARP node/claim evidence changes.
- Marks omitted nested relationships via the existing truncated
  evidence indicator.

The same \`/api/graph\` response remains in schema version 1 with
the optional \`mdns_evidence.services[].targets[]\` and nested
\`addresses[]\` evidence. No new endpoints or device nodes/edges.

## Cross-reference, NOT host fusion

An independent read-only adapter compares each mDNS A-record IPv4
address with ARP's typed, interface-scoped IPv4 protocol address
nodes. It emits a reference to an **existing** ARP node only when:

1. The interface of the mDNS capture and ARP node is identical.
2. The ARP protocol type is IPv4, the hardware type is Ethernet.
3. The numeric four-byte IPv4 address is an exact match.

It does not infer a connection, join MAC/service identities, assert
reachability, treat same-named services as identical across interfaces,
or create an ARP relationship. AAAA claims do not receive ARP
cross-references. This reference is simply a UI navigation option.

## UI acceptance

The Services tab shows, within each PTR service entry:

- The SRV advertised target name, port, original SRV TTL and current
  PTR+SRV freshness.
- Any same-response A or AAAA records, their original TTL and full
  PTR+SRV+A/AAAA chain freshness.
- A button to inspect a matching existing ARP protocol address,
  when an exact same-interface IPv4 observation exists; otherwise
  an honest "No same-interface ARP address match" message.
- Explicit explanations when a PTR appeared without a co-observed
  SRV record, or an SRV without A/AAAA addresses.
- No implied topology, fingerprint, trusted endpoint, or service
  availability. Text is inserted with \`textContent\`, not HTML.

## M5 verification steps

```bash
git fetch origin
git switch --track origin/ai/phase1n-service-address-links-2026-11-07
python -m pytest tests/cli/test_mdns_address_links.py \
  tests/cli/test_network_live_stream.py tests/web -q
python -m pytest
```

For actual live testing, run the same passive combined producer on the
authorized capture interface:

```bash
sudo .venv/bin/python -m novxis.cli.network_live_stream en5 --count 2000 --timeout 120 \
  | .venv/bin/python -m novxis.cli.web_live
```

Then inspect http://127.0.0.1:8765/ in Safari. Verify:

1. ARP nodes, sender claims, pan/zoom, reordering and inspector work.
2. Services counts, PTR advertisements and TTL freshness still work.
3. A same-response SRV shows its target and advertised port.
4. Co-located A/AAAA claims display the correct protocol family and
   record-specific freshness; a missing record never gets fabricated.
5. A matching IPv4 ARP claim offers a navigation button, selecting the
   existing address in Evidence without changing camera/layout.
6. Absent/mismatched ARP observations show "No same-interface ARP
   address match"; AAAA is never represented as an ARP cross-reference.
7. An SRV or address expiry can change freshness without any new
   captured packets.
8. The original ARP-only mode keeps Services disabled; offline
   sanitized PCAP still retains 12 typed nodes and 6 ARP sender claims.

Real SRV/A/AAAA co-location is traffic-dependent: no target records
in a capture is **not** a failed capture. The synthetic regression
fixtures cover the complete chain deterministically.

## Initial live Safari acceptance (2026-11-06)

The developer supplied a roughly 174-second Safari screen recording of
the opt-in live ARP + dual-stack mDNS debugger, captured on a single
authorized Ethernet interface. The browser session reached its bounded
capture `ended` state and retained a live Services view alongside a
populated ARP address map.

One response-derived DNS-SD instance, advertised with a native
Apple mobile-device service type, displayed a same-response SRV target,
its advertised port, an A record and AAAA records, each with record
TTL/freshness information. The A record offered **Inspect independent
ARP address**. The video shows the button opening **Evidence** and
selecting the matching existing same-interface IPv4 protocol address
node, including its one observed ARP sender claim. Other service
instances explicitly displayed missing SRV detail when none was
co-observed.

The developer independently checked the advertised IPv4 and IPv6
addresses against their iPhone's device configuration and reported
matches. Their observation that additional local service traffic
appeared around phone unlock is useful **temporal correlation**.
The simultaneously visible AirPlay record was named for the user's
MacBook Air, not independently demonstrated to originate from the
iPhone. These observations do not establish authenticated service
ownership or prove the physical identity of the responding sender.

**Verified by recording:** Service tab rendering, same-response PTR/
SRV/A/AAAA presentation, IPv4-to-existing-ARP navigation, original
Evidence inspector, independent interface scope, and no invented
cross-protocol graph edge.

**Still outstanding:** The developer has not yet supplied focused or
full Python pytest results for Phase 1N-I; the PR remains draft.
Manual proof of TTL transitions while idle, ARP-only mode and offline
replay on this feature branch was not included. Those behaviors have
regression coverage, but are not being reported as separately observed.

Public GitHub documentation omits real RFC1918 IP addresses, MACs,
IPv6 values, hostnames, personally identifying service-instance
strings, raw captures and unredacted screenshots.

## Privacy / security

Device names, service instances and IP addresses in real screenshots
or captures are private. Do not put any real addressing, service
instance names, TXT bytes or raw captures in public GitHub artifacts.
Use RFC documentation addresses such as 192.0.2.0/24 and 2001:db8::/32.
No remote binding, active discovery, decryption or credentials.

## Deferred

Cross-response DNS-SD reconstruction, a multi-interface service
inventory, active probes, liveness validation, IPv6 NDP address
cross-references, device/host identity fusion, new graph edges, and
future 3D service visualization.
