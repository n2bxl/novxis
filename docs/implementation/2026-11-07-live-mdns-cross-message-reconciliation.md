# Phase 1N-J: Live Cross-Message DNS-SD Reconciliation

Date: 2026-11-07
Status: Draft PR; developer M5 focused/full regressions and Safari validation pending.
Base: Phase 1N-I PR #41 squash-merged to main at c7c3d34.

## Scope

Extend the passive local Services tab from **same-response PTR/SRV/A/AAAA
claims** to **separately observed response records**, using the existing
\`MDNSServiceReconciliation\` state engine, not a new name-matching
heuristic. This is a single-capture-interface, read-only extension.

The design preserves the PR #41 defaults: ARP graph nodes and claims,
typed interfaces, independent OS context and subnet evidence,
keyboard-accessible tabs, offline replay, and the ability to inspect
an independently observed same-interface ARP IPv4 address.

## Architecture

    sudo network_live_stream (privileged; bounded 120 s / 2000 frames)
        |
        +-- ARPStatePipeline -> original typed binding events
        |
        +-- MDNSEventPipeline -> original message and PTR events
                |
                +-- MDNSServiceReconciliation (existing engine)
                    .state: bounded PTR-backed service evidence
                    ._unassociated: bounded PTR-less SRV/TXT/A/AAAA records
                    .snapshots(as_of): exact-name/TTL/interface join
                        |
                  project_live_reconciliation
                  bounded normalized PTR/SRV/A/AAAA metadata
                  excludes TXT, frame/payload bytes, source MACs
                        |
                    NDJSON stdin pipe
                        |
             non-root LiveARPGraphState + LiveMDNSState
                        |
                    /api/graph
                        |
              local Services sidebar
            "joined across responses"
               independent record times

The original captured packet/record objects stay inside the privileged
capture process in bounded collections (128 service instances, 16
records per instance, 256 history and 256 orphan evidence records).
Only structured, name/TTL/type/port/address summaries pass the
privilege boundary, with each per-service message capped below the
existing 4,096-character line reader. At most four changed service
summaries are emitted per observed response; excess is marked as
truncated. Existing per-response PTR count and query/response counts
are unchanged.

## Strict reconciliation contract

The underlying engine requires:

1. An actual **PTR response** for a native DNS-SD instance, fresh
   according to its original positive TTL.
2. Exact case-insensitive DNS label match between that service instance
   and the separately observed **SRV owner name**. TXT may be retained
   by the capture-side engine, but **TXT is never exported** to the
   unprivileged process.
3. Exact case-insensitive DNS label match between the **SRV target**
   and separately observed A/AAAA record owner name.
4. The **same capture interface** for all joined records.
5. Each record must be individually fresh as of the captured message's
   timestamp. A query known-answer record is not authoritative response
   evidence and cannot join a service.

The resulting browser event includes \`service_type\`, \`instance\`,
\`ptr_observed_at\`, \`as_of\`, and up to two SRV targets each with up to
three A/AAAA addresses. Each nested record has an original observation
timestamp, original TTL, and one of \`same-mdns-response\` or
\`cross-mdns-response\` provenance. The unprivileged receiver validates
every field atomically, refuses to create a service without an already
accepted PTR, refuses to attach to a different PTR epoch, and keeps
the current interface scope.

**Independent TTLs:** When cross-response SRV or A/AAAA expires, its
fresh status and the whole path's status change without a new packet.
The API revision advances, but the ARP SVG only redraws when ARP
evidence changes. An explicit TTL-zero withdrawal (goodbye) or other
invalidating response can generate a \`mdns_reconciliation_clear\` event
that removes the previously published overlay. The original
same-response targets remain available if independently supported.
No stale cross-response association may be promoted to a fresh claim.

**Read-only provenance:** The Services tab distinguishes "same
response" from "joined across responses" for each SRV or A/AAAA record
and displays its own observed timestamp. A link to an existing ARP
IPv4 address remains a **navigation cross-reference only**, not a
claim that the service or target resides on a verified physical host.

## Specific limitations

- Cross-message association runs in the capture process from bounded
  protocol state and is ephemeral. It is not a persistent OS DNS cache,
  device inventory, discovery probe or network scanner.
- \`MDNSServiceReconciliation\` currently stages orphan SRV/TXT/A/AAAA
  evidence **only in responses without a PTR-backed projection**.
  Unrelated records carried in a PTR-containing packet are not promoted
  as independently associated orphans by this engine.
- Maximum 2 targets/3 addresses per emitted service summary, maximum
  4 changed service summaries per response. Cap/truncation is explicit.
- Names and IPv4/IPv6 addresses are untrusted DNS assertions, not
  authenticated device identity or endpoint availability.
- No packet/TXT data or raw capture is sent to the localhost browser.
  No new endpoints, privileges, external dependencies, or network probes.
- A relationship only appears if enough relevant packets are seen; no
  joined records on a quiet capture is **not** an error.

## M5 acceptance

```bash
git fetch origin
git switch --track origin/ai/phase1n-cross-message-dnssd-2026-11-07
python -m pytest tests/state/test_mdns_reconciliation.py tests/web -q
python -m pytest
```

Then on your connected, authorized capture interface (en5 is an
example) start:

```bash
sudo .venv/bin/python -m novxis.cli.network_live_stream en5 --count 2000 --timeout 120 \
  | .venv/bin/python -m novxis.cli.web_live
```

In Safari at http://127.0.0.1:8765/ verify:

1. ARP nodes and evidence inspector, pan/zoom, rearrange, Subnet and Host
   remain unchanged; Services remains keyboard-operable.
2. PTR, SRV and A/AAAA observations within one packet still show
   as "same response" with separate TTL values.
3. If separate SRV/A/AAAA responses naturally arrive, a fresh exact
   name-chain join appears as "joined across responses", retaining
   separate timestamps and TTLs.
4. An earlier orphan SRV/A can join a later fresh PTR without
   inventing new device identity.
5. Independent expiry, TTL-zero withdrawal and query-only cases are
   covered deterministically by synthetic byte-level Python tests.
6. The independent ARP IPv4 jump remains a cross-reference to an
   existing selected protocol address, not a new graph connection.
7. ARP-only live producer still has Services disabled, and sanitized
   offline replay still has 12 nodes / six sender claims.

Real service names/addresses can identify private devices; do not
commit unredacted screenshots, MACs, IPv4/IPv6 addresses, or TXT
contents. The synthetic tests use RFC documentation addresses
(e.g. 192.0.2.25 and 2001:db8::25).

## Deferred

Live cross-interface capture comparisons, hostname-to-device identity,
NDP joins for IPv6, full DNS-SD cache semantics, per-record export of
original TXT, active querying, probing or verification, 3D topology,
and encrypted application payload inspection.
