# Phase 1N-E: Read-only macOS Host IPv4 and Default Route Context

Date: 2026-11-02
Status: M5 Python regressions and read-only macOS en0 comparison accepted; Safari live panel acceptance pending.
Baseline: Phase 1N-D PR #36 merged, with 529/529 full tests accepted.

## Goal

Introduce actual host network configuration as a **separate source of evidence**
beside the first live ARP graph. This is not the beginning of a physical topology
inference engine. ARP sender claims are packet observations; interface addresses
and default-route selection are reported by the operating system.

The collector runs only in the **non-root live browser process**. It is invoked
once when the session message identifies the requested capture interface.
The privileged capture helper continues to emit only ARP sender-binding facts.

## What is read

Read-only macOS commands, using literal executable paths and shell=False:

- /sbin/ifconfig <authorized-interface>
- /sbin/route -n get default

The interface argument is validated against a conservative interface-name
grammar, preventing option injection, whitespace or shell fragments. Both
commands have three-second timeouts. Failure and malformed output yield
unavailable/partial statuses; raw command output or errors are not sent to
the browser.

From ifconfig, NOVXIS extracts **IPv4 interface addresses and netmasks**.
Both macOS hexadecimal netmasks and conventional dotted masks are parsed,
checked by Python ipaddress for valid contiguous prefixes, and represented
as address + prefix length + derived configured network. For example,
192.0.2.34/24 implies the host is configured in 192.0.2.0/24; this does
**not** mean all addresses in that prefix have been observed.

From the default route query, NOVXIS extracts a single reported IPv4 gateway
and its *actual* interface. If the selected capture interface is en5 while
the default route uses en0, both are reported without contradiction or
pretending the gateway was captured via en5. The default route lookup
describes a point-in-time OS decision, not every possible route, a
destination-specific next hop, or a physically adjacent router.

The collector is macOS-only and IPv4-only. Unsupported hosts or malformed
or absent route information are explicitly represented as unavailable.

## Architecture

    macOS host configuration (unprivileged, read-only)
                        |
           HostContext collector (once per session)
                        |
                isolated host_context metadata
                        |
            Local 2D host-context inspector

    Live ARP packets -> ARPStatePipeline -> ARPAddressMapSnapshot
                        |
                    graph nodes/claims

These flows meet **only in the browser response** as separate fields.
Host prefixes are **not** added as ARP nodes, inferred cables, device
identities, or observed subnet memberships.

The graph JSON schema remains version 1 with an optional additive
host_context object in *live mode only*. Offline sanitized replay
does not borrow the developer's present configuration.

## Local commands

From the active project's unprivileged Python virtual environment:

    python -m novxis.cli.host_context en5

For an authorized short live capture (use en0 if that is your actual
traffic-carrying interface):

    sudo .venv/bin/python -m novxis.cli.arp_live_stream en5 --count 2000 --timeout 120 \
      | .venv/bin/python -m novxis.cli.web_live

Open http://127.0.0.1:8765/ and inspect the new **Host IPv4 context**
section. The browser is still loopback-only and read-only. Do not use
sudo for the right-hand process. Context is queried **once**, not
refreshed as the Mac's network settings change. Restart the session
to capture a new OS configuration snapshot.

## M5 acceptance checklist

1. Run: python -m pytest tests/host_context tests/web -q
2. Run: python -m pytest
3. Run: python -m novxis.cli.host_context en5
4. Compare the result with macOS read-only diagnostics:
   ifconfig en5
   route -n get default
5. Confirm that a distinct route interface, if present, is shown
   separately from the interface being captured.
6. Confirm no private IP/MAC addresses, real route outputs, or PCAPs
   are committed to GitHub. Tests use only documentation ranges.
7. Launch the bounded live ARP pipeline; see Host IPv4 context in
   Safari while ARP nodes/edges remain evidence-derived.
8. Confirm that the offline sanitized replay UI hides the host-context
   panel and ARP node counts/claims remain unchanged.
9. Confirm an unknown interface or unavailable default route is
   reported without a fabricated prefix or gateway.

## M5 Phase 1N-E validation (2026-11-02)

The developer provided two sets of test evidence:

- **Focused suite:** `python -m pytest tests/host_context tests/web -q`:
  **73 passed in 3.76 seconds**.
- **Full suite:** `python -m pytest`: **560 passed in 3.90 seconds**
  (macOS Darwin, Python 3.14.6, pytest 9.1.1, pluggy 1.6.0).
- **Regression change:** 31 more tests than the Phase 1N-D
  529-test baseline, with no failures.
- **Read-only CLI:** `python -m novxis.cli.host_context en0` reported
  status `reported`, with an IPv4 address, a **/22** prefix,
  a matching configured network and an IPv4 default route through
  **en0**.
- **Independent OS comparison:** `ifconfig en0` and
  `route -n get default` agreed with the CLI's selected
  interface, configured address, hexadecimal netmask-derived prefix,
  and default gateway/interface.

No actual private IP addresses, gateway address, hardware addresses or
unredacted command output have been committed to this validation note.

**Source boundary:** The developer also recognized the default gateway's
protocol address from earlier **ARP sender evidence**, prior to this OS
configuration query. Those are independent observation/configuration
sources. ARP did not establish that the address was the Mac's gateway;
the host route lookup did. Do not merge ARP node scope across capture
interfaces or infer a physical link from this agreement.

The checkout command in the submitted terminal produced
`fatal: a branch named ... already exists` because a local branch of
that name was present. The test output and collector invocation
completed successfully afterwards. A later `git branch --show-current`
check can confirm the active branch when desired.

**Still pending before PR readiness:** manual Safari validation of
the Host IPv4 context panel during a bounded live-ARP session and
confirmation that the offline PCAP preview remains without local
host configuration. Automated unit and web integration checks passed,
but those are not substitutes for this browser check.

## Deliberately deferred

IPv6, multi-route/VRF/policy routing, route metrics and path selection,
continuous OS configuration refresh, network service APIs, Linux/Windows
collectors, gateway-to-ARP-node inference, historical host configuration,
unprivileged capture helper hardening, GUI start/stop, and 3D view.

Future route visualizations must preserve source/type/scope and time,
especially when the capture interface and system default-route interface
differ.
