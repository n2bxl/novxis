# Phase 1N-G: Tabbed local 2D evidence sidebar

Date: 2026-11-02
Status: M5 Python regressions and Safari sidebar acceptance reported passing; ready for PR review.
Baseline: Phase 1N-F Subnet Evidence Lens PR #38 squash-merged to main
(commit 85405e7) after 580/580 tests passed on the developer's M5.

## UX decision

Keep the original **permanent local 2D debugger** and its sidebar but
replace the vertically stacked information sections with three
mutually exclusive pages:

- **Evidence**: selected ARP protocol/hardware address, provenance,
  observation times, sender claims and any same-interface OS route
  address cross-reference.
- **Subnet**: OS-reported IPv4 prefix groupings, observed ARP sender IP
  lists, outside-prefix addresses, and gateway address comparison.
- **Host**: read-only macOS interface IPv4 addresses, configured
  network prefixes, default route and source/time provenance.

The sidebar's active tab does not change the network graph, capture
state, camera zoom/pan, manual node layout, ARP claims or source metadata.
Tab selection is a local visual state variable, not a new API endpoint
or network action.

## Interaction contract

- Evidence is the default tab. For offline PCAP replay, Subnet and Host
  are disabled because OS configuration is not present; the disabled
  states do not allow the current local host's settings to leak into
  offline evidence.
- Live Subnet and Host tabs activate only when their respective
  source-typed response fields exist. If the active page becomes
  unavailable, fall back to Evidence without changing ARP selection.
- Clicking a visible tab changes the sidebar page without changing
  selection or moving the camera.
- Left/Right arrows navigate between enabled tabs with wraparound.
  Home and End select first and last enabled tabs. aria-selected,
  aria-controls, role=tab/tabpanel and roving tabindex support
  keyboard accessibility.
- Clicking an ARP node in the map or an address button on the
  Subnet page opens the Evidence tab to show that node's claims.
- Existing live-update polling refreshes the data behind all pages
  and retains the active page if still available; expanded subnet
  groups keep their remembered open state.
- Only one sidebar page is visible at a time. The page area scrolls
  independently within the sidebar when longer than the available
  vertical space. No physics animation, 3D, remote interface or
  additional privilege is introduced.

## M5 acceptance plan

    git fetch origin
    git switch ai/phase1n-tabbed-evidence-sidebar-2026-11-02
    python -m pytest tests/web -q
    python -m pytest

Run the same bounded live ARP pipeline on an authorized en0/en5
interface and open http://127.0.0.1:8765/ in Safari.

Check:
1. Evidence initially shows and displays the selected ARP address.
2. Clicking Subnet displays observed prefix/address lists without
   hiding or shifting the address map.
3. Clicking a subnet address selects the graph node and opens Evidence.
4. Host displays the macOS configuration snapshot, then switching back
   restores the previous selected address.
5. ArrowLeft/ArrowRight/Home/End work with a focused tab.
6. A live polling refresh does not change the selected tab and does not
   cause an expanded subnet section to collapse.
7. Zoom, pan, Rearrange, Auto arrange and evidence selection remain
   unaffected.
8. Offline replay contains 12 address nodes/6 sender claims, shows
   Evidence only, and leaves Subnet and Host disabled.

This change is presentation-only. It does not modify host collection,
subnet derivation, ARP state, packet capture, HTTP binding, or API schema.

## M5 acceptance evidence (2026-11-02)

The developer reported the focused/full pytest runs **clean** on the
updated sidebar branch. Exact command totals and elapsed times were
not included in this report, so they are not invented here. The
preceding Phase 1N-F main baseline was 580 passing tests; this branch
adds eight new sidebar asset-contract tests.

The developer also provided an approximately 149-second Safari screen
recording of the browser workflow. It shows the real-time ARP graph
populating and selected address evidence being inspected, switching
among Evidence, Subnet and Host views, and opening the sanitized
offline replay. In the test feedback, the developer indicated that
the other browser acceptance items had passed, including the
interactive map and live/sidebar behaviors.

**Keyboard coverage:** The developer manually confirmed that
**Left/Right Arrow** navigates between sidebar tabs. **Home/End**
was not manually exercised because the integrated MacBook keyboard
has no dedicated Home/End keys. The code and regression contract
checks cover these key handlers, but that is not the same as an
end-to-end Safari test. An optional follow-up is to focus a tab
and try Fn+Left Arrow (Home) and Fn+Right Arrow (End).

The unverified Home/End hardware shortcut is a minor residual manual
check, **not** a failure of the documented feature. M5 feedback and
the recording support marking the tabbed-sidebar milestone ready for
review and the owner's normal squash merge.

This repository note deliberately omits real IP addresses, MAC
addresses, packet captures, and any screenshots or recording of the
developer's private network.

## Merge-base verification

PR #39 originally branched from PR #38 while #38 awaited its squash
merge. Following that merge, this branch was rebuilt with main commit
85405e7 as its direct parent. Its diff should contain only the sidebar
HTML, JavaScript, styles, tests and this documentation, with no repeated
subnet evidence implementation.
