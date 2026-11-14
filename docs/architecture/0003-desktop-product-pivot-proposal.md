# ADR 0003 (proposal): NOVXIS as one desktop application

- **Date:** 2026-11-14
- **Status:** PROPOSED, not accepted; architecture exploration only
- **Branch:** `architecture/desktop-product-pivot-2026-11-14`
- **Baseline:** Stage 4 is merged on `main`; latest developer-reported full-suite result: **1,041/1,041 passed** on 2026-11-14
- **Scope:** Product direction, desktop hosting, app boundaries, validation and migration gates
- **Not decided:** Application framework, embedded browser engine, 3D engine, final IPC transport, signing/distribution strategy

## 1. Product intent

NOVXIS is being developed as a coherent, polished, publicly distributable
**desktop application**, with independently navigable workspaces for:

- Permanent **2D Evidence Explorer**, preserving its precise, reproducible
  debugging and inspection role.
- Future **3D Cyberspace**, presenting the **same semantic network facts**
  through a different scene and navigation model.
- Packet/protocol and capture-session inspection, with evidence provenance.
- Future operator-authorized investigations as a distinct, explicitly
  consented workflow; no probes triggered by opening or navigating a view.

The user wants one recognizable NOVXIS experience, not unrelated tools
or a browser bookmark. "One application" can contain distinct processes:
a least-privileged UI, a graph/session service, and an independently
authorized capture helper. One window is a user-experience objective,
not permission to combine trust boundaries.

The UI should implement **NOVXIS's own visual language** (technical,
monospace, restrained phosphor/cyberpunk, clarity and readability) rather
than depend on macOS/Windows decorative themes or duplicate game HUDs.
The 2D view remains a permanent reference even after desktop integration.

## 2. Invariants we must not bargain away

1. **Semantic authority:** Python decoders, normalized events, bounded state
   and immutable typed graph projections remain renderer-neutral. Neither
   2D nor 3D invents ownership, reachability, host identity, topology,
   or service status from spatial proximity or cosmetics.
2. **Provenance:** Capture interface/scope, observed vs OS-reported context,
   source records, TTL freshness, omitted/truncated data and contradictory
   claims remain explicit and inspectable.
3. **Privilege separation:** UI and renderer never require root/admin.
   Capture privileges belong in a narrow, separately authorized component;
   the unprivileged renderer consumes validated bounded evidence.
4. **Offline-first validation:** The app opens a sanitized, synthetic replay
   without elevated permissions, physical interfaces or external services.
5. **Two-way debuggability:** Keep a stable independent reference path for
   rendering a fixture while desktop-hosting experiments mature. Do not
   delete the browser-based debugger until a tested replacement exists.
6. **Portable contracts:** App/platform code must not leak into packet
   parsers or evidence graph types. Target macOS first while documenting
   cross-platform assumptions, including Windows packaging and capture
   differences as later verification work.
7. **Security and privacy:** No unrestricted file server, hidden remote
   address queries, telemetry, raw capture publication, or elevated
   process-wide UI. Native bridges must have a small, explicit,
   capability-limited surface.
8. **No silent "temporary" architecture:** Every workaround has a named
   reason, a measurable replacement condition and removal check. Never
   treat a feasibility spike as production code by default.

## 3. Proposed responsibility boundaries

```text
NOVXIS Desktop (unprivileged application host, window and navigation)
       |
       +-- 2D evidence inspector (permanent)
       +-- 3D Cyberspace renderer (future)
       +-- protocol/console views (future)
       +-- session UI / explicitly authorized investigations (future)
       |
       v
Application/session interface (versioned, validated, bounded)
       |
       v
Python capture/replay -> events -> state -> immutable typed evidence graph
       ^
       |
Separately authorized capture worker when needed (not the GUI process)
```

**Shared across renderers:** semantic graph IDs, edge kinds, observations,
source/capture scope, revisions, freshness and truncation.

**Renderer-specific:** node layout, edge anchor/route geometry, camera,
visual styling, gesture interpretation, occlusion, selection overlays.
Shared selected semantic IDs may be exchanged through application state,
not inferred from 2D or 3D coordinates.

The immediate geometry work can remain JavaScript. Framework selection
does not imply rewriting the validated SVG renderer into Python widgets.

## 4. Candidate implementation paths (no selection yet)

| Candidate | Expected strength to verify | Risk/cost to measure |
| --- | --- | --- |
| PySide6 / Qt with embedded WebEngine | Python-first desktop lifecycle, shell/navigation, reuse existing SVG UI | Deployment size, native WebEngine behavior, thread/process design, Mac/Windows distribution |
| Tauri shell with bundled Python sidecar | Custom web-first UI and potential web 3D integration inside one app | Rust/toolchain complexity, sidecar packaging, capability/IPC design, platform WebView differences |
| pywebview prototype | Quickest low-cost check that current UI can live in a managed window | Whether it scales to unified workspaces, bridge security, packaging, future 3D needs |
| Browser baseline | Existing working diagnostic oracle and devtools | Not the target standalone packaged end-user experience |

Candidates must be compared by *observed prototype evidence*, not
preference or marketing. A webview-hosted 2D debugger is not a failure
to build a desktop app. Conversely, native widgets do not automatically
improve modularity.

## 5. Explicit decision gates

### Gate A: Preserve and baseline
- Confirm updated `main` has Stage 4 docs and **1,041** passing regression
  tests, with optional raster dependencies as documented.
- Establish deterministic, sanitized service graph fixtures for empty,
  small and dense topologies, including IPv4/IPv6, MAC evidence,
  parallel paths, TTL-expired advertisements and cap-reached metadata.
- Record observable baseline: selection, port geometry, reset, manual order,
  navigation, camera and update behavior. No private packet captures.

### Gate B: Hosting spikes (separate throwaway experiments)
- Load the **same existing** 2D view and fixed fixture inside at least two
  credible desktop hosts, without rewriting protocol code.
- Verify resize, pointer/keyboard interaction, accessible labels, evidence
  hit targets, custom CSS identity and clean shutdown/relaunch.
- Run with standard user privileges. For any live test, keep the current
  privileged producer strictly separate from the viewer.
- Record startup behavior, memory footprint, redraw responsiveness,
  packaging friction, process lifetime and failures on the M5. A future
  Windows test is a distinct gate, not a claim established by macOS.
- Do not add new networking capabilities in these spikes.

### Gate C: Choose an application host deliberately
- Produce an accepted follow-up ADR ranking the measured candidates,
  including security, maintainability, custom styling, distribution,
  offline functionality, 2D continuity, 3D feasibility and rollback cost.
- Explicitly decide ownership of application state, session lifecycle,
  local transport/IPC and packaging boundaries before wiring live capture.
- No implementation shell becomes canonical merely because it opens.

### Gate D: Product foundation (after an ADR is accepted)
- Extract reusable, deterministic layout and connector calculations with
  executed behavioral tests, while preserving UI and evidence semantics.
- Build one coherent desktop shell with 2D as the first working workspace.
  Other workspace entries may be disabled placeholders only if clearly
  described as unavailable; no simulated network evidence.
- Validate error handling, offline operation, startup/shutdown, no
  orphaned capture process, navigation, regression suite, reproducible
  build and clean install/uninstall path.
- Promote a capability only after acceptance, not after a screenshot.

## 6. Quality bar and debt policy

A checkpoint is **done** only when its behavior is described, bounded,
tested, reproducible on a sanitized fixture, locally accepted, documented
and reversible. Each new subsystem must have a clear owner, inputs,
outputs and failure modes. New dependencies need a concrete benefit.

Do not pre-emptively introduce a generic plugin framework, abstract 3D
engine, full OS capture manager or frontend rewrite merely because a
candidate framework supports them.

Use benchmarks as **measurements before targets**: capture reference
startup, redraw, drag and memory behavior on consistent fixtures, then
set meaningful budgets based on actual desktop prototype data rather
than invented frame-rate or memory promises.

Security and evidence correctness are release blockers. Cosmetic polish
is not permission to blur uncertainty, merge evidence claims, or conceal
unsupported capabilities.

## 7. Next action and review boundary

This proposal records the product pivot **without choosing a host**.
First build Gate A's sanitized deterministic fixture and exact 2D behavior
baseline; in parallel write the evaluation matrix and thin-spike briefs
for Gate B. Review these before any app-shell implementation is merged.

Keep all experimentation on the dedicated branch or further short-lived
branches derived from it. Leave `main` untouched until a specific
increment clears the acceptance gate. A native window or 3D experiment
must never demand a wholesale rewrite of the Python evidence engine.

**References:** [Stage 4 closeout](../implementation/2026-11-14-stage4-closure.md),
[ADR 0001](0001-permanent-2d-reference-and-shared-graph.md),
[ADR 0002](0002-evidence-first-address-relationships.md).
