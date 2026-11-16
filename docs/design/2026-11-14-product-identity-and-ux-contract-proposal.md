# NOVXIS product identity and UI/UX contract — proposal

- **Date:** 2026-11-14
- **Status:** DRAFT for product-design review; no UI or brand asset changes in this document
- **Depends on:** [ADR 0003 desktop product pivot](../architecture/0003-desktop-product-pivot-proposal.md) (also proposed)
- **Implementation baseline:** Stage 4 merged `main`, last locally validated 1,041/1,041 tests
- **Source of design intent:** OAIOS NOVXIS Visual Identity and UI Design Manifesto, Visual System Foundations, Selected Logo and Brand Specification, Cyberspace Design Principles, and 2D/3D architecture decision
- **Source of shipped artwork:** `assets/branding/README.md` and checked-in `assets/branding/source/*.svg`

## 1. What is canon, and what is not

### Approved identity — preserve

| Topic | Current approved artifact or direction |
| --- | --- |
| Product name | **NOVXIS** — Network Observation, Visualization, eXploration Interface System |
| Mission | Make abstract networking concepts visually concrete; evidence before interpretation |
| Full-size icon | `assets/branding/source/x-junction.svg`: four angular gold arms, green central plus, four cyan open-corner brackets |
| Compact icon | `assets/branding/source/x-junction-compact.svg`: **one connected gold X**, four cyan open-corner brackets, **no center plus** |
| Monochrome compact | `assets/branding/source/monochrome/`: matching white and black geometry |
| Wordmark | `assets/branding/source/w3-tech-stripe.svg`: six bespoke angular gold letters and **two** narrow forward slashes, not the historical three stripes |
| Horizontal lockup | `assets/branding/source/novxis-lockup-horizontal.svg`: full-size icon, separator, bespoke wordmark and tagline |
| Exact tagline | `> OBSERVE / VISUALIZE / EXPLORE`, green prompt / cyan text in the current SVG |
| Signature identity gold | `#AF9600`; **not** a generic caution/health/verification status color |
| Supporting creative grammar | Dark-first graphite, restrained green/cyan phosphor, orthogonal geometry, modern TUI/brutalist ASCII influence, legible technical text |
| Typography direction | **IBM Plex Mono** for UI/supporting text; bespoke wordmark is vector artwork, not a font |

The full and compact marks are **different intended members of one family**.
Do not add a green plus to the compact X or remove its open-corner brackets.
Do not use the compact mark to depict closing, deleting, cancelling or an
unsupported network-state assertion.

The old OAIOS logo-specification prose described an earlier three-stripe
study and initially open compact-geometry choice. The checked-in, tested
artwork and its implementation history supersede those specific details.
Synchronize the OAIOS history **without erasing the decisions' chronology**.

### Not yet approved as production standards

- Complete palette extensions and final semantic color assignments
  (the OAIOS `Visual System Foundations` version 0.1 values are candidates).
- Exact type sizes, density presets, line weights, token names, contrast and
  light/high-contrast variations.
- Final application icon export, launch/splash treatment, font licensing /
  bundling, platform icon formats, and SVG tagline font portability.
- Desktop shell chrome, workspace navigation pattern, 2D inspector
  placement/dimensions, icon family, animation budget and final responsive rules.
- 3D environment, control bindings, E/Q placement and effects presets.

Do not silently promote design candidates into the canonical brand system.
Approve each after a repeatable visual and accessibility review.

## 2. Current 2D interface gap: factual implementation audit

The Stage 4 reference UI remains an effective evidence debugger. But it was
built before the approved identity was integrated:

- `novxis/web/static/index.html` calls itself **Evidence Map Preview**,
  displays a plain `NOVXIS` text label, and uses an empty `.brand-mark`
  span. No approved SVG logo or wordmark is rendered in the application.
- `novxis/web/static/styles.css` sets a system sans-serif stack and
  cyan `#63C6E8` as `--accent`. It uses rounded 11px major panels,
  6px buttons and 7px evidence cards. These choices do not reflect the
  approved monospace / right-angle NOVXIS character.
- The map already has **three** independent modes (ARP, Unified,
  Services), selectable typed evidence, stale paths, camera controls,
  independent inspectors and careful uncertainty labels. Preserve this
  information architecture instead of cosmetically hiding it.
- Brand SVG sources and tests exist but are separate from the running UI.
  This is an **integration debt**, not evidence that our identity is
  undecided or that the 2D architecture failed.

No style or navigation migration should alter graph node/edge IDs,
capture scope, TTL metadata, manual ordering or evidence hit targets.

## 3. Unified product shell: experience, not a theme

The desired product is **one installable desktop application**, with
consistent navigation and a recognizable NOVXIS visual system. Proposed
workspace model for later acceptance:

| Workspace | Role | Availability |
| --- | --- | --- |
| **Evidence / 2D** | Permanent reference debugger: graph, provenance inspector, capture context | Implemented browser UI; migrate without behavior loss |
| **Cyberspace / 3D** | Spatial exploration of the *same* typed semantic graph | Deferred; no fake 3D placeholder representing live facts |
| **Protocols / Console** | Inspect captures, decoded fields, commands and structured source details | Future integrated product workspace; some CLI foundations exist |
| **Sessions / Sources** | Open replay, select permitted interface/session, distinguish OS context from packet evidence | Desktop design work required |
| **Investigations** | Explicitly scoped, authorized actions and solicited results | Future, not passive view navigation |

A workspace can have its own layout. The **2D inspector may retain
persistent practical panels**; future 3D should favor contextual HUD zones.
Do not impose one rigid sidebar arrangement on both.

Global shell chrome should carry only essentials: product identity,
current source/scope and session state, workspace navigation, access to
settings/help, and clearly distinguished passive/active controls.
Avoid fake always-live status, decorative counters, or unsupported tabs.
The network evidence itself has visual priority over menus and branding.

## 4. Candidate visual grammar to prototype

Retain the approved NOVXIS character, then evaluate these **candidate**
rules from OAIOS Visual System Foundations rather than instantly locking
their exact numbers:

1. **Canvas:** dark graphite/obsidian, subtly bounded working area, little
   or no default bloom. No animated scanner texture over small text.
2. **Panels and controls:** squared/right-angled edges, 1px technical
   rules, 4px spacing rhythm and restrained corner brackets or divider
   ticks. Rounded SaaS cards should not be the default.
3. **Text:** locally packaged **IBM Plex Mono if licensed/validated**,
   fallback to a readable system monospace; preserve selectable/copyable
   identifiers and sufficient contrast at realistic window sizes.
4. **Palette:** `#AF9600` for identity and operator selection; carefully
   controlled phosphor `#88E6A1` and cyan `#76D8DE` for defined visual
   roles. Neutral backgrounds/text and explicit labels do most of the work.
5. **Shape:** shape/outline distinguishes actual *entity class* only;
   don't transform hardware address evidence into a router/host symbol.
6. **Evidence relationships:** distinct typed lines and inspector labels;
   stale/expired paths remain patterned and inspectable, never equated to
   offline devices. Separate observation, OS-reported context, claimed
   configuration and user annotation.
7. **Motion:** short, meaningful effects may respond to observed events
   or operator focus. A static/effects-off rendering must convey all facts.
8. **Accessibility:** high-contrast focus, full keyboard workflow,
   reduced-motion/effects-off modes, text-plus-line patterns, no
   color-only semantics, and no pale text on solid old-gold controls.

Initial palette **candidates**, **not approved tokens**:

| Purpose | Candidate | Status |
| --- | --- | --- |
| Canvas | `#0A0D10` | Test |
| Panel | `#121A20` | Test |
| Border | `#34434A` | Test |
| Primary text | `#E0E8E5` | Test |
| Focus highlight | `#E3D172` | Test |
| Gold | `#AF9600` | Approved identity accent |
| Phosphor green | `#88E6A1` | Approved brand asset color; UI meaning to test |
| Cyan | `#76D8DE` | Approved brand asset color; UI meaning to test |

The preferred UI font **direction** is established; the exact size scale
and distribution/legal packaging must still be accepted separately.

## 5. Component inventory / interaction contracts

Develop a small reviewable prototype of the following *before* reskinning
the whole application:

- **Product header:** correct compact/full mark usage by available size,
  bespoke wordmark where legible, exact tagline only when legible; no generic
  rotated-square brand placeholder.
- **Workspace navigation:** clear selected/disabled/future states,
  predictable shortcuts, no unexplained fake modes.
- **Source/session strip:** `PASSIVE CAPTURE`, `REPLAY`, interface,
  scope, capture limits and source time, without conflating OS-reported
  data with captured packets.
- **Evidence node and edge:** typed entity, selected/focused/hover
  state, source and TTL semantics retained; accessible evidence drilldown.
- **Inspector:** exact identifiers, field provenance, unknown vs absent,
  conflicting claims, bounded omissions, copyable values.
- **Controls:** inspect/rearrange/zoom/fit clearly separate from capture
  operation or active investigation authorization.
- **Feedback:** loading, empty capture, cap-reached/incomplete,
  stale, error/retry, keyboard focus and low-effects states.

Visual redesign must not break independent mode cameras, service-card
variable heights, manual rearrangement, parallel path selection or
Reset view behavior.

## 6. Design-to-implementation gates

**Gate V0: Reconcile and freeze identity source of truth.**

- Ensure OAIOS chosen-identity note acknowledges the final checked-in
  compact X and two-slash W3, preserving earlier concepts as historical.
- Verify checked-in vector assets are canonical, including exact tagline,
  monochrome compact geometry and safe small-size variants.
- List remaining unfinished release assets separately (icons, fonts,
  fallback/monochrome lockups, packaging, usage rules).

**Gate V1: Visual baseline and comparison fixture.**

- Capture **sanitized** known-evidence state in the existing Stage 4 UI:
  empty, normal, dense/cap-limited, expired, conflicts, keyboard-only,
  narrow/wide windows and reduced-effects conditions.
- Record what must remain semantically and interactively identical.

**Gate V2: One screen, one component grammar.**

- Prototype the 2D Evidence workspace with NOVXIS tokens, approved
  branding and candidate shell chrome. Clearly label mock/proposed items.
- Compare with the existing UI against legibility, evidence distinction,
  keyboard behavior, density, source context and recognizability.
- Choose/finalize visual tokens and patterns after inspection, not before.

**Gate V3: Shared design system and desktop-host acceptance.**

- Establish documented design tokens and reusable components in a
  framework-independent form usable by the 2D/desktop shell and informing
  later 3D HUD design.
- Implement in small testable increments only after the desktop-host
  architecture choice or after confirming those components are host-neutral.
- Add automated contrast/asset/content checks and manual Safari plus
  embedded-webview acceptance on consistent fixtures; avoid an untested
  all-at-once CSS rewrite.

## 7. Product definition of done

A UI change ships only if it improves product coherence **without**
changing the networking truth. It must retain valid evidence ID and
provenance, accessible interactions, no secretly authorized probes,
repeatable data-driven inspection, stable window lifecycle, and a
reversible incremental integration plan.

**Decision needed at review:** Approve the established logo family and
desktop product character as the immutable starting identity, then
explicitly identify which proposed color, typography, navigation and
component choices should be upgraded to implementation standards.
This document is a proposal, not a claim that those choices have been
approved or coded.

## References

- [Brand asset sources and revision chronology](../../assets/branding/README.md)
- [Full-size icon](../../assets/branding/source/x-junction.svg)
- [Compact Corner Frame X](../../assets/branding/source/x-junction-compact.svg)
- [W3 wordmark](../../assets/branding/source/w3-tech-stripe.svg)
- [Horizontal lockup](../../assets/branding/source/novxis-lockup-horizontal.svg)
- [Desktop architecture pivot](../architecture/0003-desktop-product-pivot-proposal.md)
- [Stage 4 closeout](../implementation/2026-11-14-stage4-closure.md)
