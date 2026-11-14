# NOVXIS branding assets

**Phase A: X-Junction vector foundations**  
**Direction:** User-approved Canva X-Junction draft, 2026-11-08  
**Scope:** Editable logo geometry only. No application runtime or UI changes.

## Selected icon

The approved mark is the **Canva draft** selected after the original
Concept A exploration. Its recognizable parts are:

- Four broad, gold, angular arms, separated from the center.
- An enlarged phosphor-green `+` in the center, **without** horizontal dashes.
- Four substantial cyan right-angle corner brackets.
- Flat fills, hard geometry, and no bloom required for legibility.

These SVG paths reconstruct the approved Canva design in a transparent
**2000 × 2000 coordinate system**. They preserve its established proportions;
the near-symmetric vector paths smooth out only negligible raster-edge
irregularities. The earlier thinner, smaller-plus SVG was superseded.

| File | Intended use |
| --- | --- |
| `source/x-junction.svg` | Full-fidelity icon with cyan corner brackets |
| `source/x-junction-compact.svg` | **Phase C1 Corner Frame X:** continuous gold X with cyan open-corner brackets; optimized for small sizes |

Both files are transparent vector originals, with no external font,
filter, pixel image, script, or background. **As of Phase C1, the compact
mark intentionally differs from the full mark:** it preserves the four
corner brackets but replaces the four separated gold arms and green plus
with one continuous gold X. The full-size Canva-derived mark remains
unchanged.

The Canva PNG supplied for this approval is the visual reference for this
vector update. The earlier selected concept exploration board remains
preserved in OAIOS at
`07 - ATTACHMENTS/NOVXIS - Selected Identity Concept - 2026-11-08.png`.
The OAIOS board and the newer user-created Canva draft are **distinct** images.
The Canva source PNG is not yet tracked in this NOVXIS branch.

## Palette

| Treatment | Hex |
| --- | --- |
| NOVXIS gold | `#AF9600` |
| Phosphor green | `#88E6A1` |
| Cyan brackets | `#76D8DE` |

These exact source colors match the user's supplied flat-color Canva draft.
They also match the NOVXIS visual-system candidate color tokens. All
three are decorative **brand colors**, not a live network health/status key.

## Validation and usage

The revised SVGs were parsed successfully and rasterized at
**128, 64, 32, and 16 pixels** using CairoSVG. A direct 2000 px comparison
against the supplied Canva PNG matched the cyan bracket and green plus
solid-fill masks exactly. The gold arms achieved approximately **98.4%
intersection-over-union** with the reference's exact solid-fill mask; the
remaining difference arises from intentional symmetric path normalization
and raster edges. At ordinary sizes the overall composition closely matches
the approved draft.

Review conventions:

- Use the **full** SVG for 64–128 px and larger applications.
- Use the **compact** SVG for 16–32 px where corner details compete.
- Inspect rasterizations at their **native pixel sizes**.
- Preserve the full SVG as the canonical artistic source. Do not edit
  its geometry solely to optimize the compact version.
- Before platform packaging, still test light background, reduced visual
  effects, and platform icon silhouettes.

Simple XML sanity check:

```bash
python - <<'PY'
from xml.etree import ElementTree as ET
for name, expected in (
    ("x-junction", "0 0 2000 2000"),
    ("x-junction-compact", "0 0 128 128"),
):
    path = f"assets/branding/source/{name}.svg"
    root = ET.parse(path).getroot()
    assert root.attrib["viewBox"] == expected
    print(path, "OK")
PY
```

Optional local PNG export (requires `cairosvg`, not a NOVXIS
runtime dependency):

```bash
python - <<'PY'
import cairosvg
for px in (128, 64, 32, 16):
    name = "x-junction-compact" if px <= 32 else "x-junction"
    cairosvg.svg2png(
        url=f"assets/branding/source/{name}.svg",
        write_to=f"/tmp/novxis-{name}-{px}.png",
        output_width=px,
        output_height=px,
    )
PY
```

## Phase B: W3 wordmark and horizontal lockup

**Status:** First vector implementation of the **selected W3 Tech Stripe
creative direction**, ready for visual review. The original X-junction
geometry from the merged Phase A assets is unchanged.

| File | Role |
| --- | --- |
| `source/w3-tech-stripe.svg` | Transparent, bespoke gold NOVXIS lettering, followed by two narrow gold forward slashes |
| `source/novxis-lockup-horizontal.svg` | Self-contained full Concept A icon, separator, W3 wordmark and exact tagline |

The W3 source uses **six separate original geometric letter paths**
(`N`, `O`, `V`, `X`, `I`, `S`) and **two independent forward-slash paths**.
The wordmark itself uses **no font, image, glow, script or external dependency**.
Its viewBox is `0 0 552 72` and its appearance follows the angular W3
concept without claiming pixel-identical tracing of the concept board.

The horizontal lockup has a `0 0 1200 250` viewBox, and embeds
**exact copies of the merged canonical X-junction SVG paths and the new W3
wordmark paths**, rather than referencing another file at runtime.
It uses the exact tagline:

```text
> OBSERVE / VISUALIZE / EXPLORE
```

The tagline is *editable live SVG text* using **IBM Plex Mono when installed**
with DejaVu Sans Mono / monospace fallbacks. Unlike the icon and wordmark
paths, its typography can vary across machines without the preferred font.
No font file is shipped. Final font selection and/or tagline outlining
remain an explicit production-readiness decision.

### Refined tagline treatment (approved styling, PR #56)

- Prompt `>`: phosphor green `#88E6A1`.
- `OBSERVE / VISUALIZE / EXPLORE`: uniformly cyan `#76D8DE`.
- Both text runs use `font-weight="500"` and `font-size="32"`
  (increased from the previous 24px iteration for stronger visual balance).
- The baseline is y=200; the uppercase wordmark geometry is unchanged by this tagline refinement.
- Left edge aligns with the `N` at horizontal lockup x=293.
- The tagline right edge aligns to the end of the **six-letter NOVXIS name**,
  excluding the appended forward slashes: `293 + 443 × 1.32 = 877.76`.
- The cyan text begins at x=323 and uses `textLength="555"`, ending
  at x=878. With 29 monospace characters, 32px text naturally approaches
  that target width; `lengthAdjust="spacing"` makes only a small adjustment
  **without stretching the individual glyph shapes**.
- Renderers that ignore SVG `textLength` may display a shorter tagline.
  Test in target browsers (including Safari) before final export, and
  consider outlining the confirmed font as a later production fallback.

The headline lettering and icon are unaffected by the tagline refinement.

### W3 punctuation revision: two forward slashes

After reviewing the first full lockup, the user chose to replace the three
thick decorative stripes with **two narrower forward slashes**. This is a
deliberate move toward terminal/path typography, not a racing-stripe motif.

- Two gold `/` paths, not three.
- Each slash is **15 SVG units wide horizontally**, matching the visual
  thickness of the roughly 16-unit W3 letter strokes.
- Separate, crisp forward-leaning parallelogram paths; no blur or stroke filter.
- The slashes follow the `S` with measured spacing, like appended punctuation.
- The standalone SVG viewBox tightens to `0 0 552 72` to avoid retaining
  unused space from the former third stripe.
- The icon, all six W3 letter paths, the separator and the larger green/cyan
  tagline remain **unchanged**.

The lockup duplicates the standalone W3 paths exactly. The revision is
subject to the same responsive rendering/optical review as the rest of the
identity assets.

### Display-size guidance

The original three-stripe wordmark was rasterized at **614, 307, and 154 px** before the double-slash revision. The combined
lockup was rasterized at **1200, 600, and 300 px**; below approximately
600 px the tagline becomes a secondary detail. Use the standalone wordmark
or icon at smaller widths, rather than shrinking the full lockup until its
tagline becomes unreadable. These are visual guidance values, not formal
minimum-size approvals.

An initial local rendering was inspected on a dark canvas. Exported PNGs
are **review derivatives**, not source files, and are not tracked in Git.

### Static validation

```bash
python -m pytest tests/branding/test_brand_svg_assets.py -q
```

The focused tests validate SVG/XML parsing, expected letter and slash
paths, exact reuse of canonical icon and standalone wordmark paths inside
the lockup, the approved tagline, flat palette, and absence of embedded
scripts/images. **8 focused tests passed locally** during the initial Phase B preparation; rerun the suite to validate the revised double-slash artwork.
No full NOVXIS networking regression suite was run for these static assets.
This branch does not modify application behavior or introduce rendering
dependencies into the NOVXIS runtime.

## Phase C1: Corner Frame X compact icon and monochrome foundations

**Design selected:** *Corner Frame X* (concept C), approved on 2026-11-08.
It is a small-size identity mark, **not** a generic close, cancel, or
checkbox icon. The earlier compact mark with separated gold arms and a
green center plus has been replaced; the approved full-size mark, wordmark,
and horizontal lockup are unchanged.

| Asset | Purpose |
| --- | --- |
| `source/x-junction-compact.svg` | Canonical full-color compact: connected gold X and cyan open-corner frame |
| `source/monochrome/x-junction-compact-white.svg` | Same exact paths, all-white, transparent background for dark surfaces |
| `source/monochrome/x-junction-compact-black.svg` | Same exact paths, all-black, transparent background for light surfaces |

**Geometry contract:** each file uses `viewBox="0 0 128 128"`,
contains **four separate cyan (or monochrome) L-shaped corner brackets**
and **one connected X path**. There is no center `+`, no enclosing
square/rectangle, and no glow. The open corners help distinguish NOVXIS
from a boxed cancellation/checkmark UI symbol. Monochrome variants do not
change any path geometry, only the fill color (`#FFFFFF` or `#000000`).

**Design usage:** use the full original `x-junction.svg` at larger sizes;
use the compact Corner Frame X in small toolbars, lists, and favicons.
Do not substitute it for actual close/delete/dismiss buttons within the
application, as that would confuse branding with an action.

### C1 validation

- Full-color and both monochrome variants were rasterized at **16, 32, 64,
  and 128 px** for visual review, on appropriate contrasting surfaces.
- The dedicated tests assert: exactly four independent corner brackets and
  one connected X, no central green plus or boxed rectangle, identical
  geometry across single-color variants, correct colors, and no live fonts.
- Optional CairoSVG + Pillow tests check nonblank transparent output at
  **16 / 32 / 64 px**; the optional packages are not runtime dependencies.
- `tests/branding/test_brand_svg_assets.py` also includes the two new mono
  files in general XML safety checks.

Run the focused test suite in a development environment:

```bash
python -m pytest tests/branding/test_compact_icon.py tests/branding/test_brand_svg_assets.py -q
```

The isolated C1 tests were exercised locally with equivalent SVG path
fixtures, including optional rasterization, with **15 passing test cases**.
That validation is not a claim that the full NOVXIS repository test suite
was executed or that Safari/final OS icon integration was verified. Before
merge, review the committed SVGs and test in Safari if desired.

### Future Phase C2

Automated multi-size PNG exports, monochrome variants of the **full-size**
lockup, terminal text-mode mark, final font portability, and
platform-specific `.icns`/`.ico` packaging remain future work.

## Phase C2: Reproducible PNG icon exports

**Scope:** Generate static PNG icons from the approved SVG source files. This is
developer-side asset tooling only. It does **not** create a macOS app bundle,
Windows icon container, distributable package, or installation artifact.

The export script is \`tools/branding/export_png.py\`. Its only optional
developer dependencies are pinned in \`tools/branding/requirements.txt\`.
Neither dependency is added to NOVXIS application runtime requirements.

| Source | Output prefix | Sizes |
| --- | --- | --- |
| \`source/x-junction.svg\` | \`full-color-\` | 64, 128, 256, 512 |
| \`source/x-junction-compact.svg\` | \`compact-color-\` | 16, 32, 64, 128, 256, 512 |
| \`source/monochrome/x-junction-compact-white.svg\` | \`compact-white-\` | 16, 32, 64, 128, 256, 512 |
| \`source/monochrome/x-junction-compact-black.svg\` | \`compact-black-\` | 16, 32, 64, 128, 256, 512 |

**Total: 22 transparent PNGs and one \`manifest.json\`.** Output goes to
\`assets/branding/exports/png/\`, which is deliberately Git-ignored. Only
the canonical SVGs and the export tooling are version-controlled.

### Run it on the M5

From the \`novxis\` repository root, after updating your branch and activating
your existing project virtual environment:

\`\`\`bash
python -m pip install -r tools/branding/requirements.txt
python tools/branding/export_png.py
python tools/branding/export_png.py --check
python -m pytest tests/branding/test_export_png.py -q
\`\`\`

If CairoSVG cannot load the Cairo shared library on macOS, install the
system Cairo runtime separately (for example \`brew install cairo\`) and retry.
This optional tooling is **not** required to run NOVXIS network capture or
the 2D browser preview.

For a scratch output directory, use
\`python tools/branding/export_png.py --output-dir /tmp/novxis-icon-exports\`.

### Reproducibility and validation

- A fixed export table selects explicit source SVGs and sizes.
- The export tool rejects unexpected SVG element types, external references,
  DTDs/entities and accidental palette changes.
- Every output is validated for dimensions, alpha transparency, and expected
  fully opaque fill colors.
- The manifest records source SHA-256, PNG SHA-256, dimensions and CairoSVG
  version in stable, sorted JSON; it does **not** include timestamps.
- \`--check\` rerenders the assets in memory and byte-compares each exported
  PNG and the manifest, detecting missing, modified and unexpected PNGs.
  It makes **no changes** in check mode.
- The exporter does not delete unknown files when writing. It overwrites its
  own known output names. Keep custom images outside the generated folder.

This yields repeatable output in the **same pinned toolchain/environment**.
We do **not** guarantee identical PNG bytes across different Cairo backends,
operating systems or rasterizer versions. Run exports and \`--check\` in the
same controlled environment for byte-level verification.

### Intentional exclusions

The W3 wordmark and horizontal lockup remain SVG masters for now. The lockup
contains editable tagline text with IBM Plex Mono and fallback behavior, so
rasterizing it across systems could change its appearance. Defer portable
outlined typography to another design review. Likewise, \`.icns\`, \`.ico\`,
app bundling, code-signing, packaging and redistribution/licensing review are
**not** part of this phase.

The focused exporter tests were run in an isolated local staging directory
with equivalent approved SVG geometries: **7 tests passed**. This does not
claim a full NOVXIS checkout/CI regression run. No application code is changed.

## Next assets

1. Review the W3 vector lettering and combined layout against the
   approved concept before calling the specific SVG geometry final.
2. Develop monochrome versions of the full icon/lockup, plus platform-specific exports.
3. Decide whether to outline the tagline in a verified IBM Plex Mono
   style for fully portable rendering.
4. Add terminal-compatible `[>+<] NOVXIS` representations and extend the
   implemented PNG exporter only when new approved vector sources are ready.

The branding branches do not modify the NOVXIS 2D evidence explorer,
network evidence graph, parser/state logic, or UI styling.
