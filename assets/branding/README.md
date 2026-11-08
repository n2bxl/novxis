# NOVXIS branding assets

**Phase A: X-Junction vector foundations**  
**Status:** Initial review candidates, not final approved production vectors.

This directory contains editable, deterministic SVG geometry for the
approved NOVXIS **Concept A / X-Junction** creative direction. The selected
reference board remains in OAIOS at
`07 - ATTACHMENTS/NOVXIS - Selected Identity Concept - 2026-11-08.png`.

The approved *concept* and this new vector drawing are distinct: these SVGs
are intentional geometric reconstructions, **not automatically vectorized
copies** or pixel-identical exports of the generated design board.

## Sources

| File | Role |
| --- | --- |
| `source/x-junction.svg` | Full icon: four bold angular gold arms, a green center plus, cyan corner brackets |
| `source/x-junction-compact.svg` | Optical-size candidate: larger gold silhouette, green center, brackets removed for small applications |

Both SVGs:
- Have transparent backgrounds and an explicit `128 × 128` viewBox.
- Use filled, square-edged geometry rather than hairline strokes.
- Use **no** animation, blur, filters, raster image references, or external fonts.
- Preserve **no horizontal bars** beside the central green plus.
- Include simple titles/descriptions and no network-semantic claims.

## Colors (candidate visual-system tokens)

| Treatment | Hex |
| --- | --- |
| NOVXIS old gold | `#AF9600` |
| Phosphor green | `#88E6A1` |
| Cyan structural brackets | `#76D8DE` |

These are the visual-system palette proposals, **not colors picked from the
generated bitmap**. The concept image may look brighter due to its artistic
lighting. Brand graphics may use phosphor decoration, but application signal
effects must still convey specific, supportable events or focus.

## Size-testing and review gates

The full and compact SVGs were independently parsed as XML and rasterized
with CairoSVG at **128, 64, 32, and 16 px** as a design smoke test.
The PNG rasterizations were inspected during this design pass but are **not**
checked into source control because they are reproducible derivatives.

- `128/64 px`: review the full-bracket icon.
- `32/16 px`: review the compact geometric variant for optical legibility.
- Confirm recognizability at **native actual sizes**, with glow disabled.
- Test on dark, light, grayscale, and monochrome backgrounds before promoting
  any variant to final production status.
- Check device-specific exports and color contrast before declaring favicon,
  dock-icon, mobile, or OS package readiness.

SVG validation example (optional local development tools):

```bash
python - <<'PY'
from xml.etree import ElementTree as ET
for path in (
    "assets/branding/source/x-junction.svg",
    "assets/branding/source/x-junction-compact.svg",
):
    root = ET.parse(path).getroot()
    assert root.attrib["viewBox"] == "0 0 128 128"
    print(path, "OK")
PY
```

Example rasterization (requires optional `cairosvg`, not a NOVXIS runtime
dependency):

```bash
python - <<'PY'
import cairosvg
for size in (128, 64, 32, 16):
    variant = "x-junction-compact" if size <= 32 else "x-junction"
    cairosvg.svg2png(
        url=f"assets/branding/source/{variant}.svg",
        write_to=f"/tmp/novxis-{variant}-{size}.png",
        output_width=size,
        output_height=size,
    )
PY
```

## Next in this branding sprint

1. Gather approval or edits on the **actual vector shapes** at full and
   compact sizes.
2. Build the approved **W3 Tech Stripe** wordmark as reproducible custom
   vector geometry, not a raster crop or an unmodified monospace font.
3. Combine the icon and wordmark into a transparent lockup featuring the exact
   tagline: `> OBSERVE / VISUALIZE / EXPLORE`.
4. Develop monochrome and high-contrast variants, a terminal-compatible
   `[>+<] NOVXIS` companion, and a scripted export/asset-validation pipeline.
5. Integrate into the actual NOVXIS UI only after asset review. The existing
   2D evidence explorer and its networking semantics are unchanged.

This phase intentionally does **not** pick a desktop packaging framework,
introduce an animated logo, or rewrite any application UI.
