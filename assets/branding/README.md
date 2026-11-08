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
| `source/x-junction-compact.svg` | Same *gold/green core geometry*, without brackets, enlarged optically for 16–32 px |

Both files are transparent vector originals, with no external font,
filter, pixel image, script, or background. The compact version uses the
same central and gold paths with a tighter viewBox; it is a derived
size variant, **not** a redesign of the approved primary mark.

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
- Before platform packaging, still test monochrome, light background,
  reduced visual effects, and platform icon silhouettes.

Simple XML sanity check:

```bash
python - <<'PY'
from xml.etree import ElementTree as ET
for name, expected in (
    ("x-junction", "0 0 2000 2000"),
    ("x-junction-compact", "300 300 1400 1400"),
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

## Next assets

1. Create the approved **W3 Tech Stripe** wordmark with original,
   reproducible vector lettering.
2. Assemble an icon + wordmark lockup with the exact tagline
   `> OBSERVE / VISUALIZE / EXPLORE`.
3. Develop monochrome and platform exports, ASCII/TUI companion
   `[>+<] NOVXIS`, and export validation tooling.

The original Phase A branch does not modify the NOVXIS 2D evidence
explorer, network evidence graph, parser/state logic, or UI styling.
