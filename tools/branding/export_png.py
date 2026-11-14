"""Generate and verify NOVXIS PNG icons from the approved SVG sources.

Not installed as a NOVXIS runtime command; optional branding developer tooling.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "assets" / "branding" / "source"
DEFAULT_OUTPUT = ROOT / "assets" / "branding" / "exports" / "png"
MANIFEST_NAME = "manifest.json"
PNG_SIZES = (16, 32, 64, 128, 256, 512)
SVG_NS = "{http://www.w3.org/2000/svg}"
ALLOWED_ELEMENTS = {"svg", "title", "desc", "g", "path"}


@dataclass(frozen=True)
class ExportSpec:
    name: str
    source: str
    sizes: tuple[int, ...]
    colors: frozenset[str]


EXPORTS = (
    ExportSpec(
        "full-color", "x-junction.svg", (64, 128, 256, 512),
        frozenset({"#AF9600", "#76D8DE", "#88E6A1"}),
    ),
    ExportSpec(
        "compact-color", "x-junction-compact.svg", PNG_SIZES,
        frozenset({"#AF9600", "#76D8DE"}),
    ),
    ExportSpec(
        "compact-white", "monochrome/x-junction-compact-white.svg", PNG_SIZES,
        frozenset({"#FFFFFF"}),
    ),
    ExportSpec(
        "compact-black", "monochrome/x-junction-compact-black.svg", PNG_SIZES,
        frozenset({"#000000"}),
    ),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_svg(source: bytes, spec: ExportSpec) -> None:
    """Block external SVG resources and unintended visual changes."""
    if b"<!DOCTYPE" in source.upper() or b"<!ENTITY" in source.upper():
        raise ValueError(f"{spec.source}: DTD or entities are not allowed")
    root = ElementTree.fromstring(source)
    if root.tag != SVG_NS + "svg":
        raise ValueError(f"{spec.source}: invalid SVG root")
    fills = set()
    for node in root.iter():
        tag = node.tag.removeprefix(SVG_NS)
        if tag not in ALLOWED_ELEMENTS:
            raise ValueError(f"{spec.source}: unsupported SVG element {tag}")
        for attribute, value in node.attrib.items():
            if attribute.lower().endswith("href") or "url(" in value.lower():
                raise ValueError(f"{spec.source}: external references are not allowed")
        if "fill" in node.attrib:
            fills.add(node.attrib["fill"].upper())
    if fills != spec.colors:
        raise ValueError(f"{spec.source}: palette changed: {sorted(fills)}")


def render_png(svg: bytes, size: int, allowed_colors: frozenset[str]) -> bytes:
    import cairosvg  # Optional, not part of NOVXIS runtime dependencies.
    from PIL import Image

    result = cairosvg.svg2png(bytestring=svg, output_width=size, output_height=size)
    image = Image.open(BytesIO(result)).convert("RGBA")
    if image.size != (size, size):
        raise ValueError(f"unexpected PNG dimensions: {image.size}")
    alpha_min, alpha_max = image.getchannel("A").getextrema()
    if (alpha_min, alpha_max) != (0, 255):
        raise ValueError("generated icon must contain both transparency and opaque pixels")
    expected = {tuple(bytes.fromhex(value[1:])) for value in allowed_colors}
    pixels = image.tobytes()
    opaque_colors = {tuple(pixels[i:i + 3]) for i in range(0, len(pixels), 4)
                     if pixels[i + 3] == 255}
    if not opaque_colors or not opaque_colors.issubset(expected):
        raise ValueError(f"unexpected opaque PNG colors: {sorted(opaque_colors)}")
    return result


def make_exports() -> tuple[dict[str, bytes], bytes]:
    import cairosvg

    files: dict[str, bytes] = {}
    entries = []
    for spec in EXPORTS:
        source = (SOURCES / spec.source).read_bytes()
        validate_svg(source, spec)
        for size in spec.sizes:
            name = f"{spec.name}-{size}.png"
            png = render_png(source, size, spec.colors)
            files[name] = png
            entries.append({
                "file": name,
                "source": f"assets/branding/source/{spec.source}",
                "source_sha256": sha256(source),
                "width": size,
                "height": size,
                "png_sha256": sha256(png),
            })
    manifest = {
        "schema_version": 1,
        "renderer": f"CairoSVG {cairosvg.__version__}",
        "format": "PNG", "background": "transparent",
        "assets": entries,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return files, manifest_bytes


def export(output_dir: Path, check: bool) -> int:
    files, manifest = make_exports()
    files[MANIFEST_NAME] = manifest
    if check:
        mismatches = []
        for name, expected in files.items():
            path = output_dir / name
            if not path.is_file() or path.read_bytes() != expected:
                mismatches.append(name)
        extras = sorted(p.name for p in output_dir.glob("*.png") if p.name not in files)
        if mismatches or extras:
            print(f"Export check failed: mismatched/missing={mismatches}; unexpected={extras}", file=sys.stderr)
            return 1
        print(f"Verified {len(files) - 1} PNGs and manifest in {output_dir}")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (output_dir / name).write_bytes(data)
    print(f"Exported {len(files) - 1} PNGs and manifest to {output_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT,
                        help="Generated PNG folder (default: assets/branding/exports/png)")
    parser.add_argument("--check", action="store_true",
                        help="Verify exported file contents, hashes, dimensions and file set")
    args = parser.parse_args(argv)
    try:
        return export(args.output_dir, args.check)
    except (ImportError, OSError, ValueError, ElementTree.ParseError) as exc:
        print(f"Brand export failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
