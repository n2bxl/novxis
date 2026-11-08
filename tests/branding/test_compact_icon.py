"""Contract and optional raster checks for the Corner Frame X compact icon."""
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

NS = "{http://www.w3.org/2000/svg}"
SOURCE = Path(__file__).resolve().parents[2] / "assets" / "branding" / "source"

ICON_FILES = (
    "x-junction-compact.svg",
    "monochrome/x-junction-compact-white.svg",
    "monochrome/x-junction-compact-black.svg",
)
EXPECTED_BRACKETS = (
    "bracket-upper-left",
    "bracket-upper-right",
    "bracket-lower-left",
    "bracket-lower-right",
)
EXPECTED_X = "M33 31 H47 L64 49 L81 31 H95 V45 L77 64 L95 83 V97 H81 L64 79 L47 97 H33 V83 L51 64 L33 45 Z"


def icon_tree(name):
    return ET.parse(SOURCE / name).getroot()


def by_id(root, identifier):
    return next(node for node in root.iter() if node.attrib.get("id") == identifier)


def groups_and_paths(name):
    root = icon_tree(name)
    brackets = by_id(root, "corner-brackets")
    symbol = by_id(root, "connected-x")
    return root, brackets.findall(f"{NS}path"), symbol.findall(f"{NS}path")


@pytest.mark.parametrize("name", ICON_FILES)
def test_compact_artwork_has_four_open_brackets_and_one_connected_x(name):
    root, corners, symbol = groups_and_paths(name)
    assert root.attrib["viewBox"] == "0 0 128 128"
    assert [path.attrib.get("id") for path in corners] == list(EXPECTED_BRACKETS)
    assert len(symbol) == 1
    assert symbol[0].attrib["id"] == "x-silhouette"
    assert symbol[0].attrib["d"] == EXPECTED_X
    assert len(list(root.iter(f"{NS}rect"))) == 0  # not a generic framed checkbox
    assert len(list(root.iter(f"{NS}text"))) == 0  # font-independent
    assert len(list(root.iter(f"{NS}use"))) == 0  # all paths self-contained


def test_compact_artwork_has_no_plus_or_green_and_preserves_cyan_corners():
    root, corners, symbol = groups_and_paths(ICON_FILES[0])
    assert by_id(root, "corner-brackets").attrib["fill"] == "#76D8DE"
    assert by_id(root, "connected-x").attrib["fill"] == "#AF9600"
    assert "#88E6A1" not in (SOURCE / ICON_FILES[0]).read_text()
    assert len(corners) == 4
    assert len(symbol) == 1


@pytest.mark.parametrize("name,color", [
    (ICON_FILES[1], "#FFFFFF"),
    (ICON_FILES[2], "#000000"),
])
def test_monochrome_uses_one_color_without_changing_geometry(name, color):
    baseline, base_corners, base_x = groups_and_paths(ICON_FILES[0])
    root, corners, symbol = groups_and_paths(name)
    assert [p.attrib["d"] for p in corners] == [p.attrib["d"] for p in base_corners]
    assert [p.attrib["d"] for p in symbol] == [p.attrib["d"] for p in base_x]
    assert {g.attrib["fill"] for g in (by_id(root, "corner-brackets"), by_id(root, "connected-x"))} == {color}
    assert len(list(root.iter(f"{NS}rect"))) == 0


@pytest.mark.parametrize("name", ICON_FILES)
@pytest.mark.parametrize("size", [16, 32, 64])
def test_optional_small_size_raster_is_nonblank_and_transparent(name, size):
    cairosvg = pytest.importorskip("cairosvg")
    image_module = pytest.importorskip("PIL.Image")
    png = cairosvg.svg2png(
        url=str(SOURCE / name),
        output_width=size,
        output_height=size,
    )
    image = image_module.open(BytesIO(png)).convert("RGBA")
    assert image.size == (size, size)
    alpha = image.getchannel("A")
    assert alpha.getextrema() == (0, 255)
    opaque_pixels = sum(1 for a in alpha.getdata() if a >= 128)
    assert size <= opaque_pixels < (size * size * 0.65)
