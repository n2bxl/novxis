"""Static self-containment checks for NOVXIS branding source SVGs."""
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

NS = "{http://www.w3.org/2000/svg}"
REPO = Path(__file__).resolve().parents[2]
BRANDING = REPO / "assets" / "branding" / "source"


def parse(name: str):
    return ET.parse(BRANDING / name).getroot()


def group(root, identity: str):
    return next(element for element in root.iter() if element.attrib.get("id") == identity)


@pytest.mark.parametrize(
    "name",
    ["x-junction.svg", "x-junction-compact.svg", "w3-tech-stripe.svg", "novxis-lockup-horizontal.svg"],
)
def test_sources_parse_and_have_no_external_images_or_scripts(name):
    root = parse(name)
    assert root.tag == f"{NS}svg"
    assert "viewBox" in root.attrib
    forbidden = {"image", "script", "foreignObject", "filter", "animate", "set"}
    for element in root.iter():
        assert element.tag.removeprefix(NS) not in forbidden
        assert not any(k.endswith("href") for k in element.attrib)


def test_w3_wordmark_is_six_custom_letter_paths_and_three_stripes():
    root = parse("w3-tech-stripe.svg")
    assert root.attrib["viewBox"] == "0 0 620 72"
    paths = group(root, "w3-tech-stripe").findall(f"{NS}path")
    assert [p.attrib["id"] for p in paths] == [
        "letter-N", "letter-O", "letter-V", "letter-X", "letter-I", "letter-S",
        "stripe-1", "stripe-2", "stripe-3",
    ]
    assert not list(root.iter(f"{NS}text"))
    assert all(path.attrib["d"] for path in paths)


def test_lockup_uses_identical_wordmark_and_icon_paths():
    lockup = parse("novxis-lockup-horizontal.svg")
    source_wordmark = group(parse("w3-tech-stripe.svg"), "w3-tech-stripe")
    lockup_wordmark = group(lockup, "w3-tech-stripe")
    expected = [(p.attrib["id"], p.attrib["d"]) for p in source_wordmark.findall(f"{NS}path")]
    actual = [(p.attrib["id"], p.attrib["d"]) for p in lockup_wordmark.findall(f"{NS}path")]
    assert actual == expected

    original_icon = [p.attrib["d"] for p in parse("x-junction.svg").iter(f"{NS}path")]
    embedded_icon = [p.attrib["d"] for p in group(lockup, "selected-x-junction-icon").iter(f"{NS}path")]
    assert embedded_icon == original_icon


def test_tagline_has_exact_approved_copy():
    lockup = parse("novxis-lockup-horizontal.svg")
    tagline = group(lockup, "brand-tagline")
    assert tagline.attrib["aria-label"] == "> OBSERVE / VISUALIZE / EXPLORE"
    texts = tagline.findall(f"{NS}text")
    assert [t.text for t in texts] == [">", "OBSERVE / VISUALIZE / EXPLORE"]
    assert [t.attrib["fill"] for t in texts] == ["#88E6A1", "#76D8DE"]
    assert all(t.attrib["font-weight"] == "500" for t in texts)
    assert all(t.attrib["font-size"] == "32" for t in texts)
    assert all(t.attrib["y"] == "200" for t in texts)
    # Larger 32px mono glyphs nearly fill the N-to-S width naturally,
    # reducing the need for exaggerated inter-character tracking.
    assert len(texts[1].text) == 29
    assert abs(len(texts[1].text) * 32 * 0.6 - float(texts[1].attrib["textLength"])) <= 3
    assert all("IBM Plex Mono" in t.attrib["font-family"] for t in texts)


def test_tagline_aligns_with_novxis_letters_not_stripes():
    lockup = parse("novxis-lockup-horizontal.svg")
    tagline = group(lockup, "brand-tagline")
    prompt, words = tagline.findall(f"{NS}text")

    # The wordmark's N begins at local x=0; the S ends at local x=443.
    # Its parent transform is translate(293,43) scale(1.32).
    letters_left = 293
    letters_right = letters_left + 443 * 1.32
    stripes_begin = letters_left + 463 * 1.32

    assert float(prompt.attrib["x"]) == letters_left
    assert float(words.attrib["x"]) > float(prompt.attrib["x"])
    assert words.attrib["lengthAdjust"] == "spacing"  # no glyph stretching
    words_right = float(words.attrib["x"]) + float(words.attrib["textLength"])
    assert abs(words_right - letters_right) <= 1.0
    assert words_right < stripes_begin


def test_svg_palette_and_no_embedded_background():
    word = parse("w3-tech-stripe.svg")
    lockup = parse("novxis-lockup-horizontal.svg")
    assert group(word, "w3-tech-stripe").attrib["fill"] == "#AF9600"
    assert any(e.attrib.get("fill") == "#88E6A1" for e in lockup.iter())
    assert any(e.attrib.get("fill") == "#76D8DE" for e in lockup.iter())
    assert len(list(lockup.iter(f"{NS}rect"))) == 1  # the narrow separator only
