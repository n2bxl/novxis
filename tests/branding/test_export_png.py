"""Focused checks for reproducible branding PNG exports."""

import json
import sys
from pathlib import Path

import pytest
from PIL import Image

TOOLS = Path(__file__).resolve().parents[2] / "tools" / "branding"
sys.path.insert(0, str(TOOLS))
import export_png  # noqa: E402


def test_export_and_check_are_repeatable(tmp_path):
    assert export_png.main(["--output-dir", str(tmp_path)]) == 0
    manifest_path = tmp_path / "manifest.json"
    first_manifest = manifest_path.read_bytes()
    manifest = json.loads(first_manifest)
    assert manifest["schema_version"] == 1
    assert len(manifest["assets"]) == 22
    assert "timestamp" not in manifest
    for entry in manifest["assets"]:
        output = tmp_path / entry["file"]
        assert output.is_file()
        assert export_png.sha256(output.read_bytes()) == entry["png_sha256"]
        assert entry["width"] == entry["height"]
        with Image.open(output) as image:
            assert image.format == "PNG"
            assert image.size == (entry["width"], entry["height"])
    assert export_png.main(["--check", "--output-dir", str(tmp_path)]) == 0
    assert manifest_path.read_bytes() == first_manifest


def test_check_detects_tampering_missing_and_extra_files(tmp_path):
    assert export_png.main(["--output-dir", str(tmp_path)]) == 0
    image = tmp_path / "compact-color-16.png"
    image.write_bytes(b"changed")
    assert export_png.main(["--check", "--output-dir", str(tmp_path)]) == 1
    assert export_png.main(["--output-dir", str(tmp_path)]) == 0
    (tmp_path / "unexpected.png").write_bytes(b"unused")
    assert export_png.main(["--check", "--output-dir", str(tmp_path)]) == 1
    (tmp_path / "unexpected.png").unlink()
    (tmp_path / "full-color-64.png").unlink()
    assert export_png.main(["--check", "--output-dir", str(tmp_path)]) == 1


@pytest.mark.parametrize("payload", [
    b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.com/image.png"/></svg>',
    b'<!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg"/>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><path fill="#FF0000" d="M1 1"/></svg>',
])
def test_rejects_noncanonical_svg(payload):
    with pytest.raises(ValueError):
        export_png.validate_svg(payload, export_png.EXPORTS[0])


def test_default_destination_is_gitignored():
    root = Path(__file__).resolve().parents[2]
    assert "assets/branding/exports/" in (root / ".gitignore").read_text()
    assert export_png.DEFAULT_OUTPUT == root / "assets/branding/exports/png"
