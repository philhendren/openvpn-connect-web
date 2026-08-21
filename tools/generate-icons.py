#!/usr/bin/env python3
"""Regenerate every raster icon from the OpenVPN mark.

Run this whenever the mark or the brand colour changes:

    uv run --with pillow python tools/generate-icons.py

Needs Google Chrome on PATH (the only SVG rasteriser on this machine) and Pillow. Outputs into
app/static/img/:

    favicon.ico            16/32/48 multi-resolution, for /favicon.ico
    favicon-32.png         PNG fallback for the <link rel=icon>
    apple-touch-icon.png   180px, iOS home screen
    icon-192.png           web app manifest
    icon-512.png           web app manifest, splash screen
    icon-maskable-512.png  web app manifest, purpose=maskable

Maskable icons are cropped by the platform -- ChromeOS uses a squircle -- so that variant is
full-bleed with the mark shrunk into the middle 60%, well inside the 80% safe zone. The others
keep the rounded-square badge, which is what looks right in a browser tab.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image

BRAND = "#EA7E20"
OUT = Path("app/static/img")
MARK = (
    "M12 .357C5.385.357 0 5.69 0 12.254c0 4.36 2.358 8.153 5.896 10.204l.77-5.076a7.046 7.046 0 "
    "01-1.846-4.719c0-3.897 3.18-7.076 7.13-7.076 3.948 0 7.126 3.18 7.126 7.076 0 1.847-.717 "
    "3.488-1.846 4.77L18 22.51c3.59-2.05 6-5.899 6-10.258C24 5.69 18.615.357 12 .357zm-.05 "
    "8.157a3.786 3.786 0 00-3.796 3.795 3.738 3.738 0 002.461 3.54L9.13 23.643h5.64l-1.435-7.795"
    "c1.385-.564 2.41-1.898 2.41-3.54a3.786 3.786 0 00-3.795-3.794z"
)


def wrapper(radius: float, scale: float) -> str:
    """One 512px SVG on a transparent page. ``radius``/``scale`` are in the 24-unit viewBox."""
    offset = (24 - 24 * scale) / 2
    return f"""<!doctype html><meta charset="utf-8">
<style>html,body{{margin:0;padding:0;background:transparent}}
svg{{display:block;width:512px;height:512px}}</style>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <rect width="24" height="24" rx="{radius}" fill="{BRAND}"/>
  <g transform="translate({offset} {offset}) scale({scale})"><path fill="#fff" d="{MARK}"/></g>
</svg>"""


def render(chrome: str, html: str, destination: Path) -> Image.Image:
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "icon.html"
        page.write_text(html)
        shot = Path(tmp) / "icon.png"
        subprocess.run(  # noqa: S603 - fixed argv, all values are literals in this file
            [
                chrome,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--hide-scrollbars",
                "--default-background-color=00000000",
                "--window-size=512,512",
                f"--screenshot={shot}",
                page.as_uri(),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
        image = Image.open(shot).convert("RGBA")
        image.load()
    if destination.suffix == ".png":
        image.save(destination, optimize=True)
    return image


def main() -> int:
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome:
        print("Google Chrome is required to rasterise the SVG.", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)

    # Rounded-square badge: tab, home screen, manifest "any".
    badge = render(chrome, wrapper(radius=5, scale=0.7), OUT / "icon-512.png")
    for size, name in (
        (192, "icon-192.png"),
        (180, "apple-touch-icon.png"),
        (32, "favicon-32.png"),
    ):
        badge.resize((size, size), Image.LANCZOS).save(OUT / name, optimize=True)
    badge.save(OUT / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])

    # Full-bleed, mark shrunk into the safe zone: manifest "maskable".
    render(chrome, wrapper(radius=0, scale=0.5), OUT / "icon-maskable-512.png")

    for path in sorted(OUT.glob("*")):
        print(f"  {path.name:<24} {path.stat().st_size:>7,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
