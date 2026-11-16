#!/usr/bin/env python3
"""Renders every PhoneConnect icon from one description of the mark.

The identity is the one this project already ships: a white ring, a cyan core, and a white
centre dot on a shaded teal tile. Everything here derives from that, so one edit updates the
Android agent, the web UI, and the desktop shell together.

    python3 scripts/generate-icons.py

Needs only Pillow. The outputs are committed, so CI never renders icons.

Geometry is expressed as radii of the **outer ring**, measured from the shipped 512 px
artwork: ring 179.2 px, inner edge 151.2, disc 129.1, dot 59.1.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass

from PIL import Image, ImageDraw

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The palette the shipped artwork used (Tailwind teal/cyan).
BACKGROUND_TOP = (15, 118, 110)     # #0f766e teal-700
BACKGROUND_BOTTOM = (17, 94, 89)    # #115e59 teal-800, one step deeper for a little depth
ACCENT = (45, 212, 191)             # #2dd4bf teal-400
FOREGROUND = (236, 254, 255)        # #ecfeff cyan-50

# Radii as fractions of the outer ring radius.
RING_INNER = 151.2 / 179.2
DISC = 129.1 / 179.2
DOT = 59.1 / 179.2

SUPERSAMPLE = 4


@dataclass(frozen=True)
class Mark:
    """The mark's proportions. Defaults are the shipped artwork."""

    ring_inner: float = RING_INNER
    disc: float = DISC
    dot: float = DOT


# A small-size variant: a thicker ring and a bigger dot keep the mark legible at 16 px.
SMALL = Mark(ring_inner=0.80, disc=0.72, dot=0.36)


def _vertical_gradient(size: int) -> Image.Image:
    column = Image.new("RGB", (1, size))
    draw = ImageDraw.Draw(column)
    for y in range(size):
        t = y / max(size - 1, 1)
        draw.point(
            (0, y),
            fill=tuple(
                round(top + (bottom - top) * t)
                for top, bottom in zip(BACKGROUND_TOP, BACKGROUND_BOTTOM)
            ),
        )
    return column.resize((size, size))


def _rounded(size: int, radius_ratio: float) -> Image.Image:
    """A shaded rounded square, drawn large and reduced for clean edges."""
    box = size * SUPERSAMPLE
    mask = Image.new("L", (box, box), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, box - 1, box - 1), radius=round(box * radius_ratio), fill=255
    )
    tile = Image.new("RGBA", (box, box), (0, 0, 0, 0))
    tile.paste(_vertical_gradient(box), (0, 0), mask)
    return tile.resize((size, size), Image.LANCZOS)


def _mark(size: int, diameter: float, mark: Mark = Mark()) -> Image.Image:
    """Ring, disc, and dot on transparency.

    `diameter` is the outer ring's diameter as a fraction of `size`; it is how the adaptive
    icon keeps the artwork inside Android's 66/108 safe zone.
    """
    box = size * SUPERSAMPLE
    layer = Image.new("RGBA", (box, box), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    outer = diameter * box / 2
    cx = cy = box / 2

    def disc_at(radius: float, fill) -> None:
        draw.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), fill=fill)

    disc_at(outer, FOREGROUND + (255,))
    disc_at(outer * mark.ring_inner, (0, 0, 0, 0))
    disc_at(outer * mark.disc, ACCENT + (255,))
    disc_at(outer * mark.dot, FOREGROUND + (255,))
    return layer.resize((size, size), Image.LANCZOS)


def app_tile(size: int, mark: Mark = Mark()) -> Image.Image:
    """The app icon: a rounded tile with the mark centred."""
    tile = _rounded(size, 0.2237)
    tile.alpha_composite(_mark(size, 0.70, mark))
    return tile


def macos_tile(size: int) -> Image.Image:
    """macOS draws icons on a 1024 grid with the artwork inset to about 82%."""
    box = size * SUPERSAMPLE
    canvas = Image.new("RGBA", (box, box), (0, 0, 0, 0))
    inner = round(box * 0.82)
    canvas.alpha_composite(_rounded(inner, 0.2237), ((box - inner) // 2, (box - inner) // 2))
    canvas = canvas.resize((size, size), Image.LANCZOS)
    # The mark is composited after the reduction so it keeps the size it had at 1:1.
    canvas.alpha_composite(_mark(size, 0.70 * 0.82))
    return canvas


def write(path: pathlib.Path, image: Image.Image, **kwargs) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, **kwargs)
    print(f"  {path.relative_to(ROOT)}  {image.size[0]}x{image.size[1]}")


def build_desktop() -> None:
    icons = ROOT / "native" / "icons"
    write(icons / "icon.png", macos_tile(1024))
    write(icons / "32x32.png", app_tile(32, SMALL))
    write(icons / "128x128.png", app_tile(128))
    write(icons / "128x128@2x.png", app_tile(256))

    # BMP entries for every size: the Windows resource compiler reads them, and only a 256 px
    # entry would otherwise depend on PNG support.
    frames = {s: app_tile(s, SMALL if s <= 32 else Mark()) for s in (16, 24, 32, 48, 64, 128, 256)}
    write(
        icons / "icon.ico",
        frames[256],
        format="ICO",
        sizes=[(s, s) for s in sorted(frames)],
        append_images=[frames[s] for s in sorted(frames) if s != 256],
        bitmap_format="bmp",
    )

    icns_sizes = (16, 32, 64, 128, 256, 512, 1024)
    icns = {s: macos_tile(s) for s in icns_sizes}
    write(
        icons / "icon.icns",
        icns[1024],
        format="ICNS",
        append_images=[icns[s] for s in icns_sizes if s != 1024],
    )


def build_web() -> None:
    public = ROOT / "web" / "public"
    write(public / "favicon-16.png", app_tile(16, SMALL))
    write(public / "favicon-32.png", app_tile(32, SMALL))
    write(public / "favicon-48.png", app_tile(48))
    write(public / "apple-touch-icon.png", app_tile(180))
    write(public / "icon-192.png", app_tile(192))
    write(public / "icon-512.png", app_tile(512))

    # A maskable icon needs its artwork inside the safe circle, so the mark is smaller.
    maskable = _rounded(512, 0.2237)
    maskable.alpha_composite(_mark(512, 0.56))
    write(public / "icon-maskable-512.png", maskable)

    ico = {s: app_tile(s, SMALL if s <= 32 else Mark()) for s in (16, 32, 48)}
    write(
        public / "favicon.ico",
        ico[48],
        format="ICO",
        sizes=[(s, s) for s in sorted(ico)],
        append_images=[ico[s] for s in sorted(ico) if s != 48],
    )


def build_android() -> None:
    """Only the store icon is rasterised.

    `minSdk` is 28, so every supported device reads the adaptive icon in `mipmap-anydpi`;
    density-specific PNGs would be dead weight in the APK and lint rejects them for filling
    the square. The foreground, background, and monochrome layers are hand-written vectors
    under `res/drawable` and `res/mipmap-anydpi*`.
    """
    write(ROOT / "assets" / "play-store-icon-512.png", app_tile(512))


def main() -> None:
    print("desktop shell")
    build_desktop()
    print("web UI")
    build_web()
    print("android agent")
    build_android()


if __name__ == "__main__":
    main()
