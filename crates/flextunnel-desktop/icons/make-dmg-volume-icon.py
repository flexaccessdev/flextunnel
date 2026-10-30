# /// script
# requires-python = ">=3.13"
# dependencies = ["pillow>=11"]
# ///
"""Render icons/dmg-volume.icns: the .dmg's mounted-volume icon.

The conventional macOS installer-volume look: a plain white external drive
with the app icon on its face, rather than the bare app icon (which is what
cargo-packager's dmg format forces). The drive is drawn here, not taken from
the system's IOStorageFamily icons, so the output is ours to commit.

Run from anywhere: `uv run crates/flextunnel-desktop/icons/make-dmg-volume-icon.py`
"""

from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent
SIZE = 1024
SS = 4  # supersampling factor for the drawn shapes

# Drive geometry, in 1024-px icon coordinates.
LEFT, RIGHT, TOP, BOTTOM = 156, 868, 72, 944
RADIUS = 84
BAND_TOP = 836  # where the grey base band starts
APP_SIZE = 452
APP_CENTER_Y = (TOP + BAND_TOP) // 2 + 6


def scaled(box):
    return tuple(v * SS for v in box)


def mask(draw_fn):
    m = Image.new("L", (SIZE * SS, SIZE * SS), 0)
    draw_fn(ImageDraw.Draw(m))
    return m.resize((SIZE, SIZE), Image.LANCZOS)


def vertical_gradient(top_rgb, bottom_rgb, y0, y1):
    grad = Image.new("RGB", (1, SIZE))
    for y in range(SIZE):
        t = min(max((y - y0) / max(y1 - y0, 1), 0.0), 1.0)
        grad.putpixel((0, y), tuple(round(a + (b - a) * t) for a, b in zip(top_rgb, bottom_rgb)))
    return grad.resize((SIZE, SIZE))


def side_shading():
    """Darken toward the left/right edges so the body reads as rounded."""
    shade = Image.new("L", (SIZE, 1), 255)
    width = RIGHT - LEFT
    for x in range(SIZE):
        u = (x - LEFT) / width
        edge = min(u, 1 - u)
        k = 1.0 if edge > 0.06 else 0.9 + 0.1 * max(edge, 0) / 0.06
        shade.putpixel((x, 0), round(255 * k))
    return shade.resize((SIZE, SIZE))


def main():
    body = mask(lambda d: d.rounded_rectangle(scaled((LEFT, TOP, RIGHT, BOTTOM)), RADIUS * SS, fill=255))
    band = ImageChops.multiply(
        body, mask(lambda d: d.rectangle(scaled((0, BAND_TOP, SIZE, SIZE)), fill=255))
    )

    canvas = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))

    # Soft drop shadow under the whole drive.
    shadow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    shadow.putalpha(body.point(lambda a: a * 0.35))
    shadow = shadow.transform(shadow.size, Image.AFFINE, (1, 0, 0, 0, 1, -10)).filter(ImageFilter.GaussianBlur(14))
    canvas.alpha_composite(shadow)

    shading = side_shading()

    face = vertical_gradient((252, 252, 252), (232, 232, 234), TOP, BAND_TOP).convert("RGBA")
    face = Image.merge("RGBA", (*[ImageChops.multiply(c, shading) for c in face.split()[:3]], body))
    canvas.alpha_composite(face)

    base = vertical_gradient((218, 218, 220), (176, 176, 180), BAND_TOP, BOTTOM).convert("RGBA")
    base = Image.merge("RGBA", (*[ImageChops.multiply(c, shading) for c in base.split()[:3]], band))
    canvas.alpha_composite(base)

    # Seam between face and band: a dark line with a highlight just below it.
    lines = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    ld = ImageDraw.Draw(lines)
    ld.rectangle((LEFT, BAND_TOP - 2, RIGHT, BAND_TOP), fill=(120, 120, 126, 150))
    ld.rectangle((LEFT, BAND_TOP + 1, RIGHT, BAND_TOP + 3), fill=(255, 255, 255, 170))
    lines.putalpha(ImageChops.multiply(lines.getchannel("A"), body))
    canvas.alpha_composite(lines)

    # Activity LED on the band.
    led_cx, led_cy, led_r = RIGHT - 70, (BAND_TOP + BOTTOM) // 2 + 4, 13
    led = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    led.putalpha(mask(lambda d: d.ellipse(scaled((led_cx - led_r - 3, led_cy - led_r - 3, led_cx + led_r + 3, led_cy + led_r + 3)), fill=255)).point(lambda a: a * 0.35))
    canvas.alpha_composite(led)
    led = Image.new("RGBA", (SIZE, SIZE), (255, 255, 255, 0))
    led.putalpha(mask(lambda d: d.ellipse(scaled((led_cx - led_r, led_cy - led_r, led_cx + led_r, led_cy + led_r)), fill=255)))
    canvas.alpha_composite(led)

    # Hairline outline so the white body holds up on a white Finder window.
    outline = Image.new("RGBA", (SIZE, SIZE), (110, 110, 116, 0))
    ring = ImageChops.subtract(body, body.filter(ImageFilter.MinFilter(5)))
    outline.putalpha(ring.point(lambda a: a * 0.45))
    canvas.alpha_composite(outline)

    # The app icon, centered on the face, with its own small shadow.
    app = Image.open(HERE / "icon.icns")
    w, h, scale = max(app.info["sizes"], key=lambda s: s[0] * s[2])  # largest representation
    app.size = (w, h)
    app.load(scale=scale)
    app = app.convert("RGBA").resize((APP_SIZE, APP_SIZE), Image.LANCZOS)
    x, y = (SIZE - APP_SIZE) // 2, APP_CENTER_Y - APP_SIZE // 2
    app_shadow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    tinted = Image.new("RGBA", app.size, (0, 0, 0, 0))
    tinted.putalpha(app.getchannel("A").point(lambda a: a * 0.3))
    app_shadow.paste(tinted, (x, y + 8))
    canvas.alpha_composite(app_shadow.filter(ImageFilter.GaussianBlur(10)))
    canvas.alpha_composite(app, (x, y))

    out = HERE / "dmg-volume.icns"
    canvas.save(out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
