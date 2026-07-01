"""
CyberINTEL-AI — Icon Generator
==================================
Generates the 4 required extension icon sizes using Pillow.
Run once to create icons before building the extension.

Usage:
  pip install Pillow
  python generate_icons.py
"""

from PIL import Image, ImageDraw, ImageFont
import os

SIZES   = [16, 32, 48, 128]
OUT_DIR = "public/icons"

def draw_icon(size: int) -> Image.Image:
    """Draw a minimal hexagon shield icon for CyberINTEL-AI."""
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    bg_color     = (10, 20, 24, 255)
    accent_color = (0, 229, 160, 255)
    padding      = size * 0.08

    # Background circle
    draw.ellipse(
        [padding, padding, size - padding, size - padding],
        fill=bg_color
    )

    # Hexagon shield outline
    cx, cy = size / 2, size / 2
    r      = (size / 2) - padding - size * 0.05
    import math

    points = [
        (
            cx + r * math.cos(math.radians(90 + 60 * i)),
            cy + r * math.sin(math.radians(90 + 60 * i))
        )
        for i in range(6)
    ]
    draw.polygon(points, outline=accent_color, fill=(0, 229, 160, 30))

    # S letter in center (only for larger sizes)
    if size >= 32:
        line_width = max(1, size // 16)
        # Simple "S" shape approximation with lines
        mid = size / 2
        arm = size * 0.18
        draw.arc(
            [mid - arm, mid - arm * 1.4, mid + arm, mid],
            start=0, end=180, fill=accent_color, width=line_width
        )
        draw.arc(
            [mid - arm, mid, mid + arm, mid + arm * 1.4],
            start=180, end=360, fill=accent_color, width=line_width
        )

    return img


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for size in SIZES:
        icon = draw_icon(size)
        path = os.path.join(OUT_DIR, f"icon{size}.png")
        icon.save(path, "PNG")
        print(f"[✓] Generated {path}")
    print(f"\nDone! Icons saved to {OUT_DIR}/")


if __name__ == "__main__":
    main()
