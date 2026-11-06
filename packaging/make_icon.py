"""Draw PhishGuard's icon (a shield with a tick) at the sizes Windows uses. Run once: writes phishguard.ico."""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).with_name("phishguard.ico")


def draw(size: int) -> Image.Image:
    s = size * 4                                   # draw large, then shrink for smooth edges
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=s // 5, fill=(23, 23, 23, 255))
    m = s * 0.2
    shield = [(s / 2, m), (s - m, m + s * 0.1), (s - m, s * 0.5), (s / 2, s - m * 0.9), (m, s * 0.5), (m, m + s * 0.1)]
    d.polygon(shield, outline=(255, 255, 255, 255), width=max(2, s // 16))
    w = max(2, s // 14)
    d.line([(s * 0.38, s * 0.5), (s * 0.47, s * 0.59), (s * 0.63, s * 0.41)], fill=(255, 255, 255, 255), width=w,
           joint="curve")
    return img.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    sizes = [16, 24, 32, 48, 64, 128, 256]
    big = draw(256)
    big.save(OUT, sizes=[(n, n) for n in sizes])
    big.save(OUT.with_suffix(".png"))
    print(OUT)
