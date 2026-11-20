"""Single source of truth for the AUREL emblem.  python -m tools.build_assets
Writes aurel/static/emblem.svg, extension/logo.svg, extension icons (PNG) and injects the shared
<defs> into aurel/templates/index.html so the web app, extension, loading screen and reports match."""
import os, re
from PIL import Image, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = "M100 16 L172 38 V112 C172 158 142 190 100 206 C58 190 28 158 28 112 V38 Z"
S2 = "M100 28 L160 46 V112 C160 150 135 177 100 192 C65 177 40 150 40 112 V46 Z"
S3 = "M100 36 L152 52 V112 C152 144 130 168 100 181 C70 168 48 144 48 112 V52 Z"
A = "M30 202 L100 4 L170 202 L142 202 L125.7 156 L74.3 156 L58 202 Z M100 83 L82 134 L118 134 Z"
BAR = "82,134 118,134 125.7,156 74.3,156"
STROKE = "M30 202 L100 4 L170 202 M74 145 H126"
SHARDS = ["0,120 0,0 60,0 100,100", "100,100 60,0 200,0 200,40", "100,100 200,40 200,170", "100,100 200,170 200,230 30,230", "100,100 30,230 0,230 0,120"]

DEFS = f'''<linearGradient id="gBlue" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4573f5"/><stop offset=".45" stop-color="#1d3fb8"/><stop offset="1" stop-color="#0a1a56"/></linearGradient>
<linearGradient id="gRim" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset=".35" stop-color="#a7b0c0"/><stop offset=".55" stop-color="#eef1f6"/><stop offset="1" stop-color="#747e90"/></linearGradient>
<linearGradient id="gA" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset=".4" stop-color="#c6cedb"/><stop offset=".62" stop-color="#8b95a7"/><stop offset="1" stop-color="#e3e8ef"/></linearGradient>
<linearGradient id="gGold" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f3dc9a"/><stop offset=".5" stop-color="#c9a24a"/><stop offset="1" stop-color="#8a6a22"/></linearGradient>
<linearGradient id="gSheen" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".34"/><stop offset=".45" stop-color="#fff" stop-opacity="0"/></linearGradient>
<linearGradient id="gGlow" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9fc0ff"/><stop offset=".5" stop-color="#fff"/><stop offset="1" stop-color="#7aa2ff"/></linearGradient>
<filter id="fShadow" x="-20%" y="-10%" width="140%" height="130%"><feDropShadow dx="0" dy="3" stdDeviation="3" flood-color="#000" flood-opacity=".55"/></filter>
<filter id="fGlow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<g id="shieldArt"><path d="{S}" fill="url(#gBlue)" stroke="url(#gRim)" stroke-width="5" stroke-linejoin="round"/><path d="{S2}" fill="none" stroke="#fff" stroke-opacity=".28" stroke-width="1.4"/><path d="{S3}" fill="none" stroke="url(#gGold)" stroke-width="1.2" opacity=".85"/><path d="{S}" fill="url(#gSheen)"/></g>
<g id="aArt" filter="url(#fShadow)"><path fill-rule="evenodd" d="{A}" fill="url(#gA)" stroke="#080a0e" stroke-width="1.2" stroke-linejoin="round"/><polygon points="{BAR}" fill="url(#gGold)"/><path d="M31.5 199 L100 8" stroke="#fff" stroke-opacity=".7" stroke-width="1.3" fill="none"/></g>
{"".join(f'<clipPath id="cp{i+1}"><polygon points="{p}"/></clipPath>' for i, p in enumerate(SHARDS))}
<mask id="mA" maskUnits="userSpaceOnUse" x="0" y="0" width="200" height="212"><path class="reveal" d="{STROKE}" pathLength="1" stroke="#fff" stroke-width="50" fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="1" stroke-dashoffset="1"/></mask>
<symbol id="emblem" viewBox="0 0 200 212"><use href="#shieldArt"/><use href="#aArt"/></symbol>'''


def standalone():
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 212" width="200" height="212"><defs>{DEFS.replace("<symbol", "<g").replace("</symbol>", "</g>").split("<g id=" + chr(34) + "emblem")[0]}</defs><use href="#shieldArt"/><use href="#aArt"/></svg>'


def icons():
    k = 4
    W, H = 200 * k, 212 * k
    def bez(p0, p1, p2, p3, n=40):
        return [tuple((1 - t) ** 3 * a + 3 * (1 - t) ** 2 * t * b + 3 * (1 - t) * t ** 2 * c + t ** 3 * d for a, b, c, d in zip(p0, p1, p2, p3)) for t in [i / n for i in range(n + 1)]]
    shield = [(100, 16), (172, 38), (172, 112)] + bez((172, 112), (172, 158), (142, 190), (100, 206)) + bez((100, 206), (58, 190), (28, 158), (28, 112)) + [(28, 38)]
    def grad(top, bot):
        g = Image.new("RGB", (W, H)); d = ImageDraw.Draw(g)
        for y in range(H):
            t = y / H; d.line([(0, y), (W, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bot)))
        return g
    sc = lambda pts: [(x * k, y * k) for x, y in pts]
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    m = Image.new("L", (W, H), 0); ImageDraw.Draw(m).polygon(sc(shield), fill=255)
    img.paste(grad((69, 115, 245), (10, 26, 86)), mask=m)
    d = ImageDraw.Draw(img); d.line(sc(shield + [shield[0]]), fill=(205, 212, 224, 255), width=5 * k, joint="curve")
    a_out = [(30, 202), (100, 4), (170, 202), (142, 202), (125.7, 156), (74.3, 156), (58, 202)]
    am = Image.new("L", (W, H), 0); ad = ImageDraw.Draw(am); ad.polygon(sc(a_out), fill=255); ad.polygon(sc([(100, 83), (82, 134), (118, 134)]), fill=0)
    sh = Image.new("RGBA", (W, H), (0, 0, 0, 0)); sh.paste((0, 0, 0, 150), mask=am.filter(ImageFilter.GaussianBlur(3 * k)).transform((W, H), Image.AFFINE, (1, 0, 0, 0, 1, -3 * k)))
    img = Image.alpha_composite(img, sh)
    img.paste(grad((250, 251, 253), (140, 150, 168)), mask=am)
    d = ImageDraw.Draw(img); d.polygon(sc([(82, 134), (118, 134), (125.7, 156), (74.3, 156)]), fill=(201, 162, 74, 255))
    d.line(sc(a_out + [a_out[0]]), fill=(8, 10, 14, 255), width=int(1.2 * k), joint="curve")
    for size in (16, 32, 48, 128):
        h = size; w = round(size * 200 / 212)
        icon = Image.new("RGBA", (size, size), (0, 0, 0, 0)); icon.paste(img.resize((w, h), Image.LANCZOS), ((size - w) // 2, 0))
        icon.save(os.path.join(ROOT, "extension", f"icon{size}.png"))
    img.resize((512, round(512 * 212 / 200)), Image.LANCZOS).save(os.path.join(ROOT, "docs", "emblem.png"))


if __name__ == "__main__":
    svg = standalone()
    open(os.path.join(ROOT, "aurel", "static", "emblem.svg"), "w").write(svg)
    open(os.path.join(ROOT, "extension", "logo.svg"), "w").write(svg)
    p = os.path.join(ROOT, "aurel", "templates", "index.html")
    html = open(p).read()
    html = re.sub(r"<!--EMBLEM-DEFS-->.*<!--/EMBLEM-DEFS-->", lambda m: "<!--EMBLEM-DEFS-->" + DEFS + "<!--/EMBLEM-DEFS-->", html, flags=re.S)
    open(p, "w").write(html)
    icons()
    print("assets built")
