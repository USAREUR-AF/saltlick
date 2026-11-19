"""Draw the repository's figures from the tree.

    python3 -I docs/figures/make-figures.py           # write docs/figures/*.svg
    python3 -I docs/figures/make-figures.py --check   # exit 1 if a committed figure is out of date

Each figure is written twice, `<name>-light.svg` and `<name>-dark.svg`, for a
`<picture>` element. The pointer record's members and the reader's four steps
are read from README.md, the refused offer blocks and the pointer format from
internal/pkgv1/package.go. The output is deterministic. Standard library only.
"""

import os
import re
import sys
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
THEMES = {
    "light": {
        "paper": "#ffffff", "panel": "#f6f8fa", "ink": "#1f2328", "quiet": "#59636e", "rule": "#d1d9e0",
        "line": "#818b98", "accent": "#0969da", "accent_soft": "#ddf4ff", "on_accent": "#ffffff",
        "good": "#1a7f37", "good_bg": "#dafbe1", "crit": "#cf222e", "crit_bg": "#ffebe9", "mute": "#6e7781",
        "s0": "#0969da", "s1": "#bc4c00", "s2": "#1a7f37", "s3": "#8250df",
    },
    "dark": {
        "paper": "#0d1117", "panel": "#161b22", "ink": "#e6edf3", "quiet": "#9198a1", "rule": "#3d444d",
        "line": "#7d8590", "accent": "#4493f8", "accent_soft": "#132c4c", "on_accent": "#0d1117",
        "good": "#3fb950", "good_bg": "#12261e", "crit": "#f85149", "crit_bg": "#2f1517", "mute": "#8b949e",
        "s0": "#4493f8", "s1": "#f0883e", "s2": "#3fb950", "s3": "#bc8cff",
    },
}
SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"


def n(v):
    return ("%.1f" % v).rstrip("0").rstrip(".")


def tw(s, size, mono=False, bold=False):
    """Text width estimate; the browser check in the README confirms it."""
    if mono:
        return len(s) * size * 0.61
    w = 0.0
    for c in s:
        if c in "il.,:;|!'`·1 ":
            w += 0.30
        elif c in "ft()[]/-":
            w += 0.36
        elif c in "mwMW@%":
            w += 0.86
        elif c.isupper() or c in "0123456789≤≥²→":
            w += 0.64
        else:
            w += 0.55
    return w * size * (1.06 if bold else 1.0)


def wrap(s, width, size, mono=False, bold=False):
    out, line = [], ""
    for word in s.split(" "):
        t = word if not line else line + " " + word
        if tw(t, size, mono, bold) <= width or not line:
            line = t
        else:
            out.append(line)
            line = word
    if line:
        out.append(line)
    return out


class SVG:
    def __init__(self, w, h, title, desc):
        self.w, self.h, self.title, self.desc = w, h, title, desc
        self.items = []

    def add(self, s):
        self.items.append(s)

    def rect(self, x, y, w, h, fill="panel", stroke="rule", rx=8, sw=1, dash=None):
        d = ' stroke-dasharray="%s"' % dash if dash else ""
        self.add('<rect x="%s" y="%s" width="%s" height="%s" rx="%s" fill="{%s}" stroke="{%s}" stroke-width="%s"%s/>'
                 % (n(x), n(y), n(w), n(h), n(rx), fill, stroke, n(sw), d))

    def text(self, x, y, s, size=14, fill="ink", anchor="start", bold=False, mono=False, italic=False):
        self.add('<text x="%s" y="%s" font-size="%s" fill="{%s}" text-anchor="%s"%s%s%s>%s</text>'
                 % (n(x), n(y), n(size), fill, anchor, ' font-weight="600"' if bold else "",
                    ' font-family="%s"' % MONO if mono else "", ' font-style="italic"' if italic else "", escape(s)))

    def lines(self, x, y, rows, size=14, lead=1.4, **kw):
        for i, r in enumerate(rows):
            self.text(x, y + i * size * lead, r, size, **kw)
        return y + len(rows) * size * lead

    def line(self, x1, y1, x2, y2, stroke="line", sw=1.5, dash=None, arrow=False):
        d = ' stroke-dasharray="%s"' % dash if dash else ""
        m = ' marker-end="url(#arrow)"' if arrow else ""
        self.add('<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="{%s}" stroke-width="%s"%s%s/>'
                 % (n(x1), n(y1), n(x2), n(y2), stroke, n(sw), d, m))

    def path(self, d, stroke="line", fill="none", sw=1.5, dash=None, arrow=False):
        dd = ' stroke-dasharray="%s"' % dash if dash else ""
        m = ' marker-end="url(#arrow)"' if arrow else ""
        f = "none" if fill == "none" else "{%s}" % fill
        self.add('<path d="%s" fill="%s" stroke="{%s}" stroke-width="%s"%s%s/>' % (d, f, stroke, n(sw), dd, m))

    def circle(self, x, y, r, fill="ink", stroke=None, sw=1.5):
        s = ' stroke="{%s}" stroke-width="%s"' % (stroke, n(sw)) if stroke else ""
        f = "none" if fill == "none" else "{%s}" % fill
        self.add('<circle cx="%s" cy="%s" r="%s" fill="%s"%s/>' % (n(x), n(y), n(r), f, s))

    def ellipse(self, x, y, rx, ry, fill="none", stroke="line", sw=1.5, dash=None, opacity=None):
        d = ' stroke-dasharray="%s"' % dash if dash else ""
        f = "none" if fill == "none" else "{%s}" % fill
        o = ' fill-opacity="%s"' % opacity if opacity is not None else ""
        self.add('<ellipse cx="%s" cy="%s" rx="%s" ry="%s" fill="%s"%s stroke="{%s}" stroke-width="%s"%s/>'
                 % (n(x), n(y), n(rx), n(ry), f, o, stroke, n(sw), d))

    def render(self, theme):
        t = THEMES[theme]
        body = "\n".join(self.items)
        for k, v in t.items():
            body = body.replace("{%s}" % k, v)
        return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" '
                'aria-labelledby="t d" font-family="%s">\n<title id="t">%s</title>\n<desc id="d">%s</desc>\n'
                '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                'orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="%s"/></marker></defs>\n'
                '<rect width="100%%" height="100%%" rx="12" fill="%s"/>\n%s\n</svg>\n'
                % (self.w, self.h, self.w, self.h, SANS.replace("'", "&apos;"), escape(self.title), escape(self.desc),
                   t["line"], t["paper"], body))


def header(f, title, sub):
    """Title and subtitle at the top left."""
    f.text(24, 38, title, 20, bold=True)
    f.text(24, 62, sub, 14, fill="quiet")


# ---------------------------------------------------------------- tree facts

def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def facts():
    """The pointer record's members, the reader's steps, the refused blocks, the pointer format."""
    readme = read("README.md")
    sec = readme.split("## The pointer record", 1)[1].split("\n## ", 1)[0]
    members = re.findall(r"^\| `([a-z0-9_]+)` \|", sec, re.M)
    steps_txt = sec.split("four steps", 1)[1]
    steps = [re.sub(r"\.$", "", s.strip()) for s in re.findall(r"^\d\. (.+)$", steps_txt, re.M)]
    go = read("internal/pkgv1/package.go")
    refused = re.findall(r'^\t"([a-z_]+)": +"', go.split("var offerMembers", 1)[1].split("}", 1)[0], re.M)
    spec = re.search(r'PointerSpec = "([^"]+)"', go).group(1)
    if len(members) < 5 or len(steps) != 4 or len(refused) != 3:
        sys.exit("make-figures: README.md or package.go changed shape; update facts()")
    return members, steps, refused, spec


def fig_directory():
    members, steps, refused, spec = facts()
    W = 880
    title = "Being listed grants access to nothing"
    desc = ("saltlick serves a signed %s record: where a party's signed package is and its SHA-256 digest. "
            "The reading party fetches the package and checks its signatures and digest against its own trust store "
            "and a key read aloud between the two parties, so the directory is an input to none of the checks. "
            "Entries carrying %s are refused. With the directory switched off, both parties compose with the same "
            "versioned tool and compare one digest." % (spec, ", ".join(refused)))
    f = SVG(W, 540, title, desc)
    header(f, title, "The directory serves a signed pointer. Every check happens at the reading party.")

    top, bh = 92, 318
    L = (24, 196)
    M = (252, 300)
    R = (584, 272)

    # left: the publishing party
    x, w = L
    f.rect(x, top, w, bh, fill="panel", stroke="rule")
    f.text(x + 16, top + 30, "xaa", 17, bold=True, mono=True)
    f.text(x + 16, top + 52, "the publishing party", 14, fill="quiet")
    f.rect(x + 16, top + 74, w - 32, 50, fill="paper", stroke="line", rx=6)
    f.text(x + w / 2, top + 96, "signed package", 14, anchor="middle", bold=True)
    f.text(x + w / 2, top + 115, "on its own host", 13, anchor="middle", fill="quiet")
    y = f.lines(x + 16, top + 156, wrap("Signs a pointer to the package and PUTs it.", w - 32, 14), 14)
    f.lines(x + 16, y + 10, wrap("The first write binds its key: trust on first use, which proves nothing about identity.",
                                 w - 32, 14), 14, fill="quiet")

    # middle: the directory
    x, w = M
    f.rect(x, top, w, bh, fill="panel", stroke="rule")
    f.text(x + 16, top + 30, "saltlick", 17, bold=True, mono=True)
    f.text(x + 16, top + 52, "stores and serves bytes, decides nothing", 14, fill="quiet")
    cy = top + 68
    ch = 22 + 20 * len(members)
    f.rect(x + 16, cy, w - 32, ch, fill="paper", stroke="line", rx=6)
    f.text(x + 28, cy + 20, spec, 13, fill="quiet", mono=True)
    for i, m in enumerate(members[1:]):
        f.text(x + 28, cy + 42 + 20 * i, m, 13, mono=True)
    y = cy + ch + 28
    f.text(x + 16, y, "Refused with HTTP 422:", 14, bold=True)
    f.text(x + 16, y + 22, "  ".join(refused), 13, mono=True, fill="crit")
    f.text(x + 16, y + 44, "No accounts, no private keys.", 14, fill="quiet")

    # right: the reading party
    x, w = R
    f.rect(x, top, w, bh, fill="panel", stroke="rule")
    f.text(x + 16, top + 30, "xab", 17, bold=True, mono=True)
    f.text(x + 16, top + 52, "the reading party", 14, fill="quiet")
    y = top + 82
    for i, s in enumerate(steps):
        check = i >= 2
        s = s.replace("`", "")
        s = re.sub(r"^GET /v1/parties/xaa — the pointer$", "GET the pointer from saltlick", s)
        f.circle(x + 27, y - 5, 10, fill="good" if check else "mute")
        f.text(x + 27, y, str(i + 1), 13, anchor="middle", bold=True, fill="on_accent")
        y = f.lines(x + 46, y, wrap(s, w - 62, 14), 14, fill="ink") + 10
    f.text(x + 16, top + bh - 18, "Steps 3 and 4 are the checks.", 14, fill="good", bold=True)

    # arrows between columns
    ay = top + 170
    f.line(L[0] + L[1] + 2, ay, M[0] - 4, ay, sw=1.5, arrow=True)
    f.text((L[0] + L[1] + M[0]) / 2, ay - 8, "PUT", 13, anchor="middle", mono=True, fill="quiet")
    f.line(M[0] + M[1] + 2, top + 82 - 5, R[0] - 4, top + 82 - 5, sw=1.5, arrow=True)
    f.text((M[0] + M[1] + R[0]) / 2, top + 82 - 13, "GET", 13, anchor="middle", mono=True, fill="quiet")

    # out of band: the key, between the two parties only, under the directory
    by = top + bh + 34
    lx, rx = L[0] + L[1] / 2, R[0] + R[1] / 2
    px0, px1 = M[0] - 34, M[0] + M[1] + 34
    f.path("M%s,%s V%s H%s" % (n(lx), n(top + bh + 2), n(by), n(px0)), stroke="good", sw=2, dash="6 5")
    f.path("M%s,%s H%s V%s" % (n(px1), n(by), n(rx), n(top + bh + 2)), stroke="good", sw=2, dash="6 5")
    f.rect(px0, by - 18, px1 - px0, 36, fill="good_bg", stroke="good", rx=18)
    f.text(M[0] + M[1] / 2, by + 5, "The verifying key, read aloud between the parties", 14, anchor="middle", bold=True)
    f.text((px0 + px1) / 2, by + 44, "Out of band, never through the directory: a call to a voice you recognize, a meeting, a courier.",
           14, anchor="middle", fill="quiet")

    # the directory switched off
    oy = by + 78
    f.line(24, oy - 18, W - 24, oy - 18, stroke="rule", sw=1)
    f.lines(24, oy + 4, wrap("Switched off, federation still works: both parties compose with the same versioned tool "
                             "and compare one digest.", W - 48, 14), 14)
    return f


FIGURES = [("peering-directory", fig_directory)]


def main(argv):
    check = "--check" in argv
    stale = []
    for name, fn in FIGURES:
        fig = fn()
        for theme in THEMES:
            p = os.path.join(HERE, "%s-%s.svg" % (name, theme))
            out = fig.render(theme)
            if check:
                if not os.path.isfile(p) or open(p, encoding="utf-8").read() != out:
                    stale.append(os.path.relpath(p, ROOT))
            else:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(out)
                print(os.path.relpath(p, ROOT))
    if stale:
        print("out of date: " + ", ".join(stale) + "; run python3 -I docs/figures/make-figures.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
