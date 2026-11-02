"""Keeps the docs site's shared parts in step: the header, the sidebar and the
back/next links at the foot of each page.

The pages in docs/ are plain HTML, served as they are by GitHub Pages, with no
build step. Each page marks where the shared parts go with <!-- nav:top -->,
<!-- nav:side --> and <!-- nav:next --> (each closed by <!-- /nav:... -->).
This script rewrites what is between the markers from PAGES below.

    python docs_nav.py           rewrite the pages
    python docs_nav.py --check   exit 1 if any page is out of step
"""

import re
import sys
from html import escape
from pathlib import Path

DOCS = Path(__file__).resolve().parent / "docs"

# (section, file, title in the sidebar). Order is reading order, and sets back/next.
PAGES = [
    ("Start here", "index.html", "What AIngram is"),
    ("Start here", "how-it-works.html", "How it works"),
    ("Using AIngram", "wallet.html", "1 · Your wallet"),
    ("Using AIngram", "sign-in.html", "2 · Sign in"),
    ("Using AIngram", "policy.html", "3 · Your first policy"),
    ("Using AIngram", "connect.html", "4 · Connect Claude"),
    ("Using AIngram", "teach.html", "5 · Teach your AI"),
    ("Using AIngram", "import.html", "6 · Bring in old memories"),
    ("Using AIngram", "everyday.html", "Everyday use"),
    ("Running a server", "server.html", "What you need"),
    ("Running a server", "install.html", "Install"),
    ("Running a server", "https.html", "Your web address and HTTPS"),
    ("Running a server", "backups.html", "Nightly backups"),
    ("Help", "safety.html", "Staying safe"),
    ("Help", "troubleshooting.html", "Troubleshooting"),
]

# The header's links: (label, first page, the sections it covers).
TOP = [
    ("Start here", "index.html", {"Start here"}),
    ("Use it", "wallet.html", {"Using AIngram"}),
    ("Run a server", "server.html", {"Running a server"}),
    ("Help", "safety.html", {"Help"}),
]
TECH = {"Running a server"}
REPO = "https://github.com/TheFeloniousMonk/AIngram"


def plain(title: str) -> str:
    """The sidebar's '1 · Your wallet' reads as 'Your wallet' elsewhere."""
    return title.split(" · ", 1)[-1]


def top(section: str) -> str:
    links = "\n".join(
        f'    <a href="{href}"{" class=\"on\"" if section in covers else ""}>{escape(label)}</a>'
        for label, href, covers in TOP)
    return ('<header class="top">\n'
            '  <a class="brand" href="index.html"><span class="ai">AI</span>ngram<span class="sub">docs</span></a>\n'
            '  <nav class="topnav" aria-label="Sections">\n'
            f'{links}\n'
            f'    <a href="{REPO}">GitHub</a>\n'
            '  </nav>\n'
            '</header>')


def side(current: str) -> str:
    out, last = [], None
    for section, href, title in PAGES:
        if section != last:
            cls = ' class="tech"' if section in TECH else ""
            out.append(f"    <h4{cls}>{escape(section)}</h4>")
            last = section
        on = ' class="on" aria-current="page"' if href == current else ""
        out.append(f'    <a href="{href}"{on}>{escape(title)}</a>')
    here = next(t for _, h, t in PAGES if h == current)
    return ('<div class="side-wrap">\n'
            '  <button class="ghost side-toggle" aria-expanded="false">'
            f'<span>{escape(plain(here))}</span><span>Open ▾</span></button>\n'
            '  <nav class="side" aria-label="All pages">\n'
            + "\n".join(out) + "\n"
            '  </nav>\n'
            '</div>')


def nxt(current: str) -> str:
    i = [h for _, h, _ in PAGES].index(current)
    parts = []
    if i > 0:
        _, h, t = PAGES[i - 1]
        parts.append(f'  <a href="{h}"><small>Back</small>← {escape(plain(t))}</a>')
    if i < len(PAGES) - 1:
        _, h, t = PAGES[i + 1]
        parts.append(f'  <a class="fwd" href="{h}"><small>Next</small>{escape(plain(t))} →</a>')
    return '<div class="next">\n' + "\n".join(parts) + "\n</div>"


def render(text: str, href: str, section: str) -> str:
    parts = {"top": top(section), "side": side(href), "next": nxt(href)}
    for name, body in parts.items():
        pattern = re.compile(rf"(<!-- nav:{name} -->\n).*?(<!-- /nav:{name} -->)", re.S)
        if not pattern.search(text):
            raise SystemExit(f"{href}: missing <!-- nav:{name} --> markers")
        text = pattern.sub(lambda m: m.group(1) + body + "\n" + m.group(2), text)
    return text


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for section, href, _ in PAGES:
        path = DOCS / href
        text = path.read_text(encoding="utf-8")
        new = render(text, href, section)
        if new != text:
            stale.append(href)
            if not check:
                path.write_text(new, encoding="utf-8", newline="\n")
    listed = {h for _, h, _ in PAGES}
    unlisted = sorted(p.name for p in DOCS.glob("*.html") if p.name not in listed)
    if unlisted:
        print("not in PAGES:", ", ".join(unlisted))
    if check:
        if stale:
            print("out of step (run python docs_nav.py):", ", ".join(stale))
        return 1 if stale or unlisted else 0
    print(f"updated {len(stale)} page(s)" if stale else "all pages already in step")
    return 1 if unlisted else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
