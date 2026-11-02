"""The docs site: shared nav in step, and every link between pages lands somewhere."""

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

import docs_nav

DOCS = Path(__file__).resolve().parent / "docs"


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.ids = [], set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        for name in ("href", "src"):
            if a.get(name):
                self.links.append(a[name])


def parse(name: str) -> Page:
    p = Page()
    p.feed((DOCS / name).read_text(encoding="utf-8"))
    return p


class DocsTest(unittest.TestCase):
    def test_nav_in_step(self):
        self.assertEqual(docs_nav.main(["--check"]), 0, "run python docs_nav.py")

    def test_every_page_listed(self):
        listed = {h for _, h, _ in docs_nav.PAGES}
        self.assertEqual({p.name for p in DOCS.glob("*.html")}, listed)

    def test_local_links_resolve(self):
        pages = {p.name: parse(p.name) for p in DOCS.glob("*.html")}
        for name, page in pages.items():
            for link in page.links:
                if re.match(r"[a-z]+:", link):
                    continue
                target, _, anchor = link.partition("#")
                target = target or name
                with self.subTest(page=name, link=link):
                    self.assertTrue((DOCS / target).exists(), "missing file")
                    if anchor:
                        self.assertIn(anchor, pages[target].ids, "missing anchor")

    def test_no_placeholder_links(self):
        for p in DOCS.glob("*.html"):
            with self.subTest(page=p.name):
                self.assertNotIn('href="#"', p.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
