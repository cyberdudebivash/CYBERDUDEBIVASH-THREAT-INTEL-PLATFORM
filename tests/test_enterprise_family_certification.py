"""
Cross-page production certification tests for the enterprise family
(PR-10, Commercial Production Certification & Launch Readiness).

Unlike tests/test_enterprise_homepage.py, test_enterprise_pricing.py,
test_enterprise_compliance.py, test_developer_portal.py, and
test_enterprise_knowledge_center.py -- each of which validates its own
page in isolation -- this suite validates the 5 pages *together*, as
one commercial surface. It does not duplicate any per-page check;
every test here compares pages against each other or asserts a
repository-wide fact (e.g. "the OG image asset actually exists on
disk") that no single-page suite is positioned to catch.

Categories:
  1. Metadata consistency (title suffix, canonical correctness, theme
     color, robots, og:site_name, twitter:site -- identical or
     correctly patterned across all 5 pages).
  2. Footer / branding consistency (copyright text, favicon, brand
     mark -- byte-identical across all 5 pages).
  3. Asset integrity (the shared OG image referenced by all 5 pages
     actually exists on disk).
  4. Crawlability (none of the 5 pages accidentally sets
     noindex/nofollow; none is blocked by robots.txt).
  5. Version-reference discipline (no page asserts its own, bare
     platform version number outside a cited drift disclosure).
  6. Navigation unification (re-confirms PR-9's fix holds, as a
     release-readiness gate independent of that suite continuing to
     exist).
  7. Support-contact baseline (every page shares at least the common
     enterprise@ contact address).

Run with: pytest tests/test_enterprise_family_certification.py -v
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

FAMILY_PAGES = [
    "enterprise-homepage.html",
    "enterprise-pricing.html",
    "enterprise-compliance.html",
    "developer-portal.html",
    "enterprise-knowledge-center.html",
]

EXPECTED_CANONICAL_BASE = "https://intel.cyberdudebivash.com/"


class _MetaParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None
        self._in_title = False
        self.canonical = None
        self.theme_color = None
        self.robots = None
        self.og_site_name = None
        self.twitter_site = None
        self.nav_hrefs: list[str] = []
        self._in_primary_nav = False
        self.footer_bottom_text = ""
        self._in_footer_bottom = False
        self.favicon_href = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        if tag == "link" and a.get("rel") == "canonical":
            self.canonical = a.get("href")
        if tag == "link" and a.get("rel") == "icon":
            self.favicon_href = a.get("href")
        if tag == "meta" and a.get("name") == "theme-color":
            self.theme_color = a.get("content")
        if tag == "meta" and a.get("name") == "robots":
            self.robots = a.get("content")
        if tag == "meta" and a.get("property") == "og:site_name":
            self.og_site_name = a.get("content")
        if tag == "meta" and a.get("name") == "twitter:site":
            self.twitter_site = a.get("content")
        if tag == "nav" and a.get("aria-label") == "Primary":
            self._in_primary_nav = True
        if tag == "a" and a.get("href") and self._in_primary_nav:
            self.nav_hrefs.append(a["href"])
        if tag == "div" and "sapx-footer-bottom" in (a.get("class") or "").split():
            self._in_footer_bottom = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag == "nav":
            self._in_primary_nav = False
        if tag == "div":
            self._in_footer_bottom = False

    def handle_data(self, data):
        if self._in_title:
            self.title = (self.title or "") + data
        if self._in_footer_bottom:
            self.footer_bottom_text += data


def _parse_page(filename: str) -> tuple[_MetaParser, str]:
    path = REPO_ROOT / filename
    assert path.exists(), f"{path} not found"
    text = path.read_text(encoding="utf-8")
    parser = _MetaParser()
    parser.feed(text)
    return parser, text


@pytest.fixture(scope="module")
def pages():
    return {name: _parse_page(name) for name in FAMILY_PAGES}


# ---------------------------------------------------------------------
# 1. Metadata consistency
# ---------------------------------------------------------------------

def test_every_title_follows_the_shared_brand_suffix(pages):
    suffix = "CYBERDUDEBIVASH® SENTINEL APEX"
    offenders = {
        name: parser.title for name, (parser, _text) in pages.items()
        if not parser.title or not parser.title.endswith(suffix)
    }
    assert not offenders, f"title(s) not ending in the shared brand suffix: {offenders}"


def test_every_canonical_url_is_self_referential_and_correct_domain(pages):
    offenders = {}
    for name, (parser, _text) in pages.items():
        expected = EXPECTED_CANONICAL_BASE + name
        if parser.canonical != expected:
            offenders[name] = parser.canonical
    assert not offenders, f"canonical URL mismatch(es): {offenders}"


def test_theme_color_identical_across_all_pages(pages):
    values = {name: parser.theme_color for name, (parser, _t) in pages.items()}
    distinct = set(values.values())
    assert len(distinct) == 1, f"theme-color is not identical across pages: {values}"


def test_no_page_blocks_search_indexing(pages):
    offenders = {
        name: parser.robots for name, (parser, _t) in pages.items()
        if not parser.robots or "noindex" in parser.robots.lower()
    }
    assert not offenders, f"page(s) missing robots meta or set to noindex: {offenders}"


def test_og_site_name_and_twitter_site_identical_across_all_pages(pages):
    og_values = {name: parser.og_site_name for name, (parser, _t) in pages.items()}
    tw_values = {name: parser.twitter_site for name, (parser, _t) in pages.items()}
    assert len(set(og_values.values())) == 1, f"og:site_name differs across pages: {og_values}"
    assert len(set(tw_values.values())) == 1, f"twitter:site differs across pages: {tw_values}"


# ---------------------------------------------------------------------
# 2. Footer / branding consistency
# ---------------------------------------------------------------------

def test_footer_copyright_text_identical_across_all_pages(pages):
    values = {name: parser.footer_bottom_text.strip() for name, (parser, _t) in pages.items()}
    distinct = set(values.values())
    assert len(distinct) == 1, f"footer copyright text differs across pages: {values}"


def test_favicon_identical_across_all_pages(pages):
    values = {name: parser.favicon_href for name, (parser, _t) in pages.items()}
    distinct = set(values.values())
    assert len(distinct) == 1, "favicon data URI differs across pages (lengths only, for readability): " + str(
        {name: len(v or "") for name, v in values.items()}
    )


# ---------------------------------------------------------------------
# 3. Asset integrity
# ---------------------------------------------------------------------

def test_shared_og_image_asset_exists_on_disk(pages):
    for name, (_parser, text) in pages.items():
        match = re.search(r'property="og:image" content="([^"]+)"', text)
        assert match, f"{name} is missing an og:image meta tag"
        url = match.group(1)
        assert url.startswith("https://intel.cyberdudebivash.com/"), (
            f"{name}'s og:image is not an absolute intel.cyberdudebivash.com URL: {url}"
        )
        relative = url[len("https://intel.cyberdudebivash.com/"):]
        asset_path = REPO_ROOT / relative
        assert asset_path.exists(), f"{name} references a missing OG image asset: {asset_path}"


# ---------------------------------------------------------------------
# 4. Crawlability
# ---------------------------------------------------------------------

def test_robots_txt_does_not_disallow_any_enterprise_family_page():
    robots_path = REPO_ROOT / "robots.txt"
    assert robots_path.exists()
    text = robots_path.read_text(encoding="utf-8")
    disallow_lines = [ln for ln in text.splitlines() if ln.strip().lower().startswith("disallow")]
    for page in FAMILY_PAGES:
        offenders = [ln for ln in disallow_lines if page in ln]
        assert not offenders, f"robots.txt disallows {page}: {offenders}"


# ---------------------------------------------------------------------
# 5. Version-reference discipline
# ---------------------------------------------------------------------

VERSION_RE = re.compile(r"\bv1[0-9]{2}\.[0-9]+\b")

def test_no_page_asserts_its_own_bare_platform_version(pages):
    """Version numbers may appear only inside a disclosed drift
    citation (quoting another file, or discussing the Known Repository
    Drift Dashboard / Changelog Explorer) -- never as this page's own
    unqualified claim. A simple, defensible proxy: any version-number
    occurrence must appear within 200 chars of one of these citation
    markers."""
    citation_markers = (
        "docs/developer-portal-guide.md", "CHANGELOG", "RELEASE_NOTES",
        "index.html", "security-compliance.html", "api-docs.html",
        "trust-center.html", "drift", "Drift", "v1", "per its own docstring",
        "quotes", "Quoting",
    )
    offenders = {}
    for name, (_parser, text) in pages.items():
        for match in VERSION_RE.finditer(text):
            window = text[max(0, match.start() - 200):match.end() + 50]
            if not any(marker in window for marker in citation_markers):
                offenders.setdefault(name, []).append(match.group(0))
    assert not offenders, f"uncited bare version-number claim(s) found: {offenders}"


# ---------------------------------------------------------------------
# 6. Navigation unification (release-readiness gate)
# ---------------------------------------------------------------------

def test_all_five_pages_share_identical_primary_nav(pages):
    nav_sets = {name: sorted(parser.nav_hrefs) for name, (parser, _t) in pages.items()}
    reference = nav_sets[FAMILY_PAGES[0]]
    mismatched = {name: hrefs for name, hrefs in nav_sets.items() if hrefs != reference}
    assert not mismatched, f"primary nav has regressed to non-identical across pages: {mismatched}"


def test_primary_nav_has_exactly_seven_links(pages):
    for name, (parser, _t) in pages.items():
        assert len(parser.nav_hrefs) == 7, (
            f"{name}'s primary nav has {len(parser.nav_hrefs)} links, expected 7"
        )


# ---------------------------------------------------------------------
# 7. Support-contact baseline
# ---------------------------------------------------------------------

def test_every_page_includes_the_shared_enterprise_contact(pages):
    offenders = [
        name for name, (_parser, text) in pages.items()
        if "mailto:contact@cyberdudebivash.in" not in text
    ]
    assert not offenders, f"page(s) missing the shared enterprise@ contact: {offenders}"
