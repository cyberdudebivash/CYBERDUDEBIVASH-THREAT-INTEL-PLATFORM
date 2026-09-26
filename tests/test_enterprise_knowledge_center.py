"""
Static-analysis regression tests for enterprise-knowledge-center.html
(PR-9, Platform Quality, Search & Release Readiness).

Same five categories as the PR-5/6/7/8 test suites, plus PR-9-specific
categories:

  1. Token usage verification.
  2. Duplicate component detection.
  3. Heading hierarchy validation.
  4. DOM validation.
  5. Broken-link detection.
  6. Search validation (PR-9-specific) -- the Search Hub's filter must
     actually be wired up: a labeled input, an aria-live result count,
     and every result card carrying the data this depends on.
  7. Navigation consistency across the whole enterprise-family
     (PR-9-specific) -- this PR unified a previously-diverged nav
     across 4 existing pages plus this new one. This guards that the
     unification doesn't silently regress in a future edit to any of
     the 5 files.
  8. Repository drift disclosure integrity (PR-9-specific) -- the
     Known Repository Drift Dashboard's substance (not just its
     heading) must stay present.

Run with: pytest tests/test_enterprise_knowledge_center.py -v
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGE_PATH = REPO_ROOT / "enterprise-knowledge-center.html"
COMPONENTS_CSS = REPO_ROOT / "css" / "components.css"

FAMILY_PAGES = [
    "enterprise-homepage.html",
    "enterprise-pricing.html",
    "enterprise-compliance.html",
    "developer-portal.html",
    "enterprise-knowledge-center.html",
]

NON_FILE_SCHEMES = ("http://", "https://", "mailto:", "tel:")


@pytest.fixture(scope="module")
def page_text():
    assert PAGE_PATH.exists(), f"{PAGE_PATH} not found"
    return PAGE_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def page_style(page_text):
    match = re.search(r"<style>(.*?)</style>", page_text, re.DOTALL)
    assert match, "expected exactly one <style> block in enterprise-knowledge-center.html"
    return match.group(1)


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.classes: set[str] = set()
        self.ids: list[str] = []
        self.hrefs: list[str] = []
        self.headings: list[int] = []
        self.stylesheet_hrefs: list[str] = []
        self.saw_skip_link = False
        self.saw_header = False
        self.saw_primary_nav = False
        self.saw_main = False
        self.saw_footer = False
        self._in_primary_nav = False
        self.primary_nav_hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("class"):
            self.classes.update(a["class"].split())
        if a.get("id"):
            self.ids.append(a["id"])
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
            if self._in_primary_nav:
                self.primary_nav_hrefs.append(a["href"])
        if tag == "link" and a.get("rel") == "stylesheet" and a.get("href"):
            self.stylesheet_hrefs.append(a["href"])
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(int(tag[1]))
        if tag == "a" and "sapx-skip-link" in (a.get("class") or "").split():
            self.saw_skip_link = True
        if tag == "header" and "sapx-site-header" in (a.get("class") or "").split():
            self.saw_header = True
        if tag == "nav" and a.get("aria-label") == "Primary":
            self.saw_primary_nav = True
            self._in_primary_nav = True
        if tag == "main" and a.get("id") == "main-content":
            self.saw_main = True
        if tag == "footer" and "sapx-site-footer" in (a.get("class") or "").split():
            self.saw_footer = True

    def handle_endtag(self, tag):
        if tag == "nav":
            self._in_primary_nav = False


def _parse(text: str) -> _PageParser:
    parser = _PageParser()
    parser.feed(text)
    return parser


@pytest.fixture(scope="module")
def parsed(page_text):
    return _parse(page_text)


def _split_top_level_blocks(text):
    depth = 0
    start = 0
    header_start = 0
    blocks = []
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                blocks.append(["header", text[header_start:i].strip()])
                start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                blocks[-1] = (blocks[-1][1], text[start:i])
                header_start = i + 1
    return blocks


def _all_rules(css_text):
    no_comments = re.sub(r"/\*.*?\*/", "", css_text, flags=re.DOTALL)
    rules = []
    for header, body in _split_top_level_blocks(no_comments):
        if header.startswith("@media"):
            for inner_header, inner_body in _split_top_level_blocks(body):
                if not inner_header.startswith("@"):
                    rules.append((inner_header.strip(), inner_body.strip()))
        elif not header.startswith("@"):
            rules.append((header.strip(), body.strip()))
    return rules


# ---------------------------------------------------------------------
# 1. Token usage verification
# ---------------------------------------------------------------------

HARDCODED_COLOR_RE = re.compile(
    r"(?<![\w-])(color|background|background-color|border-color|border|"
    r"box-shadow|outline|fill|stroke)\s*:\s*([^;]+);"
)
LITERAL_COLOR_TOKEN_RE = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)")
HARDCODED_SPACING_RE = re.compile(
    r"(?<![\w-])(padding|margin|gap|font-size|border-radius)\s*:\s*([^;]+);"
)


def _values_outside_var(declaration_value: str) -> str:
    value = declaration_value
    pattern = re.compile(r"(var|calc|clamp|color-mix)\([^()]*\)")
    while True:
        new_value = pattern.sub("", value)
        if new_value == value:
            break
        value = new_value
    return value


def test_no_hardcoded_colors_in_page_style(page_style):
    offenders = []
    for match in HARDCODED_COLOR_RE.finditer(page_style):
        prop, value = match.group(1), match.group(2)
        if LITERAL_COLOR_TOKEN_RE.search(_values_outside_var(value)):
            offenders.append(f"{prop}: {value.strip()}")
    assert not offenders, (
        f"enterprise-knowledge-center.html's <style> block has hardcoded "
        f"color literal(s) outside var(--sapx-*): {offenders}"
    )


def test_no_hardcoded_spacing_or_font_size_in_page_style(page_style):
    offenders = []
    for match in HARDCODED_SPACING_RE.finditer(page_style):
        prop, value = match.group(1), match.group(2)
        remainder = _values_outside_var(value).strip()
        tokens = [t for t in remainder.split() if t not in ("0", "auto")]
        if tokens:
            offenders.append(f"{prop}: {value.strip()}")
    assert not offenders, (
        f"enterprise-knowledge-center.html's <style> block has hardcoded "
        f"spacing/font-size outside var(--sapx-*): {offenders}"
    )


def test_tokens_css_linked_before_components_css(parsed):
    assert "/css/tokens.css" in parsed.stylesheet_hrefs
    assert "/css/components.css" in parsed.stylesheet_hrefs
    assert parsed.stylesheet_hrefs.index("/css/tokens.css") < parsed.stylesheet_hrefs.index("/css/components.css")


def test_hero_css_not_used(parsed):
    assert "/css/hero.css" not in parsed.stylesheet_hrefs


# ---------------------------------------------------------------------
# 2. Duplicate component detection
# ---------------------------------------------------------------------

def test_page_style_does_not_redefine_existing_components(page_style):
    redefined = []
    for header, _body in _all_rules(page_style):
        for selector in header.split(","):
            selector = selector.strip()
            if selector.startswith(".sapx-"):
                redefined.append(selector)
    assert not redefined, (
        f"enterprise-knowledge-center.html redefines existing component "
        f"selector(s) in its own <style> block: {redefined} -- extend "
        f"with a pr9-* class instead of shadowing components.css."
    )


def test_no_undefined_classes_referenced(parsed, page_style):
    def defined_classes(css_text):
        return {m.group(1) for m in re.finditer(r"\.([a-zA-Z0-9_-]+)", css_text)}

    defined = (
        defined_classes(COMPONENTS_CSS.read_text(encoding="utf-8"))
        | defined_classes(page_style)
    )
    undefined = sorted(c for c in parsed.classes if c not in defined)
    assert not undefined, (
        f"enterprise-knowledge-center.html references undefined CSS class(es): {undefined}"
    )


# ---------------------------------------------------------------------
# 3. Heading hierarchy validation
# ---------------------------------------------------------------------

def test_exactly_one_h1(parsed):
    h1_count = sum(1 for level in parsed.headings if level == 1)
    assert h1_count == 1, f"expected exactly one <h1>, found {h1_count}"


def test_no_skipped_heading_levels(parsed):
    max_seen = 0
    for level in parsed.headings:
        assert level <= max_seen + 1, (
            f"heading hierarchy skips a level: encountered h{level} after "
            f"the highest level so far was h{max_seen} (sequence: {parsed.headings})"
        )
        max_seen = max(max_seen, level)


# ---------------------------------------------------------------------
# 4. DOM validation
# ---------------------------------------------------------------------

def test_no_duplicate_ids(parsed):
    duplicates = sorted({i for i in parsed.ids if parsed.ids.count(i) > 1})
    assert not duplicates, f"duplicate id attribute(s) found: {duplicates}"


def test_required_landmarks_present(parsed):
    assert parsed.saw_skip_link, "missing .sapx-skip-link"
    assert parsed.saw_header, "missing header.sapx-site-header"
    assert parsed.saw_primary_nav, 'missing nav[aria-label="Primary"]'
    assert parsed.saw_main, "missing main#main-content"
    assert parsed.saw_footer, "missing footer.sapx-site-footer"


def test_skip_link_target_exists(page_text, parsed):
    match = re.search(r'<a class="sapx-skip-link" href="#([^"]+)"', page_text)
    assert match, "skip link not found or not in expected form"
    assert match.group(1) in parsed.ids


# ---------------------------------------------------------------------
# 5. Broken-link detection
# ---------------------------------------------------------------------

def _resolve_repo_path(href: str):
    if href.startswith(NON_FILE_SCHEMES) or href.startswith("#"):
        return None
    path_part = urlsplit(href).path
    if not path_part:
        return None
    if not path_part.startswith("/"):
        path_part = "/" + path_part
    fs_path = REPO_ROOT / path_part.lstrip("/")
    if path_part.endswith("/"):
        fs_path = fs_path / "index.html"
    return fs_path


def test_internal_links_resolve(parsed):
    broken = []
    for href in parsed.hrefs:
        base = href.split("#")[0]
        if not base:
            continue
        fs_path = _resolve_repo_path(base)
        if fs_path is None:
            continue
        if not fs_path.exists():
            broken.append((href, str(fs_path)))
    assert not broken, f"internal link(s) do not resolve to a real file: {broken}"


# ---------------------------------------------------------------------
# 6. Search validation (PR-9-specific)
# ---------------------------------------------------------------------

def test_search_input_is_labeled(page_text):
    assert '<label class="pr9-search-label" for="pr9-search-input">' in page_text
    assert 'id="pr9-search-input"' in page_text


def test_search_has_live_result_count(page_text):
    assert 'id="pr9-search-count"' in page_text
    assert 'aria-live="polite"' in page_text


def test_search_filter_function_defined_and_wired(page_text):
    assert "function pr9FilterKnowledgeCenter(" in page_text
    assert 'oninput="pr9FilterKnowledgeCenter(this.value)"' in page_text


def test_every_search_card_has_category_and_text(page_text):
    cards = re.findall(r'<div class="sapx-card sapx-feature-card pr9-search-card"[^>]*>', page_text)
    assert len(cards) >= 25, f"expected at least 25 search cards, found {len(cards)}"
    assert all('data-category="' in c for c in cards), "every search card needs data-category"
    assert all('data-text="' in c for c in cards), "every search card needs data-text"


def test_search_result_count_matches_actual_card_count(page_text):
    """The hardcoded initial 'Showing all N resources' text must match
    the real number of .pr9-search-card elements -- guards the exact
    off-by-one this test would have caught during development."""
    cards = re.findall(r'class="sapx-card sapx-feature-card pr9-search-card"', page_text)
    match = re.search(r"Showing all (\d+) resources\.", page_text)
    assert match, "expected an initial 'Showing all N resources.' count"
    assert int(match.group(1)) == len(cards), (
        f"hardcoded initial count says {match.group(1)} but {len(cards)} "
        f".pr9-search-card elements actually exist"
    )


# ---------------------------------------------------------------------
# 7. Navigation consistency across the enterprise-family (PR-9-specific)
# ---------------------------------------------------------------------

def _primary_nav_hrefs(filename: str) -> list[str]:
    path = REPO_ROOT / filename
    assert path.exists(), f"{path} not found"
    parsed_page = _parse(path.read_text(encoding="utf-8"))
    return parsed_page.primary_nav_hrefs


def test_all_enterprise_family_pages_share_identical_primary_nav():
    """This PR unified a previously-diverged nav (enterprise-homepage.html
    and enterprise-pricing.html had one 7-link nav without Trust Center;
    enterprise-compliance.html and developer-portal.html had a different
    6-link nav without Documentation/Research). All 5 pages must now
    carry the exact same set of nav hrefs, or the unification has
    regressed."""
    nav_sets = {page: _primary_nav_hrefs(page) for page in FAMILY_PAGES}
    reference = set(nav_sets[FAMILY_PAGES[0]])
    mismatched = {
        page: hrefs for page, hrefs in nav_sets.items()
        if set(hrefs) != reference
    }
    assert not mismatched, (
        f"primary nav hrefs are not identical across the enterprise-family: {mismatched}"
    )


def test_primary_nav_includes_knowledge_center_on_every_family_page():
    for page in FAMILY_PAGES:
        hrefs = _primary_nav_hrefs(page)
        assert "/enterprise-knowledge-center.html" in hrefs, (
            f"{page}'s primary nav is missing the Knowledge Center link"
        )


def test_own_nav_link_has_aria_current(page_text):
    assert '<li><a href="/enterprise-knowledge-center.html" aria-current="page">Knowledge Center</a></li>' in page_text


# ---------------------------------------------------------------------
# 8. Repository drift disclosure integrity (PR-9-specific)
# ---------------------------------------------------------------------

def test_drift_dashboard_section_present(parsed, page_text):
    assert "drift-dashboard" in parsed.ids, "expected #drift-dashboard section anchor"
    assert "Known Repository Drift Dashboard" in page_text


def test_drift_dashboard_covers_every_major_topic(page_text):
    required_topics = [
        "Platform version number",
        "SOC 2 / ISO 27001 status",
        "Canonical vs. shipped navigation",
        "Site-wide navigation connectivity",
        "Sitemap coverage",
        "Broken sitemap reference",
        "JWT signing algorithm",
    ]
    missing = [t for t in required_topics if t not in page_text]
    assert not missing, f"Known Repository Drift Dashboard is missing topic(s): {missing}"


def test_version_drift_discloses_all_three_values(page_text):
    """Guards the specific three-way version split found during this
    PR's audit: v184.0, v185.0, and the actually-deployed v174.1 (with
    the API health endpoint reporting 170.0) must all be named."""
    for value in ("v184.0", "v185.0", "v174.1", "170.0"):
        assert value in page_text, f"expected version drift disclosure to mention {value!r}"


def test_does_not_silently_pick_a_jwt_algorithm_side(page_text):
    assert "HS256" in page_text and "RS256" in page_text


def test_links_to_pr8_drift_notice_rather_than_duplicating_it(page_text):
    """PR-9 must cross-reference PR-8's 9-topic API drift matrix, not
    copy/re-litigate it -- guards against content duplication."""
    assert 'href="/developer-portal.html#drift-notice"' in page_text
    # dist/ never ships *.md (the /docs/... URL 404'd live), so the guide is
    # linked where it renders: the public GitHub repo (2026-09-26).
    assert (
        'href="https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM'
        '/blob/main/docs/developer-portal-guide.md"'
    ) in page_text
