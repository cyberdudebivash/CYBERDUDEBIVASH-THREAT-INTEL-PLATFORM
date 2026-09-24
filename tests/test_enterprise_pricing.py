"""
Static-analysis regression tests for enterprise-pricing.html (PR-6).

Same five categories as tests/test_enterprise_homepage.py (PR-5), plus
one PR-6-specific category:

  1. Token usage verification    -- zero hardcoded design values in the
     page's own <style> block, outside var(--sapx-*).
  2. Duplicate component detection -- the page's own <style> block
     never redefines an existing .sapx-* selector, and every class
     referenced is actually defined somewhere.
  3. Heading hierarchy validation -- exactly one <h1>, no skipped
     heading levels.
  4. DOM validation -- no duplicate `id` attributes, required
     landmarks present, skip link's target exists.
  5. Broken-link detection -- every internal href resolves to a real
     file in the repository.
  6. Pricing-fact consistency (PR-6-specific) -- every dollar figure
     quoted on this page must also appear in pricing.html or
     upgrade.html, the pages that actually own real, live pricing.
     This is the automated guard against the exact failure mode the
     task brief warns about ("do not fabricate pricing") for a page
     built from real evidence rather than placeholders: if a number
     here ever drifts from the real pricing page, this test catches it.

Run with: pytest tests/test_enterprise_pricing.py -v
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGE_PATH = REPO_ROOT / "enterprise-pricing.html"
TOKENS_CSS = REPO_ROOT / "css" / "tokens.css"
COMPONENTS_CSS = REPO_ROOT / "css" / "components.css"
REAL_PRICING_HTML = REPO_ROOT / "pricing.html"
REAL_UPGRADE_HTML = REPO_ROOT / "upgrade.html"

NON_FILE_SCHEMES = ("http://", "https://", "mailto:", "tel:")


@pytest.fixture(scope="module")
def page_text():
    assert PAGE_PATH.exists(), f"{PAGE_PATH} not found"
    return PAGE_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def page_style(page_text):
    match = re.search(r"<style>(.*?)</style>", page_text, re.DOTALL)
    assert match, "expected exactly one <style> block in enterprise-pricing.html"
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

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("class"):
            self.classes.update(a["class"].split())
        if a.get("id"):
            self.ids.append(a["id"])
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
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
        if tag == "main" and a.get("id") == "main-content":
            self.saw_main = True
        if tag == "footer" and "sapx-site-footer" in (a.get("class") or "").split():
            self.saw_footer = True


@pytest.fixture(scope="module")
def parsed(page_text):
    parser = _PageParser()
    parser.feed(page_text)
    return parser


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
        f"enterprise-pricing.html's <style> block has hardcoded color "
        f"literal(s) outside var(--sapx-*): {offenders}"
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
        f"enterprise-pricing.html's <style> block has hardcoded spacing/"
        f"font-size outside var(--sapx-*): {offenders}"
    )


def test_tokens_css_linked_before_components_css(parsed):
    assert "/css/tokens.css" in parsed.stylesheet_hrefs
    assert "/css/components.css" in parsed.stylesheet_hrefs
    assert parsed.stylesheet_hrefs.index("/css/tokens.css") < parsed.stylesheet_hrefs.index("/css/components.css")


def test_hero_css_not_used(parsed):
    """This is a content page, not the landing hero -- css/hero.css is
    documented as scoped to that specific placement, so it must not be
    linked here (would risk re-introducing the disclosed .sapx-btn-primary
    cascade conflict PR-5 fixed for the homepage, on a page that has no
    reason to load hero.css at all)."""
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
        f"enterprise-pricing.html redefines existing component selector(s) "
        f"in its own <style> block: {redefined} -- extend with a pr6-* "
        f"class instead of shadowing components.css."
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
        f"enterprise-pricing.html references undefined CSS class(es): {undefined}"
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
        fs_path = _resolve_repo_path(href)
        if fs_path is None:
            continue
        if not fs_path.exists():
            broken.append((href, str(fs_path)))
    assert not broken, f"internal link(s) do not resolve to a real file: {broken}"


# ---------------------------------------------------------------------
# 6. Pricing-fact consistency (PR-6-specific)
# ---------------------------------------------------------------------

DOLLAR_FIGURE_RE = re.compile(r"\$[\d,]+(?:\.\d+)?")


def test_every_dollar_figure_matches_real_pricing_pages(page_text):
    """Every $-figure shown on this presentation page must also appear
    on pricing.html or upgrade.html -- the pages that own real, live
    pricing. Guards against this page's numbers ever drifting from the
    real checkout flow (the exact "do not fabricate pricing" risk the
    PR-6 brief calls out, applied to a page built from real evidence)."""
    assert REAL_PRICING_HTML.exists() and REAL_UPGRADE_HTML.exists()
    real_figures = set(DOLLAR_FIGURE_RE.findall(REAL_PRICING_HTML.read_text(encoding="utf-8")))
    real_figures |= set(DOLLAR_FIGURE_RE.findall(REAL_UPGRADE_HTML.read_text(encoding="utf-8")))

    page_figures = set(DOLLAR_FIGURE_RE.findall(page_text))
    unmatched = sorted(page_figures - real_figures)
    assert not unmatched, (
        f"enterprise-pricing.html quotes dollar figure(s) not found in "
        f"pricing.html or upgrade.html: {unmatched} -- every price here "
        f"must match the real, live pricing pages exactly."
    )
    # Sanity: this page must actually show pricing, not zero figures
    # (an empty intersection would trivially "pass" the check above).
    assert page_figures, "expected at least one dollar figure on the pricing page"


def test_api_rate_limits_match_real_comparison_table(page_text):
    """Same guard as above, for the per-day API rate limits quoted in the
    API Plans section. Expected figures come from config/commercial-contract.json
    (requests_per_day) rather than literals -- the previous hardcoded "100/day"
    for FREE was itself stale (contract and DAILY_QUOTAS: 50/day)."""
    import json
    contract = json.loads((REPO_ROOT / "config" / "commercial-contract.json").read_text(encoding="utf-8"))
    real_text = REAL_PRICING_HTML.read_text(encoding="utf-8")
    expected = [f"{contract['tiers'][t]['requests_per_day']:,}/day" for t in ("free", "pro", "enterprise")]
    for limit in expected:
        assert limit in page_text, f"enterprise-pricing.html missing expected rate limit '{limit}'"
        assert limit in real_text, f"'{limit}' not found in real pricing.html -- page may be quoting a stale figure"
