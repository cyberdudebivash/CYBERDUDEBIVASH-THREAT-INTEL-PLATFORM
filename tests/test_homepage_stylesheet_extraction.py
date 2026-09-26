"""
tests/test_homepage_stylesheet_extraction.py

Homepage weight (2026-09-26): index.html was 1,467,070 bytes (~300 KB
gzipped). GitHub Pages behind Cloudflare serves HTML uncached at the edge
(cf-cache-status: DYNAMIC, max-age=600) but caches /css and /js
(max-age=14400), so every visit re-downloaded ~250 KB of inline design-system
CSS that never changes between feed updates.

The first 225 KB of that <style> block now lives in
css/homepage-design-system.css, linked at the same position. The IOC paywall
rules and everything after them stay inline in their original order: the
cascade is unchanged, and the free-tier blur never depends on an asset load.

These tests keep that safe over time:
- ?v= must equal the file's sha256[:12]. Cloudflare caches /css for 4h, so an
  edited file with an unchanged ?v= would serve stale styles after a deploy.
- The paywall rules stay inline and never move into the external file.
- The link precedes the inline block (cascade order).
- The file keeps index.html's integrity protection.
- index.html stays under a size budget, so the CSS is not re-inlined.
"""
import hashlib
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO / "index.html"
CSS_REL = "css/homepage-design-system.css"
CSS = REPO / CSS_REL
LINK_RE = re.compile(r'<link rel="stylesheet" href="/css/homepage-design-system\.css\?v=([0-9a-f]{12})">')

# Budget: 1,242,493 bytes after extraction (was 1,467,070). Headroom for normal
# edits, but re-inlining the 225 KB stylesheet would fail.
INDEX_BUDGET_BYTES = 1_300_000

PAYWALL_SELECTORS = (
    ".cdb-ioc-lock-strip",
    ".cdb-ioc-lock-blur",
    ".cdb-ioc-lock-overlay",
    ".cdb-ioc-unlock-btn",
    ".cdb-ioc-unlock-btn-alt",
)


def _index() -> str:
    return INDEX.read_text(encoding="utf-8")


def test_link_version_is_content_hash():
    links = LINK_RE.findall(_index())
    assert len(links) == 1, "index.html must link css/homepage-design-system.css exactly once"
    expected = hashlib.sha256(CSS.read_bytes()).hexdigest()[:12]
    assert links[0] == expected, (
        f"css/homepage-design-system.css changed: set its ?v= in index.html to {expected} "
        "(Cloudflare caches /css for 4h; a stale ?v= serves old styles after deploy)"
    )


def test_paywall_rules_stay_inline_after_the_link():
    html = _index()
    css = CSS.read_text(encoding="utf-8")
    link_at = LINK_RE.search(html).start()
    for sel in PAYWALL_SELECTORS:
        assert re.search(re.escape(sel) + r"\s*\{", css) is None, f"{sel} must stay inline, not in {CSS_REL}"
        m = re.search(re.escape(sel) + r"\s*\{", html)
        assert m, f"{sel} rule missing from index.html"
        assert m.start() > link_at, f"{sel} must come after the stylesheet link (cascade order)"
    blur = re.search(r"\.cdb-ioc-lock-blur\s*\{([^}]*)\}", html)
    assert "blur(" in blur.group(1)


def test_link_is_in_head():
    html = _index()
    assert LINK_RE.search(html).start() < html.index("</head>")


def test_extracted_css_has_no_relative_urls_or_imports():
    css = CSS.read_text(encoding="utf-8")
    assert "@import" not in css
    assert re.search(r"url\(\s*['\"]?(?!data:|https?:|#)", css) is None, (
        "relative url() would resolve against /css/ instead of / after extraction"
    )


def test_extracted_css_keeps_integrity_protection():
    import importlib.util
    spec = importlib.util.spec_from_file_location("fi", REPO / "scripts" / "frontend_integrity.py")
    fi = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fi)
    assert CSS_REL in fi.PROTECTED_ASSETS
    wf = yaml.safe_load((REPO / ".github" / "workflows" / "frontend-integrity-sync.yml").read_text(encoding="utf-8"))
    on = wf.get("on") or wf.get(True)
    for event in ("pull_request", "push"):
        assert CSS_REL in on[event]["paths"], f"frontend-integrity-sync {event} paths must include {CSS_REL}"


def test_index_html_stays_within_size_budget():
    size = INDEX.stat().st_size
    assert size <= INDEX_BUDGET_BYTES, f"index.html is {size} bytes (budget {INDEX_BUDGET_BYTES})"
