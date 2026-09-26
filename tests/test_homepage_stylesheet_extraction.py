"""
tests/test_homepage_stylesheet_extraction.py

Homepage weight (2026-09-26): index.html was 1,467,070 bytes (~300 KB
gzipped). GitHub Pages behind Cloudflare serves HTML uncached at the edge
(cf-cache-status: DYNAMIC, max-age=600) but caches /css and /js
(max-age=14400), so every visit re-downloaded ~736 KB of inline CSS and JS
that only changes when someone edits it.

Two blocks now live in their own files, referenced at the same position:
  css/homepage-design-system.css   first 225 KB of the design-system <style>
  js/homepage-dashboard-engine.js  the 511 KB dashboard-engine <script>

The IOC paywall rules and everything after them stay inline in their original
order: the cascade is unchanged, and the free-tier blur never depends on an
asset load. scripts/homepage_source.py rebuilds the original page text for
every gate and test that inspects the homepage's code.

These tests keep that safe over time:
- ?v= must equal each file's sha256[:12]. Cloudflare caches /css and /js for
  4h, so an edited file with an unchanged ?v= serves the old file after a
  deploy.
- The engine is a plain synchronous <script> (same execution order as inline).
- The paywall rules stay inline and after the stylesheet link.
- The homepage source inlines both files back (no references left) and still
  carries the architecture markers the gates check for.
- Both files keep index.html's integrity protection and ship in dist/.
- index.html stays under a size budget, so neither block is re-inlined.
"""
import hashlib
import importlib.util
import re
from pathlib import Path

import yaml

from scripts.homepage_source import (
    EXTRACTED_ASSETS,
    read_homepage_source,
    stale_asset_versions,
)

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO / "index.html"
CSS_REL = "css/homepage-design-system.css"
JS_REL = "js/homepage-dashboard-engine.js"
CSS = REPO / CSS_REL
JS = REPO / JS_REL
LINK_RE = re.compile(r'<link rel="stylesheet" href="/css/homepage-design-system\.css\?v=([0-9a-f]{12})">')
SCRIPT_RE = re.compile(r'<script src="/js/homepage-dashboard-engine\.js\?v=([0-9a-f]{12})"></script>')

# Budget: 731,846 bytes after both extractions (was 1,467,070). Headroom for
# normal edits, but re-inlining either block would fail.
INDEX_BUDGET_BYTES = 800_000

PAYWALL_SELECTORS = (
    ".cdb-ioc-lock-strip",
    ".cdb-ioc-lock-blur",
    ".cdb-ioc-lock-overlay",
    ".cdb-ioc-unlock-btn",
    ".cdb-ioc-unlock-btn-alt",
)

# Markers the deploy-blocking gates require in the homepage source
# (apex_stability_lock, regression_immunity, access-governance-gate.yml, ...).
ARCHITECTURE_MARKERS = (
    "window.EMBEDDED_INTEL",
    "api/v1/intel/latest.json",
    "_isPro",
    "_hasProAccess",
    "ACCESS GOVERNANCE v184.0",
    "CDB-RENDERER-ENGINE-V173-START",
)


def _index() -> str:
    return INDEX.read_text(encoding="utf-8")


def test_versions_are_content_hashes():
    html = _index()
    for regex, path in ((LINK_RE, CSS), (SCRIPT_RE, JS)):
        refs = regex.findall(html)
        assert len(refs) == 1, f"index.html must reference {path.name} exactly once"
        expected = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
        assert refs[0] == expected, (
            f"{path.name} changed: set its ?v= in index.html to {expected}, or run "
            "scripts/version_governance.py --apply (Cloudflare caches /css and /js for 4h)"
        )
    assert stale_asset_versions() == []


def test_engine_script_is_synchronous():
    tag = SCRIPT_RE.search(_index()).group(0)
    assert " async" not in tag and " defer" not in tag and "type=" not in tag, (
        "the engine ran inline; it must stay a plain classic script to keep execution order"
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


def test_stylesheet_link_is_in_head():
    html = _index()
    assert LINK_RE.search(html).start() < html.index("</head>")


def test_extracted_files_are_self_contained():
    css = CSS.read_text(encoding="utf-8")
    assert "@import" not in css
    assert re.search(r"url\(\s*['\"]?(?!data:|https?:|#)", css) is None, (
        "relative url() would resolve against /css/ instead of / after extraction"
    )
    for path in (CSS, JS):
        assert not path.read_bytes().startswith(b"\xef\xbb\xbf"), f"{path.name} must not start with a BOM"
    assert "</script" not in JS.read_text(encoding="utf-8").lower()


def test_homepage_source_inlines_both_assets():
    source = read_homepage_source()
    for rel, _pattern, _rebuild in EXTRACTED_ASSETS:
        assert f"/{rel}?v=" not in source, f"{rel} was not inlined back into the homepage source"
    for marker in ARCHITECTURE_MARKERS:
        assert marker in source, f"homepage source lost {marker!r}"


def test_homepage_source_fails_closed_without_an_asset(tmp_path):
    (tmp_path / "index.html").write_text(_index(), encoding="utf-8")
    (tmp_path / "css").mkdir()
    (tmp_path / "css" / CSS.name).write_text(CSS.read_text(encoding="utf-8"), encoding="utf-8")
    source = read_homepage_source(tmp_path)  # engine file missing
    assert f"/{JS_REL}?v=" in source
    # Both live only in the engine: the gates that require them now fail.
    assert re.search(r"window\.EMBEDDED_INTEL\s*=\s*\[", source) is None
    assert "api/v1/intel/latest.json" not in source


def test_extracted_files_keep_integrity_protection():
    spec = importlib.util.spec_from_file_location("fi", REPO / "scripts" / "frontend_integrity.py")
    fi = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fi)
    wf = yaml.safe_load((REPO / ".github" / "workflows" / "frontend-integrity-sync.yml").read_text(encoding="utf-8"))
    on = wf.get("on") or wf.get(True)
    for rel in (CSS_REL, JS_REL):
        assert rel in fi.PROTECTED_ASSETS
        for event in ("pull_request", "push"):
            assert rel in on[event]["paths"], f"frontend-integrity-sync {event} paths must include {rel}"


def test_extracted_files_ship_in_dist():
    verifier = (REPO / "scripts" / "dist_artifact_verifier.py").read_text(encoding="utf-8")
    fast_publish = (REPO / ".github" / "workflows" / "pages-fast-publish.yml").read_text(encoding="utf-8")
    for rel in (CSS_REL, JS_REL):
        assert f'"{rel}"' in verifier, f"dist_artifact_verifier.py must require dist/{rel}"
        assert rel in fast_publish, f"pages-fast-publish.yml must require dist/{rel}"


def test_index_html_stays_within_size_budget():
    size = INDEX.stat().st_size
    assert size <= INDEX_BUDGET_BYTES, f"index.html is {size} bytes (budget {INDEX_BUDGET_BYTES})"
