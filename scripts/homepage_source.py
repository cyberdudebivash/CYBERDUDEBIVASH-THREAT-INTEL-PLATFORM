#!/usr/bin/env python3
"""
scripts/homepage_source.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Homepage source (index.html + extracted assets)
====================================================================================
2026-09-26: two large inline blocks moved out of index.html so browsers and
Cloudflare can cache them (index.html: 1,467,070 -> ~732,000 bytes):

  css/homepage-design-system.css   the first 225 KB of the design-system <style>
  js/homepage-dashboard-engine.js  the 511 KB dashboard-engine <script>

Gates and tests that inspect the homepage's CODE (EMBEDDED_INTEL, tier gates,
freshness wiring, paywall CTAs, encoding scans, ...) must keep seeing that
code. read_homepage_source() returns index.html with each extracted asset put
back inline at its reference, i.e. the same text those checks read before the
extraction. Checks keep their exact logic; only the read changes.

Use this for content inspection only. Hashing, copying or deploying the real
file must keep using index.html itself.

A missing asset file leaves its reference tag in place, so content checks fail
closed instead of passing on a partial page.

CLI: `python3 scripts/homepage_source.py` prints the homepage source to
stdout (for shell and node consumers in workflows).

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_HTML = "index.html"


def _inline_css(text: str) -> str:
    # The file holds the block's text plus one trailing newline; the inline
    # remainder of the same <style> block continues right after it.
    return "<style>\n" + (text[:-1] if text.endswith("\n") else text)


def _inline_js(text: str) -> str:
    return "<script>\n" + text + "</script>"


# (asset path, reference pattern in index.html, rebuild-inline function)
EXTRACTED_ASSETS: tuple = (
    (
        "css/homepage-design-system.css",
        re.compile(
            r'<link rel="stylesheet" href="/css/homepage-design-system\.css\?v=[0-9a-f]{12}">'
            r"\n    <!--(?:(?!-->).)*-->\n    <style>",
            re.S,
        ),
        _inline_css,
    ),
    (
        "js/homepage-dashboard-engine.js",
        re.compile(r'<script src="/js/homepage-dashboard-engine\.js\?v=[0-9a-f]{12}"></script>'),
        _inline_js,
    ),
)


def read_homepage_source(root: Path | str | None = None) -> str:
    """index.html with its extracted assets inlined back at their references."""
    base = Path(root) if root is not None else REPO_ROOT
    html = (base / INDEX_HTML).read_text(encoding="utf-8", errors="replace")
    for rel, pattern, rebuild in EXTRACTED_ASSETS:
        asset = base / rel
        if not asset.is_file():
            continue  # reference stays; content checks fail closed
        text = asset.read_text(encoding="utf-8", errors="replace")
        html = pattern.sub(lambda _m, t=text, r=rebuild: r(t), html, count=1)
    return html


def asset_version(text: str) -> str:
    """The ?v= cache-busting value for an extracted asset: sha256[:12] of its text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def stale_asset_versions(root: Path | str | None = None) -> list[tuple[str, str, str]]:
    """(asset, ?v= in index.html, expected ?v=) for every extracted asset whose
    reference no longer matches its content. Cloudflare caches /css and /js for
    4h, so a stale ?v= keeps serving the old file after a deploy."""
    base = Path(root) if root is not None else REPO_ROOT
    html = (base / INDEX_HTML).read_text(encoding="utf-8")
    stale = []
    for rel, _pattern, _rebuild in EXTRACTED_ASSETS:
        asset = base / rel
        m = re.search(re.escape("/" + rel) + r"\?v=([0-9a-f]{12})", html)
        if not (asset.is_file() and m):
            continue
        expected = asset_version(asset.read_text(encoding="utf-8"))
        if m.group(1) != expected:
            stale.append((rel, m.group(1), expected))
    return stale


def sync_asset_versions(root: Path | str | None = None) -> list[str]:
    """Rewrites stale ?v= values in index.html. Returns the assets updated.
    Call after any automated edit to an extracted asset (version_governance)."""
    base = Path(root) if root is not None else REPO_ROOT
    stale = stale_asset_versions(base)
    if not stale:
        return []
    path = base / INDEX_HTML
    html = path.read_text(encoding="utf-8")
    for rel, old, new in stale:
        html = html.replace(f"/{rel}?v={old}", f"/{rel}?v={new}")
    tmp = path.with_suffix(".html.assetv_tmp")
    tmp.write_text(html, encoding="utf-8")
    os.replace(tmp, path)
    return [rel for rel, _old, _new in stale]


def is_homepage(path: Path | str) -> bool:
    """True when path is this repo's index.html (however it was spelled)."""
    try:
        return Path(path).resolve() == (REPO_ROOT / INDEX_HTML).resolve()
    except OSError:
        return False


def read_text_for_inspection(path: Path | str, encoding: str = "utf-8", errors: str = "replace") -> str:
    """Drop-in for Path(path).read_text() in content checks: the homepage
    source for index.html, the file's own text for anything else."""
    if is_homepage(path):
        return read_homepage_source()
    return Path(path).read_text(encoding=encoding, errors=errors)


def read_bytes_for_inspection(path: Path | str) -> bytes:
    """Bytes variant of read_text_for_inspection() (UTF-8 for the homepage)."""
    if is_homepage(path):
        return read_homepage_source().encode("utf-8")
    return Path(path).read_bytes()


def main() -> int:
    sys.stdout.write(read_homepage_source())
    return 0


if __name__ == "__main__":
    sys.exit(main())
