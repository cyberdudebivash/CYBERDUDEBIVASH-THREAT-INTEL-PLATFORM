#!/usr/bin/env python3
"""Fail-closed production CDN parity check for Sentinel APEX GitHub Pages.

This gate deliberately does not infer release success from HTTP 200, HEAD,
Last-Modified, or API health. It requires the *actual public* homepage to use
an asset version derived from the candidate source and requires the exact
JavaScript bytes served through that versioned URL to match source SHA-256.

No credentials, writes, purge, paid endpoints, or customer state are touched.
Use only after pages_deploy_freshness_gate.py (which handles publishing delay).
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

REPO = Path(__file__).resolve().parents[1]
ASSET = "js/homepage-dashboard-engine.js"
PATTERN = re.compile(r'<script\b[^>]*\bsrc=["\']/js/homepage-dashboard-engine\.js\?v=([0-9a-f]{12})["\'][^>]*>\s*</script>', re.I)
MAX_HTML = 3 * 1024 * 1024
MAX_JS = 2 * 1024 * 1024


class ReleaseParityError(RuntimeError):
    """A verified production release invariant is not satisfied."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def script_version(html: bytes) -> str:
    matches = PATTERN.findall(html.decode("utf-8", errors="replace"))
    if len(matches) != 1:
        raise ReleaseParityError("Expected one SHA-12 dashboard script tag")
    return matches[0].lower()


def expected_source(root: Path = REPO) -> tuple[str, str]:
    html = (root / "index.html").read_bytes()
    script = (root / ASSET).read_bytes()
    digest = sha256(script)
    if script_version(html) != digest[:12]:
        raise ReleaseParityError("Repository HTML and JS SHA-256 version differ")
    return digest[:12], digest


def public_get(url: str, max_bytes: int, expected_host: str) -> bytes:
    req = Request(url, headers={
        "User-Agent": "SENTINEL-APEX-RELEASE-BYTE-PARITY/1.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Accept": "text/html,application/javascript,*/*",
    })
    with urlopen(req, timeout=12) as resp:
        actual = urlparse(resp.geturl())
        if actual.scheme != "https" or actual.netloc.lower() != expected_host.lower():
            raise ReleaseParityError("Unexpected cross-origin redirect")
        if resp.status != 200:
            raise ReleaseParityError("Unexpected HTTP status: " + str(resp.status))
        blob = resp.read(max_bytes + 1)
        if not blob or len(blob) > max_bytes:
            raise ReleaseParityError("Missing or oversized release asset")
        return blob


def check_once(source: Path = REPO, platform_url: str = "https://intel.cyberdudebivash.com", getter=public_get) -> dict:
    origin = urlparse(platform_url)
    if origin.scheme != "https" or not origin.netloc or origin.path not in ("", "/"):
        raise ReleaseParityError("Invalid canonical HTTPS production origin")
    expected_short, expected_full = expected_source(source)
    # Unique query each run avoids an old cached homepage. The versioned JS
    # URL uses the actual SHA-12 used by customer browsers.
    public_html = getter(urljoin(platform_url + "/", "/?release_parity=" + expected_short), MAX_HTML, origin.netloc)
    observed_short = script_version(public_html)
    if observed_short != expected_short:
        raise ReleaseParityError("Live HTML still serves a different dashboard version")
    # Assert initial claims are not fabricated before JS executes.
    body = public_html.decode("utf-8", errors="replace")
    if not re.search(r'id=["\']sync-val["\'][^>]*>\s*SYNC:\s*<span[^>]*>VERIFYING</span>', body):
        raise ReleaseParityError("Live homepage default SYNC is not VERIFYING")
    if not re.search(r'id=["\']m-feed-count["\'][^>]*>&mdash;</span>\s*REGISTERED', body):
        raise ReleaseParityError("Live homepage still initializes a fabricated source count")
    live_js = getter(urljoin(platform_url + "/", "/" + ASSET + "?v=" + expected_short), MAX_JS, origin.netloc)
    actual_full = sha256(live_js)
    if actual_full != expected_full:
        raise ReleaseParityError("Live dashboard bytes differ from reviewed release SHA-256")
    return {"asset": ASSET, "asset_sha256": actual_full, "asset_version": expected_short,
            "homepage_initial_status": "VERIFYING", "source_count_initial_state": "UNKNOWN",
            "deployed_asset_identical": True}


def main() -> int:
    platform = os.environ.get("PLATFORM_URL", "https://intel.cyberdudebivash.com").rstrip("/")
    try:
        result = check_once(REPO, platform)
    except (OSError, ReleaseParityError, ValueError) as exc:
        print("P0 PRODUCTION BYTE PARITY: FAIL — " + str(exc), file=sys.stderr)
        return 1
    print("P0 PRODUCTION BYTE PARITY: PASS")
    for key, value in result.items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
