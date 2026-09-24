#!/usr/bin/env python3
"""
Customer-visible release label check.

Every root *.html page that shows a SENTINEL APEX release label to a visitor
must show the current platform release (VERSION). Labels inside HTML
comments, CSS comments and non-JSON-LD <script> blocks are not visible and
are ignored; component versions (Watchdog 3.0.0, webhook contract, schema
versions) are not release labels and are never matched.

    python3 scripts/customer_release_label.py            # report, exit 1 on drift
    python3 scripts/customer_release_label.py --apply    # rewrite drifted labels
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# "SENTINEL APEX v184.0", "SENTINEL APEX&trade; v184.0", "API &mdash; v200.0",
# "APEX &mdash; v200.0". Group 1 is the version number only.
LABEL = re.compile(
    r"(?:SENTINEL APEX(?:&trade;|™)?\s*(?:&mdash;|—|-)?\s*v"
    r"|(?:API|APEX)\s*(?:&mdash;|—)\s*v)(\d{3}\.\d)\b"
)
HIDDEN = [
    re.compile(r"<!--.*?-->", re.S),
    re.compile(r"<style\b[^>]*>.*?</style>", re.S | re.I),
]
SCRIPT = re.compile(r"<script\b([^>]*)>.*?</script>", re.S | re.I)
# Visible text that names a release in another form.
EXTRA = [
    re.compile(r'("platform":"CYBERDUDEBIVASH SENTINEL APEX","version":"v)(\d{3}\.\d)(")'),
    re.compile(r'(Documented in <code>api-docs\.html</code> \("v)(\d{3}\.\d)("\))'),
]


def current() -> str:
    return (REPO / "VERSION").read_text().strip()


def _mask(src: str) -> str:
    """Blank out comments, <style> blocks and non-JSON-LD scripts (invisible text)."""
    out = src
    for rx in HIDDEN:
        out = rx.sub(lambda m: " " * len(m.group(0)), out)
    return SCRIPT.sub(
        lambda m: m.group(0) if "ld+json" in m.group(1).lower() else " " * len(m.group(0)), out
    )


def drift(path: Path, ver: str) -> list[tuple[int, str]]:
    src = path.read_text(encoding="utf-8", errors="replace")
    masked = _mask(src)
    found = [(m.start(1), m.group(1)) for m in LABEL.finditer(masked) if m.group(1) != ver]
    for rx in EXTRA:
        found += [(m.start(2), m.group(2)) for m in rx.finditer(src) if m.group(2) != ver]
    return sorted(found)


def apply(path: Path, ver: str) -> int:
    hits = drift(path, ver)
    if not hits:
        return 0
    src = path.read_text(encoding="utf-8", errors="replace")
    for pos, old in reversed(hits):
        src = src[:pos] + ver + src[pos + len(old):]
    path.write_text(src, encoding="utf-8")
    return len(hits)


def main() -> int:
    ver = current()
    pages = sorted(REPO.glob("*.html"))
    if "--apply" in sys.argv:
        n = sum(apply(p, ver) for p in pages)
        print(f"rewrote {n} label(s) to v{ver}")
        return 0
    bad = {p.name: [v for _, v in drift(p, ver)] for p in pages}
    bad = {k: v for k, v in bad.items() if v}
    for name, vs in bad.items():
        print(f"DRIFT {name}: {', '.join('v' + v for v in vs)} (current v{ver})")
    print(f"{len(pages)} pages checked, {len(bad)} with a non-current visible release label")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
