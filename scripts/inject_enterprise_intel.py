#!/usr/bin/env python3
"""
inject_enterprise_intel.py
Phase 2 — Inject enterprise intelligence command center block into index.html
Injection point: between SOC tab panel closing </div> and premium-intel-products section.
Zero-regression: only inserts new content, never removes existing content.
"""
import sys
from pathlib import Path

REPO_ROOT  = Path(__file__).resolve().parent.parent
INDEX_HTML = REPO_ROOT / "index.html"
BLOCK_FILE = REPO_ROOT / "scripts" / "enterprise_intel_block.html"

# The exact string at the injection point (must be unique in file)
INJECTION_MARKER = (
    '\n        <!-- ═══════════════════════════════════════════════════════════════════ -->\n'
    '        <!-- ═══════════════════════════════════════════════════════════════════ -->\n'
    '        <!-- 💰 CYBERDUDEBIVASH PREMIUM INTEL PRODUCTS &mdash; v127.0              -->\n'
    '        <!-- High-value monetized intelligence offerings for SOC teams        -->\n'
    '        <!-- ═══════════════════════════════════════════════════════════════════ -->\n'
    '        <section id="premium-intel-products"'
)

REPLACE_WITH_PREFIX = '\n        <!-- ── ENTERPRISE INTELLIGENCE COMMAND CENTER v158.0 — INJECTED BELOW ── -->\n'

def main():
    if not INDEX_HTML.exists():
        print(f"ERROR: {INDEX_HTML} not found", file=sys.stderr)
        return 1
    if not BLOCK_FILE.exists():
        print(f"ERROR: {BLOCK_FILE} not found", file=sys.stderr)
        return 1

    src   = INDEX_HTML.read_text(encoding='utf-8')
    block = BLOCK_FILE.read_text(encoding='utf-8')

    # Verify injection point exists exactly once
    count = src.count(INJECTION_MARKER)
    if count == 0:
        print("ERROR: Injection marker NOT found in index.html", file=sys.stderr)
        print("  Marker:", repr(INJECTION_MARKER[:80]), file=sys.stderr)
        return 1
    if count > 1:
        print(f"ERROR: Injection marker found {count} times — ambiguous", file=sys.stderr)
        return 1

    # Check enterprise block is not already injected (idempotency guard)
    if 'enterprise-intel-command' in src:
        print("INFO: enterprise-intel-command already present in index.html — skipping injection")
        return 0

    # Perform injection: insert block BEFORE the marker
    new_src = src.replace(
        INJECTION_MARKER,
        REPLACE_WITH_PREFIX + block + INJECTION_MARKER
    )

    # Sanity checks
    assert 'enterprise-intel-command' in new_src, "ASSERTION FAILED: block not found after injection"
    assert 'premium-intel-products' in new_src,   "ASSERTION FAILED: premium-intel-products removed!"
    assert 'id="cdb-panel-soc"' in new_src,       "ASSERTION FAILED: SOC tab panel removed!"
    assert new_src.count('<section id="premium-intel-products"') == 1, "REGRESSION: duplicate premium section!"
    assert len(new_src) > len(src),                "ASSERTION FAILED: file shrunk after injection!"

    INDEX_HTML.write_text(new_src, encoding='utf-8')
    print(f"SUCCESS: Enterprise intel block injected into index.html")
    print(f"  Before: {len(src):,} chars")
    print(f"  After:  {len(new_src):,} chars")
    print(f"  Delta:  +{len(new_src)-len(src):,} chars")
    return 0

if __name__ == "__main__":
    sys.exit(main())
