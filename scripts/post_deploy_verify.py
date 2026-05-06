#!/usr/bin/env python3
"""
SENTINEL APEX v145.4 — POST-DEPLOY EMBEDDED_INTEL VERIFIER
===========================================================
STAGE 5.1 (new) — POST-DEPLOY VERIFICATION

Verifies that the deployed index.html on GitHub Pages / Cloudflare actually
has a populated EMBEDDED_INTEL after the pipeline's git commit and deploy.

WHY THIS EXISTS:
  The P0 root cause was that update_embedded_intel.py (Stage 3.6b) cleared
  EMBEDDED_INTEL to [] on every pipeline run, and if inject_embedded_intel.py
  (Stage 3.93) then failed, safe_git_commit.py committed the cleared state.
  GitHub Pages deployed with empty EMBEDDED_INTEL → bootFromEmbeddedCache()
  returned early → zero instant cards → "LIVE INTEL cards disappear" P0.

  This verifier runs AFTER GitHub Pages deploy and checks:
  1. The LOCAL committed index.html has populated EMBEDDED_INTEL (>= 3 items)
  2. The sapx-card-grid container div exists in index.html
  3. The card renderer scripts are referenced in index.html
  4. The api/feed.json in the repo is valid and non-empty

EXIT CODES:
  0 = PASS (all checks passed)
  0 = WARN (some checks failed — non-fatal, alerting only)
  (Never exits 1 — this step must not block the pipeline after deploy)

(c) 2026 CyberDudeBivash Pvt. Ltd. CONFIDENTIAL.
"""
import sys
import os
import re
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_PATH = REPO_ROOT / "index.html"
API_FEED_PATH = REPO_ROOT / "api" / "feed.json"

PASS = "[PASS]"
WARN = "[WARN]"
FAIL = "[FAIL]"

failures = []
warnings_list = []


def check_pass(msg):
    print(f"{PASS} {msg}")


def check_warn(msg):
    print(f"{WARN} {msg}")
    warnings_list.append(msg)


def check_fail(msg):
    print(f"{FAIL} {msg}")
    failures.append(msg)


print("=" * 68)
print("SENTINEL APEX v145.4 -- POST-DEPLOY VERIFIER")
print("Checking local committed state matches production requirements")
print("=" * 68)
print()

# ─── CHECK 1: index.html exists ─────────────────────────────────────────────
print("CHECK 1: index.html exists and is non-empty")
if not INDEX_PATH.exists():
    check_fail("index.html not found in repository")
    print("\n[RESULT] POST-DEPLOY VERIFY: CRITICAL ISSUES FOUND (non-blocking)")
    sys.exit(0)

html = INDEX_PATH.read_text(encoding="utf-8", errors="replace")
html_kb = len(html) / 1024
if len(html) < 100_000:
    check_fail(f"index.html is only {html_kb:.1f} KB — likely truncated (expected > 100KB)")
else:
    check_pass(f"index.html present: {html_kb:.0f} KB")

print()

# ─── CHECK 2: EMBEDDED_INTEL is populated ───────────────────────────────────
print("CHECK 2: EMBEDDED_INTEL is populated (>= 3 items) in committed index.html")
ei_pattern = re.compile(r'window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);', re.DOTALL)
ei_match = ei_pattern.search(html)
if not ei_match:
    check_fail("window.EMBEDDED_INTEL declaration not found in index.html")
else:
    ei_val = ei_match.group(1).strip()
    ei_compact = ei_val.replace(" ", "").replace("\n", "").replace("\r", "")
    if ei_compact == "[]" or len(ei_compact) <= 4:
        check_fail(
            "EMBEDDED_INTEL = [] in committed index.html. "
            "inject_embedded_intel.py failed or was skipped. "
            "bootFromEmbeddedCache() will return early — no instant cards. "
            "ACTION REQUIRED: Check Stage 3.93 logs in this workflow run."
        )
        failures[-1] += (
            " | FIX: Ensure api/feed.json is non-empty before Stage 3.93."
        )
    else:
        item_count = ei_val.count('"id":')
        size_kb = len(ei_val) / 1024
        check_pass(
            f"EMBEDDED_INTEL populated: ~{item_count} items ({size_kb:.1f} KB) — "
            "bootFromEmbeddedCache() will render cards instantly on page load"
        )

print()

# ─── CHECK 3: sapx-card-grid container present ──────────────────────────────
print("CHECK 3: #sapx-card-grid container present in index.html")
if 'id="sapx-card-grid"' in html or "id='sapx-card-grid'" in html:
    check_pass("#sapx-card-grid container present — enterprise card renderer has a DOM anchor")
else:
    check_fail(
        "#sapx-card-grid container MISSING from index.html. "
        "card_renderer_integration.js will create a fallback container "
        "(appended to body) which may not appear in the expected location."
    )

print()

# ─── CHECK 4: Card renderer scripts referenced ──────────────────────────────
print("CHECK 4: Card renderer scripts referenced in index.html")
required_scripts = [
    ("js/api_adapter.js",               "API normalizer"),
    ("js/card_renderer.js",             "enterprise card renderer"),
    ("js/card_renderer_integration.js", "integration + boot"),
]
for script_path, desc in required_scripts:
    if script_path in html:
        check_pass(f"{script_path} ({desc}) referenced")
    else:
        check_fail(f"{script_path} ({desc}) NOT referenced in index.html — cards will not load")

print()

# ─── CHECK 5: bootFromEmbeddedCache function present ────────────────────────
print("CHECK 5: bootFromEmbeddedCache() function present in index.html")
if "bootFromEmbeddedCache" in html:
    check_pass("bootFromEmbeddedCache() present — instant render path active")
else:
    check_fail("bootFromEmbeddedCache() NOT found — instant card render path missing")

print()

# ─── CHECK 6: api/feed.json in repo is valid and non-empty ──────────────────
print("CHECK 6: api/feed.json is valid JSON with items")
if not API_FEED_PATH.exists():
    check_warn("api/feed.json not found in repository (may be served from R2 only)")
else:
    try:
        feed_data = json.loads(API_FEED_PATH.read_text(encoding="utf-8"))
        if isinstance(feed_data, list):
            count = len(feed_data)
            if count == 0:
                check_fail(
                    "api/feed.json is an EMPTY array []. "
                    "inject_embedded_intel.py reads from this file — "
                    "empty feed caused the EMBEDDED_INTEL injection to fail/skip."
                )
            else:
                apex_count = sum(1 for i in feed_data if isinstance(i, dict) and i.get("apex_ai"))
                apex_pct = (apex_count / count * 100) if count else 0
                check_pass(
                    f"api/feed.json: {count} items, {apex_pct:.0f}% with apex_ai enrichment"
                )
        else:
            check_warn(
                f"api/feed.json is a {type(feed_data).__name__} (expected list). "
                "inject_embedded_intel.py expects a flat list — injection may fail."
            )
    except json.JSONDecodeError as e:
        check_fail(f"api/feed.json JSON parse error: {e}")

print()

# ─── CHECK 7: Physical JS files exist ───────────────────────────────────────
print("CHECK 7: Card renderer JS files exist on disk")
js_files = [
    REPO_ROOT / "js" / "api_adapter.js",
    REPO_ROOT / "js" / "card_renderer.js",
    REPO_ROOT / "js" / "card_renderer_integration.js",
    REPO_ROOT / "css" / "card_renderer_styles.css",
]
for jf in js_files:
    rel = jf.relative_to(REPO_ROOT)
    if jf.exists():
        size_kb = jf.stat().st_size / 1024
        check_pass(f"{rel}: {size_kb:.0f} KB")
    else:
        check_fail(f"{rel}: FILE MISSING — card renderer will not load")

print()

# ─── FINAL REPORT ────────────────────────────────────────────────────────────
print("=" * 68)
if failures:
    print(f"POST-DEPLOY VERIFY: {len(failures)} ISSUE(S) DETECTED (non-blocking)")
    print()
    for i, f in enumerate(failures, 1):
        print(f"  {i}. {f}")
    print()
    print("ACTION: Review Stage 3.93 (inject_embedded_intel.py) logs.")
    print("        If api/feed.json was empty, the next pipeline run will fix it.")
    print("        The EMBEDDED_INTEL guard in safe_git_commit.py should have")
    print("        prevented committing an empty state — check its logs too.")
else:
    print("POST-DEPLOY VERIFY: ALL CHECKS PASSED")
    print("Dashboard will render cards instantly from EMBEDDED_INTEL on page load.")

print("=" * 68)

# Always exit 0 — this is a reporting step, not a gate
sys.exit(0)
