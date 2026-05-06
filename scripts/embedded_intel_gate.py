#!/usr/bin/env python3
"""
SENTINEL APEX v147.3.0 -- EMBEDDED_INTEL POPULATION GATE
=========================================================
STAGE 3.93.5 -- PRE-COMMIT EMBEDDED_INTEL INTEGRITY CHECK

Verifies that window.EMBEDDED_INTEL in index.html is POPULATED (>= 3 items)
BEFORE safe_git_commit.py stages and commits index.html.

ROOT CAUSE ADDRESSED:
  update_embedded_intel.py (Stage 3.6b) cleared EMBEDDED_INTEL to [] on every
  run. If inject_embedded_intel.py (Stage 3.93) failed for ANY reason (empty
  feed, parse error, API timeout), safe_git_commit.py would commit the cleared
  [] state, GitHub Pages would deploy with EMPTY EMBEDDED_INTEL, and
  bootFromEmbeddedCache() would return early -- ZERO instant cards --
  "LIVE INTEL cards disappear" P0.

This gate provides explicit failure visibility in GitHub Actions UI.
The safe_git_commit.py EMBEDDED_INTEL Guard provides the actual blocking
restore (git checkout HEAD -- index.html) if this gate detects empty state.

EXIT CODES:
  0 = always (informational gate -- safe_git_commit.py handles the hard block)

(c) 2026 CyberDudeBivash Pvt. Ltd. CONFIDENTIAL.
"""
import re
import sys
import os

INDEX = "index.html"

print("=== SENTINEL APEX v147.3.0 -- EMBEDDED_INTEL POPULATION GATE ===")
print(f"Checking: {os.path.abspath(INDEX)}")
print()

if not os.path.exists(INDEX):
    print("[WARN] index.html not found -- skipping gate check")
    sys.exit(0)

try:
    html = open(INDEX, encoding="utf-8", errors="replace").read()
except Exception as e:
    print(f"[WARN] Could not read index.html: {e} -- skipping gate check")
    sys.exit(0)

m = re.search(r"window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);", html, re.DOTALL)
if not m:
    print("[WARN] EMBEDDED_INTEL declaration not found -- architecture may differ")
    sys.exit(0)

val = m.group(1).strip()
compact = val.replace(" ", "").replace("\n", "").replace("\r", "")

if compact == "[]" or len(compact) <= 4:
    print("[FAIL] EMBEDDED_INTEL is EMPTY after Stage 3.93 inject.")
    print("       Root cause: inject_embedded_intel.py failed or api/feed.json was empty.")
    print("       safe_git_commit.py EMBEDDED_INTEL Guard will restore index.html from HEAD.")
    print("       Previous known-good EMBEDDED_INTEL state will be committed instead.")
    print("       Dashboard WILL render cards -- from the last-good embedded snapshot.")
    sys.exit(0)

item_count = val.count('"id":')
size_kb = len(val) / 1024
print(f"[PASS] EMBEDDED_INTEL populated: ~{item_count} items ({size_kb:.1f} KB)")
print("       bootFromEmbeddedCache() and card_renderer_integration._bootFromEmbedded()")
print("       will render cards instantly on page load -- no API dependency for initial render.")
sys.exit(0)
