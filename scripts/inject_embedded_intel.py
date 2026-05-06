#!/usr/bin/env python3
"""
SENTINEL APEX v147.0 — EMBEDDED INTEL INJECTOR
================================================
STAGE 3.93 — PRE-DEPLOY INSTANT-RENDER INJECTION

Reads top-N items from api/feed.json and injects them into index.html as
window.EMBEDDED_INTEL = [...] for instant-render before the API fetch completes.

Architecture role (v147.0 — 3-LAYER FALLBACK):
  INSTANT   : EMBEDDED_INTEL (THIS SCRIPT — top-25 items, injected pre-deploy)
  PRIMARY   : Worker API    (data.preview.items)
  FALLBACK1 : api/feed.json (same-domain — Worker R2 handler)
  FALLBACK2 : raw.githubusercontent.com (cross-origin bypass)

Why instant-render matters:
  - User sees intel cards immediately on page load (zero spinner wait)
  - Protects against ALL network failures — dashboard always shows last-known data
  - EMBEDDED_INTEL is refreshed every pipeline run → always max 1 pipeline cycle stale

Atomic write strategy:
  1. Read current index.html
  2. Build replacement EMBEDDED_INTEL block in memory
  3. Write to tmp file → fsync → rename (atomic replace — no partial state)

Exit 0 = SUCCESS (index.html updated)
Exit 1 = FAILURE (fatal — source or target missing / parse error)
"""

import sys
import os
import json
import re
import tempfile
import shutil
import traceback

# ── CONFIG ──────────────────────────────────────────────────────────────────
FEED_PATH   = 'api/feed.json'
INDEX_PATH  = 'index.html'
INJECT_N    = 25          # Top N items to embed (keeps payload small)
SCRIPT_NAME = 'inject_embedded_intel.py'
VERSION     = 'v147.0'


def fatal(msg):
    print(f'[FATAL] {msg}')
    sys.exit(1)


def info(msg):
    print(f'[ OK ] {msg}')


def warn(msg):
    print(f'[WARN] {msg}')


print(f'=== SENTINEL APEX {VERSION} — EMBEDDED INTEL INJECTOR ===')
print(f'Feed  : {os.path.abspath(FEED_PATH)}')
print(f'Target: {os.path.abspath(INDEX_PATH)}')
print(f'Inject: top {INJECT_N} items')
print()

# ── STEP 1: Read api/feed.json ───────────────────────────────────────────────
if not os.path.exists(FEED_PATH):
    fatal(f'{FEED_PATH} not found — pipeline must generate it before this stage')

try:
    with open(FEED_PATH, 'r', encoding='utf-8', errors='replace') as f:
        raw_feed = json.load(f)
except json.JSONDecodeError as e:
    fatal(f'{FEED_PATH} JSON parse error: {e}')

if not isinstance(raw_feed, list):
    # ===========================================================================
    # P0 PERMANENT FIX (v147.1): Non-fatal on bad feed format — preserve existing
    # EMBEDDED_INTEL rather than crashing and leaving index.html with [] after
    # update_embedded_intel.py cleared it at Stage 3.6b.
    # ===========================================================================
    warn(f'{FEED_PATH} is not a JSON array (got {type(raw_feed).__name__}) — '
         f'preserving existing EMBEDDED_INTEL in index.html')
    print('[INJECT PRESERVED] Existing EMBEDDED_INTEL preserved — no change to index.html')
    sys.exit(0)

if len(raw_feed) == 0:
    # ===========================================================================
    # P0 PERMANENT FIX (v147.1): Non-fatal on empty feed — read and preserve
    # existing EMBEDDED_INTEL rather than clearing it. This prevents the P0 where
    # update_embedded_intel.py cleared EMBEDDED_INTEL to [] at Stage 3.6b, then
    # this script exited 1 (FATAL) → safe_git_commit.py committed [] → cards gone.
    # ===========================================================================
    warn(f'{FEED_PATH} is empty — checking existing EMBEDDED_INTEL in index.html')
    if os.path.exists(INDEX_PATH):
        with open(INDEX_PATH, 'r', encoding='utf-8', errors='replace') as _f:
            _existing = _f.read()
        _ei_match = re.search(r'window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);', _existing, re.DOTALL)
        if _ei_match:
            _ei_val = _ei_match.group(1).strip().replace(' ', '').replace('\n', '')
            if _ei_val != '[]' and len(_ei_val) > 4:
                print(f'[INJECT PRESERVED] api/feed.json empty but existing EMBEDDED_INTEL '
                      f'has data ({len(_ei_val):,} chars) — preserving, no write needed')
                sys.exit(0)
    warn('Both api/feed.json AND existing EMBEDDED_INTEL are empty — '
         'dashboard will rely entirely on live API fetch')
    print('[INJECT SKIP] Nothing to inject — exiting 0 (non-fatal, live API is fallback)')
    sys.exit(0)

info(f'Feed loaded: {len(raw_feed)} total items')

# ── STEP 2: Sort by freshness, take top N ───────────────────────────────────
def sort_key(item):
    """Sort by processed_at > published_at > timestamp DESC, then risk_score DESC."""
    ts_str = (
        item.get('processed_at') or
        item.get('published_at') or
        item.get('timestamp') or
        item.get('generated_at') or
        ''
    )
    try:
        from datetime import datetime, timezone
        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp() if ts_str else 0
    except (ValueError, AttributeError):
        ts = 0
    risk = item.get('risk_score') or item.get('cvss_score') or 0
    try:
        risk = float(risk)
    except (TypeError, ValueError):
        risk = 0.0
    return (ts, risk)

feed_sorted = sorted(raw_feed, key=sort_key, reverse=True)
top_items   = feed_sorted[:INJECT_N]
info(f'Selected top {len(top_items)} items for EMBEDDED_INTEL injection')

# ── STEP 3: Serialise to compact JSON ────────────────────────────────────────
try:
    embedded_json = json.dumps(top_items, ensure_ascii=False, separators=(',', ':'))
except Exception as e:
    fatal(f'JSON serialisation failed: {e}')

info(f'Serialised payload: {len(embedded_json):,} bytes')

# ── STEP 4: Read index.html ──────────────────────────────────────────────────
if not os.path.exists(INDEX_PATH):
    fatal(f'{INDEX_PATH} not found')

with open(INDEX_PATH, 'r', encoding='utf-8', errors='replace') as f:
    html_content = f.read()

# ── STEP 5: Locate and replace EMBEDDED_INTEL declaration ────────────────────
# Pattern matches:  window.EMBEDDED_INTEL = [...anything...];
# Uses non-greedy match with DOTALL so it handles multi-line existing arrays too.
pattern = re.compile(
    r'(window\.EMBEDDED_INTEL\s*=\s*)\[.*?\](;)',
    re.DOTALL
)

match = pattern.search(html_content)
if not match:
    fatal('window.EMBEDDED_INTEL declaration not found in index.html — cannot inject')

# Build replacement: keep prefix and suffix, inject new array
replacement = match.group(1) + embedded_json + match.group(2)
new_content  = html_content[:match.start()] + replacement + html_content[match.end():]

# Sanity check: verify injection is present in new content
if embedded_json[:80] not in new_content:
    fatal('Post-injection sanity check failed — serialised payload not found in new content')

info(f'EMBEDDED_INTEL replacement located at char {match.start():,}')
info(f'Replacement size: {len(replacement):,} chars (was {match.end()-match.start():,})')

# ── STEP 6: Atomic write (tmp → fsync → rename) ──────────────────────────────
index_dir = os.path.dirname(os.path.abspath(INDEX_PATH)) or '.'
try:
    fd, tmp_path = tempfile.mkstemp(
        dir=index_dir,
        prefix='.inject_embedded_intel_',
        suffix='.tmp'
    )
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as tmp_f:
            tmp_f.write(new_content)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        shutil.move(tmp_path, INDEX_PATH)
    except Exception:
        # Clean up tmp on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
except Exception as e:
    fatal(f'Atomic write failed: {e}\n{traceback.format_exc()}')

# ── STEP 7: Post-write verification ─────────────────────────────────────────
try:
    with open(INDEX_PATH, 'r', encoding='utf-8', errors='replace') as f:
        verify_content = f.read()
    if embedded_json[:80] in verify_content:
        info(f'Post-write verify PASSED — EMBEDDED_INTEL confirmed in {INDEX_PATH}')
    else:
        warn(f'Post-write verify WARNING — EMBEDDED_INTEL payload not found after write')
except Exception as e:
    warn(f'Post-write verify read failed: {e}')

# ── FINAL SUMMARY ────────────────────────────────────────────────────────────
print()
print(f'=== INJECT COMPLETE ===')
print(f'  Items injected : {len(top_items)}')
print(f'  Payload size   : {len(embedded_json):,} bytes')
print(f'  Target         : {os.path.abspath(INDEX_PATH)}')
print(f'  bootFromEmbeddedCache() will render {len(top_items)} cards instantly on page load')
print()

sys.exit(0)
