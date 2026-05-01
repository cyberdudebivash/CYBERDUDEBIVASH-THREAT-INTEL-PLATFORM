#!/usr/bin/env python3
"""
SENTINEL APEX v146.0 — DASHBOARD FRONTEND ARCHITECTURE GUARD
=============================================================
STAGE 3.92 — HARD FAIL GATE

Validates that index.html frontend has NOT been contaminated by:
  1. EMBEDDED_INTEL populated with data (must be [])
  2. MANIFEST_URLS containing BANNED sources (root feed.json / RAW_MANIFEST /
     raw.githubusercontent.com / jsDelivr CDN)
  3. data.items dead fallback pattern (|| data.items ||) in parse chain

Architecture invariant (v146.0 — P0 STABLE):
  PRIMARY:  Worker API (data.preview.items) — intel.cyberdudebivash.com/api/preview
  FALLBACK: api/feed.json (same-domain, zero CORS risk, pipeline-updated each run)

  APPROVED sources in MANIFEST_URLS:
    ✔ WORKER_PREVIEW_URL   (intel.cyberdudebivash.com — Worker API)
    ✔ api/feed.json        (same-domain fallback — CORS-safe, always accessible)

  BANNED sources in MANIFEST_URLS:
    ✗ feed.json            (root-level — not same-domain, deprecated)
    ✗ RAW_MANIFEST         (raw.githubusercontent.com — 5-min cache, stale risk)
    ✗ raw.githubusercontent.com (cross-origin, cached, bypasses Worker)
    ✗ jsDelivr / jsdelivr  (24h CDN cache — permanent sync killer)

v146.0 CHANGE LOG:
  - api/feed.json added to APPROVED list (P0 fix — prevents stuck-loader on CORS fail)
  - CHECK 2b added: api/feed.json MUST be present (regression guard against API-only revert)
  - Root cause: v145.0 API-only arch caused CORS blocking → zero-card dashboard → P0 incident
  - CORS blocks Worker fetch in browser even when API responds correctly server-side

Exit 0 = PASS
Exit 1 = FAIL (blocks deployment)
"""

import sys
import re
import os

INDEX_PATH = 'index.html'
ERRORS = []
WARNINGS = []


def fail(msg):
    ERRORS.append(msg)
    print(f'[FAIL] {msg}')


def warn(msg):
    WARNINGS.append(msg)
    print(f'[WARN] {msg}')


def ok(msg):
    print(f'[ OK] {msg}')


print('=== DASHBOARD FRONTEND GUARD v146.0 ===')
print(f'Checking: {os.path.abspath(INDEX_PATH)}')
print()

if not os.path.exists(INDEX_PATH):
    print('[FATAL] index.html not found')
    sys.exit(1)

with open(INDEX_PATH, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

file_size = len(content)
print(f'File size: {file_size:,} chars')
print()

# ── CHECK 1: EMBEDDED_INTEL must be empty array ─────────────────────────────
print('CHECK 1: EMBEDDED_INTEL must be [] (API-only architecture)')
embedded_match = re.search(r'window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);', content, re.DOTALL)
if embedded_match:
    value = embedded_match.group(1).strip()
    stripped = value.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
    if stripped == '[]':
        ok('EMBEDDED_INTEL = [] (empty — API-only architecture correct)')
    else:
        item_count = value.count('{')
        fail(f'EMBEDDED_INTEL contains data (~{item_count} items) — VIOLATES API-only architecture!')
        fail('  Fix: reset to window.EMBEDDED_INTEL = [];')
else:
    warn('EMBEDDED_INTEL declaration not found — file may be structured differently')

print()

# ── CHECK 2: MANIFEST_URLS must not contain banned cross-origin sources ──────
# v146.0: api/feed.json is APPROVED (same-domain, CORS-safe fallback)
# BANNED: root feed.json | RAW_MANIFEST | raw.githubusercontent.com | jsDelivr
print('CHECK 2: MANIFEST_URLS must not contain banned cross-origin sources')
print('         (api/feed.json is APPROVED as same-domain CORS-safe fallback)')
manifest_block_match = re.search(
    r'var MANIFEST_URLS\s*=\s*\[(.*?)\];',
    content,
    re.DOTALL
)
if manifest_block_match:
    block = manifest_block_match.group(1)
    # Extract non-comment, non-empty lines (actual array entries)
    lines = [l.strip() for l in block.split('\n')
             if l.strip() and not l.strip().startswith('//') and not l.strip().startswith('#')]

    banned_found = []
    for line in lines:
        # ── BANNED patterns (v146.0) ──────────────────────────────────────────
        # RAW_MANIFEST: variable name for raw.githubusercontent paths
        if 'RAW_MANIFEST' in line:
            banned_found.append((line[:100], 'RAW_MANIFEST — cross-origin, cached, deprecated'))
            continue
        # raw.githubusercontent.com — cross-origin, 5-min cache, unreliable
        if 'raw.githubusercontent.com' in line:
            banned_found.append((line[:100], 'raw.githubusercontent.com — cross-origin, cache risk'))
            continue
        # jsDelivr / jsdelivr — 24h CDN cache = permanent sync killer
        if 'jsdelivr' in line.lower():
            banned_found.append((line[:100], 'jsDelivr CDN — 24h cache, sync killer'))
            continue
        # Root-level feed.json — NOT api/feed.json (which is approved same-domain)
        # Pattern: matches 'feed.json' or "feed.json" that is NOT prefixed with api/
        if re.search(r"""['"]feed\.json['"]""", line) and 'api/feed.json' not in line:
            banned_found.append((line[:100], 'root feed.json — not same-domain, use api/feed.json'))

    if banned_found:
        for entry, reason in banned_found:
            fail(f'MANIFEST_URLS contains banned source ({reason}): {entry}')
        fail('  Fix: Remove banned sources. Approved: WORKER_PREVIEW_URL + api/feed.json only')
    else:
        if 'WORKER_PREVIEW_URL' in block:
            ok('MANIFEST_URLS — no banned cross-origin sources detected')
        else:
            warn('MANIFEST_URLS has no WORKER_PREVIEW_URL — Worker API missing as primary source')

print()

# ── CHECK 2b: api/feed.json MUST be present as fallback ──────────────────────
# Regression guard: prevents silent revert to CORS-broken API-only arch (v145.0 P0 root cause)
print('CHECK 2b: api/feed.json same-domain fallback must be present (P0 regression guard)')
if manifest_block_match:
    block_2b = manifest_block_match.group(1)
    if "'api/feed.json'" in block_2b or '"api/feed.json"' in block_2b:
        ok('api/feed.json fallback present — CORS-safe, P0 regression guard active')
    else:
        fail('api/feed.json fallback MISSING from MANIFEST_URLS')
        fail('  Risk: Worker-only arch fails silently in browser due to CORS → stuck loader P0')
        fail('  Fix: Add api/feed.json as second entry in MANIFEST_URLS')
else:
    warn('Cannot check for api/feed.json fallback — MANIFEST_URLS block not found')

print()

# ── CHECK 3: data.items dead fallback must not be in parse chain ────────────
print('CHECK 3: Parse chain must not contain data.items dead fallback (|| data.items ||)')
dead_fallback_pattern = re.search(r'\|\|\s*data\.items\s*\|\|', content)
if dead_fallback_pattern:
    pos = dead_fallback_pattern.start()
    ctx = content[max(0, pos - 80):pos + 80].replace('\n', ' ')
    fail(f'data.items dead fallback found in parse chain: ...{ctx}...')
    fail('  Fix: Remove || data.items || from parse chain')
else:
    ok('No data.items dead fallback in parse chain')

print()

# ── CHECK 4: cleanText sanitizer must be present ────────────────────────────
print('CHECK 4: cleanText() sanitizer must be present')
if 'function cleanText(' in content:
    ok('cleanText() sanitizer present')
else:
    warn('cleanText() sanitizer not found — encoding protection missing')

print()

# ── CHECK 5: Debug logging must be present ──────────────────────────────────
print('CHECK 5: API items debug logging must be present')
if '[SENTINEL-APEX] API items:' in content:
    ok('API items debug log present')
else:
    warn('API items debug log not found (non-blocking)')

print()

# ── CHECK 6: P0 safety timer must be present ────────────────────────────────
print('CHECK 6: P0 safety timer (12s stuck-loader backstop) must be present')
if 'P0-SAFETY' in content or 'P0 SAFETY TIMER' in content:
    ok('P0 safety timer present — stuck-loader backstop active')
else:
    warn('P0 safety timer not found — grid may remain stuck if all fetches fail silently')

print()

# ── CHECK 7: Terminal fallback must clear #threat-grid ──────────────────────
print('CHECK 7: Terminal fallback must clear #threat-grid (not leave stuck at spinner)')
if 'v146.0 P0 FIX: #threat-grid MUST never stay stuck' in content:
    ok('Terminal fallback grid-clear present — no permanent stuck-loader state possible')
else:
    warn('Terminal fallback grid-clear not confirmed — check threat-grid clear in all-sources-failed path')

print()

# ── RESULT ───────────────────────────────────────────────────────────────────
total_checks = 7
print('=' * 60)
print(f'CHECKS: {total_checks} total | ERRORS: {len(ERRORS)} | WARNINGS: {len(WARNINGS)}')
print()

if ERRORS:
    print('[DASHBOARD FRONTEND GUARD] FAILED — deployment blocked')
    print()
    print('Errors:')
    for e in ERRORS:
        print(f'  ✗ {e}')
    if WARNINGS:
        print('Warnings:')
        for w in WARNINGS:
            print(f'  ! {w}')
    sys.exit(1)
else:
    print('[DASHBOARD FRONTEND GUARD v146.0] PASSED — frontend architecture invariants hold')
    if WARNINGS:
        print('Warnings (non-blocking):')
        for w in WARNINGS:
            print(f'  ! {w}')
    sys.exit(0)
