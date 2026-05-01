#!/usr/bin/env python3
"""
SENTINEL APEX v145.0 — DASHBOARD FRONTEND ARCHITECTURE GUARD
=============================================================
STAGE 3.92 — HARD FAIL GATE

Validates that index.html frontend has NOT been contaminated by:
  1. EMBEDDED_INTEL populated with data (must be [])
  2. MANIFEST_URLS containing feed.json / api/feed.json / RAW_MANIFEST
  3. data.items fallback in the parse chain (dead code that masks errors)

Architecture invariant (v145.0):
  Dashboard MUST read ONLY from Worker API (data.preview.items)
  Any deviation = production regression = HARD FAIL

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

print('=== DASHBOARD FRONTEND GUARD v145.0 ===')
print(f'Checking: {os.path.abspath(INDEX_PATH)}')
print()

if not os.path.exists(INDEX_PATH):
    print('[FATAL] index.html not found')
    sys.exit(1)

# Read file (binary to handle any encoding)
with open(INDEX_PATH, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

file_size = len(content)
print(f'File size: {file_size:,} chars')
print()

# ── CHECK 1: EMBEDDED_INTEL must be empty array ─────────────────────────────
print('CHECK 1: EMBEDDED_INTEL must be [] (API-only architecture)')
# Match: window.EMBEDDED_INTEL = []; or window.EMBEDDED_INTEL=[];
embedded_match = re.search(r'window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);', content, re.DOTALL)
if embedded_match:
    value = embedded_match.group(1).strip()
    # Check it's truly empty: [] or [ ] or [\n]
    stripped = value.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
    if stripped == '[]':
        ok('EMBEDDED_INTEL = [] (empty — API-only architecture correct)')
    else:
        # Has content — how much?
        item_count = value.count('{')
        fail(f'EMBEDDED_INTEL contains data (~{item_count} items) — VIOLATES v145.0 API-only architecture!')
        fail('  Fix: run scripts/update_embedded_intel.py to reset to []')
else:
    warn('EMBEDDED_INTEL declaration not found in first 500KB — file may be structured differently')

print()

# ── CHECK 2: MANIFEST_URLS must be API-only (no feed.json, no RAW_MANIFEST) ─
print('CHECK 2: MANIFEST_URLS must contain ONLY WORKER_PREVIEW_URL')
manifest_block_match = re.search(
    r'var MANIFEST_URLS\s*=\s*\[(.*?)\];',
    content,
    re.DOTALL
)
if manifest_block_match:
    block = manifest_block_match.group(1)
    # Check for banned sources (non-comment lines)
    lines = [l.strip() for l in block.split('\n') if l.strip() and not l.strip().startswith('//')]
    banned_found = []
    for line in lines:
        if 'feed.json' in line or 'RAW_MANIFEST' in line:
            # Make sure it's an actual array entry, not a comment
            if not line.startswith('//') and not line.startswith('#'):
                banned_found.append(line[:80])

    if banned_found:
        for b in banned_found:
            fail(f'MANIFEST_URLS contains banned source: {b}')
        fail('  Fix: Remove feed.json/api/feed.json/RAW_MANIFEST from MANIFEST_URLS')
        fail('  Dashboard must use ONLY WORKER_PREVIEW_URL')
    else:
        # Confirm WORKER_PREVIEW_URL is present
        if 'WORKER_PREVIEW_URL' in block:
            ok('MANIFEST_URLS = [WORKER_PREVIEW_URL] only — API-only architecture correct')
        else:
            warn('MANIFEST_URLS has no WORKER_PREVIEW_URL — dashboard may have no data source')
else:
    warn('MANIFEST_URLS block not found — skipping check')

print()

# ── CHECK 3: data.items dead fallback must not be in parse chain ────────────
print('CHECK 3: Parse chain must not contain data.items dead fallback')
# Look for the pattern: data.items in a chain like || data.items ||
dead_fallback_pattern = re.search(
    r'\|\|\s*data\.items\s*\|\|',
    content
)
if dead_fallback_pattern:
    # Find surrounding context
    pos = dead_fallback_pattern.start()
    ctx = content[max(0, pos-80):pos+80].replace('\n', ' ')
    fail(f'data.items dead fallback found in parse chain: ...{ctx}...')
    fail('  Fix: Remove || data.items from MANIFEST_URLS parse chain')
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

# ── RESULT ───────────────────────────────────────────────────────────────────
print('=' * 60)
print(f'CHECKS: {5} total | ERRORS: {len(ERRORS)} | WARNINGS: {len(WARNINGS)}')
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
    print('[DASHBOARD FRONTEND GUARD] PASSED — frontend architecture invariants hold')
    if WARNINGS:
        print('Warnings (non-blocking):')
        for w in WARNINGS:
            print(f'  ! {w}')
    sys.exit(0)
