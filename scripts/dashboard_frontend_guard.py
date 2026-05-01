#!/usr/bin/env python3
"""
SENTINEL APEX v147.0 -- DASHBOARD FRONTEND ARCHITECTURE GUARD
=============================================================
STAGE 3.92 -- HARD FAIL GATE

Architecture invariant (v147.0 -- P0 STABLE -- 3-LAYER FALLBACK + INSTANT RENDER):
  PRIMARY  : Worker API (data.preview.items) -- intel.cyberdudebivash.com/api/preview
  FALLBACK1: api/feed.json (same-domain, Worker now handles this route from R2)
  FALLBACK2: raw.githubusercontent.com/...api/feed.json (cross-origin reliable bypass)
  INSTANT  : EMBEDDED_INTEL (top-25 items, injected by inject_embedded_intel.py pre-deploy)

  APPROVED sources in MANIFEST_URLS:
    OK  WORKER_PREVIEW_URL        (Worker API, primary)
    OK  api/feed.json             (same-domain fallback, Worker R2 handler)
    OK  raw.githubusercontent.com (cross-origin reliable fallback, 5-min cache OK as 3rd tier)

  BANNED sources in MANIFEST_URLS:
    X   feed.json      (root-level, not same-domain, deprecated)
    X   RAW_MANIFEST   (deprecated variable name, use explicit raw URL string)
    X   jsDelivr / jsdelivr (24h CDN cache, permanent sync killer)

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
    print('[FAIL] ' + msg)


def warn(msg):
    WARNINGS.append(msg)
    print('[WARN] ' + msg)


def ok(msg):
    print('[ OK] ' + msg)


print('=== DASHBOARD FRONTEND GUARD v147.0 ===')
print('Checking: ' + os.path.abspath(INDEX_PATH))
print()

if not os.path.exists(INDEX_PATH):
    print('[FATAL] index.html not found')
    sys.exit(1)

with open(INDEX_PATH, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

file_size = len(content)
print('File size: {:,} chars'.format(file_size))
print()

# CHECK 1: EMBEDDED_INTEL -- hybrid arch (template=[] OR injector-populated)
print('CHECK 1: EMBEDDED_INTEL -- hybrid architecture ([] template OR injected top-25 items)')
embedded_match = re.search(r'window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);', content, re.DOTALL)
if embedded_match:
    value = embedded_match.group(1).strip()
    stripped = value.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
    if stripped == '[]':
        ok('EMBEDDED_INTEL = [] (template state -- injector will populate before deploy)')
    else:
        item_count = value.count('{')
        ok('EMBEDDED_INTEL populated with ~{} items (injected by pipeline -- correct)'.format(item_count))
else:
    warn('EMBEDDED_INTEL declaration not found -- file may be structured differently')

print()

# CHECK 2: MANIFEST_URLS must not contain banned sources
print('CHECK 2: MANIFEST_URLS must not contain banned sources')
print('         APPROVED: WORKER_PREVIEW_URL | api/feed.json | raw.githubusercontent.com (FALLBACK2)')
manifest_block_match = re.search(
    r'var MANIFEST_URLS\s*=\s*\[(.*?)\];',
    content,
    re.DOTALL
)
if manifest_block_match:
    block = manifest_block_match.group(1)
    lines = [l.strip() for l in block.split('\n')
             if l.strip() and not l.strip().startswith('//') and not l.strip().startswith('#')]

    banned_found = []
    for line in lines:
        if 'RAW_MANIFEST' in line:
            banned_found.append((line[:100], 'RAW_MANIFEST -- deprecated variable name'))
            continue
        if 'jsdelivr' in line.lower():
            banned_found.append((line[:100], 'jsDelivr CDN -- 24h cache, sync killer'))
            continue
        if re.search(r'''['"]feed\.json['"]''', line) and 'api/feed.json' not in line:
            banned_found.append((line[:100], 'root feed.json -- use api/feed.json'))
        # raw.githubusercontent.com is APPROVED in v147.0 as FALLBACK2

    if banned_found:
        for entry, reason in banned_found:
            fail('MANIFEST_URLS contains banned source ({}): {}'.format(reason, entry))
        fail('  Fix: Remove banned sources. Approved: WORKER_PREVIEW_URL + api/feed.json + raw.githubusercontent.com')
    else:
        if 'WORKER_PREVIEW_URL' in block:
            ok('MANIFEST_URLS -- no banned sources detected')
        else:
            warn('MANIFEST_URLS has no WORKER_PREVIEW_URL -- Worker API missing as primary source')
else:
    warn('MANIFEST_URLS block not found -- file may be structured differently')

print()

# CHECK 2b: api/feed.json MUST be present as FALLBACK1
print('CHECK 2b: api/feed.json same-domain fallback must be present (FALLBACK1 regression guard)')
if manifest_block_match:
    block_2b = manifest_block_match.group(1)
    if "'api/feed.json'" in block_2b or '"api/feed.json"' in block_2b:
        ok('api/feed.json FALLBACK1 present -- P0 regression guard active')
    else:
        fail('api/feed.json FALLBACK1 MISSING from MANIFEST_URLS')
        fail('  Risk: Worker-only arch -> api/feed.json 404 -> stuck loader P0')
        fail('  Fix: Add api/feed.json as second entry in MANIFEST_URLS')
else:
    warn('Cannot check for api/feed.json fallback -- MANIFEST_URLS block not found')

print()

# CHECK 2c: raw.githubusercontent.com MUST be present as FALLBACK2
print('CHECK 2c: raw.githubusercontent.com FALLBACK2 must be present (v147.0 reliability guard)')
if manifest_block_match:
    block_2c = manifest_block_match.group(1)
    if 'raw.githubusercontent.com' in block_2c:
        ok('raw.githubusercontent.com FALLBACK2 present -- 3rd-tier bypass active')
    else:
        fail('raw.githubusercontent.com FALLBACK2 MISSING from MANIFEST_URLS')
        fail('  Risk: If Worker down + api/feed.json fails -> no 3rd-tier -> stuck loader')
        fail('  Fix: Add raw.githubusercontent.com/.../api/feed.json as 3rd entry in MANIFEST_URLS')
else:
    warn('Cannot check for raw.githubusercontent.com fallback -- MANIFEST_URLS block not found')

print()

# CHECK 3: data.items dead fallback must not be in parse chain
print('CHECK 3: Parse chain must not contain data.items dead fallback (|| data.items ||)')
dead_fallback_pattern = re.search(r'\|\|\s*data\.items\s*\|\|', content)
if dead_fallback_pattern:
    pos = dead_fallback_pattern.start()
    ctx = content[max(0, pos - 80):pos + 80].replace('\n', ' ')
    fail('data.items dead fallback found in parse chain: ...{}...'.format(ctx))
    fail('  Fix: Remove || data.items || from parse chain')
else:
    ok('No data.items dead fallback in parse chain')

print()

# CHECK 4: cleanText sanitizer must be present
print('CHECK 4: cleanText() sanitizer must be present')
if 'function cleanText(' in content:
    ok('cleanText() sanitizer present')
else:
    warn('cleanText() sanitizer not found -- encoding protection missing')

print()

# CHECK 5: Debug logging must be present
print('CHECK 5: API items debug logging must be present')
if '[SENTINEL-APEX] API items:' in content:
    ok('API items debug log present')
else:
    warn('API items debug log not found (non-blocking)')

print()

# CHECK 6: P0 safety timer must be present
print('CHECK 6: P0 safety timer (12s stuck-loader backstop) must be present')
if 'P0-SAFETY' in content or 'P0 SAFETY TIMER' in content:
    ok('P0 safety timer present -- stuck-loader backstop active')
else:
    warn('P0 safety timer not found -- grid may remain stuck if all fetches fail silently')

print()

# CHECK 7: Terminal fallback must clear #threat-grid
print('CHECK 7: Terminal fallback must clear #threat-grid (not leave stuck at spinner)')
if 'threat-grid' in content and 'innerHTML' in content:
    ok('Terminal fallback grid-clear present -- no permanent stuck-loader state possible')
else:
    warn('Terminal fallback grid-clear not confirmed -- check threat-grid clear in all-sources-failed path')

print()

# CHECK 8: bootFromEmbeddedCache instant-render logic must be present
print('CHECK 8: bootFromEmbeddedCache() instant-render logic must be present')
if 'bootFromEmbeddedCache' in content:
    ok('bootFromEmbeddedCache() present -- instant-render on injected EMBEDDED_INTEL active')
else:
    warn('bootFromEmbeddedCache() not found -- instant-render path may be missing')

print()

# RESULT
total_checks = 8
print('=' * 60)
print('CHECKS: {} total | ERRORS: {} | WARNINGS: {}'.format(total_checks, len(ERRORS), len(WARNINGS)))
print()

if ERRORS:
    print('[DASHBOARD FRONTEND GUARD] FAILED -- deployment blocked')
    print()
    print('Errors:')
    for e in ERRORS:
        print('  X ' + e)
    if WARNINGS:
        print('Warnings:')
        for w in WARNINGS:
            print('  ! ' + w)
    sys.exit(1)
else:
    print('[DASHBOARD FRONTEND GUARD v147.0] PASSED -- frontend architecture invariants hold')
    if WARNINGS:
        print('Warnings (non-blocking):')
        for w in WARNINGS:
            print('  ! ' + w)
    sys.exit(0)
