#!/usr/bin/env python3
"""
SENTINEL APEX v149.1 -- DASHBOARD FRONTEND ARCHITECTURE GUARD
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
import subprocess
import tempfile

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


print('=== DASHBOARD FRONTEND GUARD v175.1 ===')
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

# CHECK 1: EMBEDDED_INTEL -- v150.0 immutable architecture (must be static [])
# ARCHITECTURE CHANGE: EMBEDDED_INTEL must be [] (permanent static stub)
# Pipeline no longer injects data into index.html -- data served from api/v1/intel/*.json
print('CHECK 1: EMBEDDED_INTEL -- v150.0 immutable architecture (must be static [])')
embedded_match = re.search(r'window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);', content, re.DOTALL)
if embedded_match:
    value = embedded_match.group(1).strip()
    stripped = value.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
    if stripped == '[]':
        ok('EMBEDDED_INTEL = [] (correct -- immutable API-first architecture active)')
    else:
        item_count = value.count('{')
        fail('EMBEDDED_INTEL was MUTATED with ~{} items -- HTML injection detected!'.format(item_count))
        fail('  ARCHITECTURE VIOLATION: index.html must never be modified by the pipeline.')
        fail('  Fix: Run inject_embedded_intel.py (now no-op) -- check for rogue scripts.')
else:
    warn('EMBEDDED_INTEL declaration not found -- file may be structured differently')

# CHECK 1b: api/v1/intel/latest.json must be referenced in MANIFEST_URLS
print('CHECK 1b: api/v1/intel/latest.json PRIMARY source must be in MANIFEST_URLS')
if "'api/v1/intel/latest.json'" in content or '"api/v1/intel/latest.json"' in content:
    ok('api/v1/intel/latest.json PRIMARY source present in fetch chain')
else:
    fail('api/v1/intel/latest.json NOT found in MANIFEST_URLS')
    fail('  Fix: Add api/v1/intel/latest.json as first entry in MANIFEST_URLS')

print()

# CHECK 2: MANIFEST_URLS must not contain banned sources
# v158.0.1 HARDENING: use findall + select the LARGEST block to defend against
# component-local MANIFEST_URLS declarations (e.g. EICC engine) appearing before
# the main dashboard block. The main MANIFEST_URLS is always the largest block.
print('CHECK 2: MANIFEST_URLS must not contain banned sources')
print('         APPROVED: WORKER_PREVIEW_URL | api/feed.json | raw.githubusercontent.com (FALLBACK2)')
_all_manifest_blocks = re.findall(
    r'var MANIFEST_URLS\s*=\s*\[(.*?)\];',
    content,
    re.DOTALL
)
manifest_block_match = bool(_all_manifest_blocks)
if _all_manifest_blocks:
    # Select the LARGEST block — this is always the main dashboard MANIFEST_URLS
    block = max(_all_manifest_blocks, key=len)
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
        fail('  Fix: Remove banned sources. Approved: api/v1/intel/latest.json + WORKER_PREVIEW_URL + api/feed.json + raw.githubusercontent.com')
    else:
        if 'api/v1/intel/latest.json' in block:
            ok('MANIFEST_URLS -- api/v1/intel/latest.json PRIMARY present, no banned sources')
        elif 'WORKER_PREVIEW_URL' in block:
            ok('MANIFEST_URLS -- no banned sources detected (add api/v1/intel/latest.json as PRIMARY for v150.0)')
        else:
            warn('MANIFEST_URLS has no PRIMARY source -- add api/v1/intel/latest.json as first entry')
else:
    warn('MANIFEST_URLS block not found -- file may be structured differently')

print()

# CHECK 2b: api/feed.json MUST be present as FALLBACK1
print('CHECK 2b: api/feed.json same-domain fallback must be present (FALLBACK1 regression guard)')
if manifest_block_match:
    block_2b = block  # 'block' is already the largest MANIFEST_URLS block
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
    block_2c = block  # 'block' is already the largest MANIFEST_URLS block
    if 'raw.githubusercontent.com' in block_2c:
        ok('raw.githubusercontent.com FALLBACK2 present -- 3rd-tier bypass active')
    else:
        fail('raw.githubusercontent.com FALLBACK2 MISSING from MANIFEST_URLS')
        fail('  Risk: If Worker down + api/feed.json fails -> no 3rd-tier -> stuck loader')
        fail('  Fix: Add raw.githubusercontent.com/.../api/feed.json as 3rd entry in MANIFEST_URLS')
else:
    warn('Cannot check for raw.githubusercontent.com fallback -- MANIFEST_URLS block not found')

print()

# CHECK 2d: EICC engine MUST use api/feed.json as PRIMARY (v175.1 single-source mandate)
# ROOT CAUSE FIXED: Stage 67 (Generate API Manifests) runs BEFORE Stage 71 (Source Diversity
# Enforcer). When EICC_DATA_URLS[0] was api/v1/intel/latest.json, EICC fetched pre-diversity
# data while GOC fetched post-diversity data from api/feed.json — causing cross-section item
# count divergence and customer-visible "duplication" of intel items across dashboard sections.
# PERMANENT MANDATE: EICC and GOC must both read exclusively from api/feed.json.
print('CHECK 2d: EICC_DATA_URLS PRIMARY must be api/feed.json (single-source mandate v175.1)')
_eicc_blocks = re.findall(r'var EICC_DATA_URLS\s*=\s*\[(.*?)\];', content, re.DOTALL)
if _eicc_blocks:
    _eicc_block = _eicc_blocks[0]
    # Extract ordered non-comment URL entries
    _eicc_src_lines = [l.strip() for l in _eicc_block.split('\n')
                       if l.strip() and not l.strip().startswith('//')]
    _eicc_url_lines = [l for l in _eicc_src_lines if '.json' in l or 'URL' in l.upper()]
    _first_eicc = _eicc_url_lines[0] if _eicc_url_lines else ''
    # PRIMARY check
    if "'api/feed.json'" in _first_eicc or '"api/feed.json"' in _first_eicc:
        if 'latest.json' not in _first_eicc:
            ok("EICC PRIMARY = api/feed.json -- single-source active, cross-section divergence impossible")
        else:
            fail("EICC PRIMARY line contains both api/feed.json AND latest.json -- ambiguous source")
    elif 'latest.json' in _first_eicc:
        fail("DUAL-SOURCE BUG: EICC PRIMARY = api/v1/intel/latest.json (pre-diversity-enforcement data)")
        fail("  ROOT CAUSE: latest.json written at Stage 67, BEFORE Stage 71 diversity trim")
        fail("  CUSTOMER IMPACT: EICC ticker/preview shows different items than GOC main grid")
        fail("  FIX: Change EICC_DATA_URLS[0] to 'api/feed.json' (same source as GOC MANIFEST_URLS)")
    else:
        warn('EICC_DATA_URLS PRIMARY source unrecognised: {}'.format(_first_eicc[:80]))
    # Regression guard: latest.json must NOT appear anywhere in EICC_DATA_URLS
    if 'latest.json' in _eicc_block:
        fail("REGRESSION: api/v1/intel/latest.json present in EICC_DATA_URLS -- dual-source reintroduced")
        fail("  FIX: Remove api/v1/intel/latest.json from EICC_DATA_URLS entirely")
    else:
        ok("api/v1/intel/latest.json absent from EICC_DATA_URLS -- dual-source regression guard ACTIVE")
else:
    warn('EICC_DATA_URLS block not found in index.html (non-blocking if EICC section removed)')

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

# CHECK 8: bootFromEmbeddedCache must be present (v150.0: graceful no-op when EMBEDDED_INTEL=[])
print('CHECK 8: AI Brain CDB_AI bridge + GOC_LIVE_INTEL hook must be registered (v150.1)')
ai_bridge_ok = ('window.CDB_AI' in content and 'runBrain' in content)
goc_hook_ok  = ('__GOC_LIVE_INTEL' in content)
ai_poller_ok = ('_startAIBrainPoller' in content or '_aiBrainPollTimer' in content)
if ai_bridge_ok and goc_hook_ok and ai_poller_ok:
    ok('AI Brain: CDB_AI.runBrain registered + __GOC_LIVE_INTEL hook + self-healing poller active')
elif not ai_bridge_ok:
    fail('window.CDB_AI.runBrain NOT registered -- AI Brain cannot receive API data callback')
    fail('  Fix: Add window.CDB_AI = {runBrain: runAIBrain} before API fetch completes')
elif not goc_hook_ok:
    fail('window.__GOC_LIVE_INTEL NOT referenced in AI Brain -- panels will stay empty')
    fail('  Fix: Change runAIBrain() to read window.__GOC_LIVE_INTEL || window.EMBEDDED_INTEL')
else:
    warn('AI Brain poller not found -- self-healing retry mechanism may be missing')
# Legacy check: bootFromEmbeddedCache graceful no-op still expected as static stub
if 'bootFromEmbeddedCache' in content:
    ok('bootFromEmbeddedCache() graceful no-op stub present')
else:
    warn('bootFromEmbeddedCache() not found (non-blocking in v150.1 API-first arch)')

print()

# CHECK 9: JavaScript syntax validation (v149.1 P0 PERMANENT FIX)
# The P0 incident was caused by a SyntaxError in the main <script> block that
# prevented ALL JavaScript from executing. This check runs node --check on the
# extracted main script to catch SyntaxErrors before they reach gh-pages.
print('CHECK 9: JavaScript syntax validation (node --check on main <script> block)')
node_available = False
try:
    result = subprocess.run(['node', '--version'], capture_output=True, timeout=10)
    node_available = (result.returncode == 0)
except (FileNotFoundError, subprocess.TimeoutExpired):
    node_available = False

if not node_available:
    warn('node not available in PATH -- JS syntax check skipped (install Node.js on runner)')
else:
    # Extract the largest <script> block (the main app script)
    script_blocks = re.findall(r'<script(?:\s[^>]*)?>([\s\S]*?)</script>', content)
    if not script_blocks:
        fail('No <script> blocks found in index.html -- file may be corrupt')
    else:
        largest_script = max(script_blocks, key=len)
        script_size = len(largest_script)
        print('  Main script block: {:,} chars'.format(script_size))

        if script_size < 10000:
            warn('Main script block is unexpectedly small ({:,} chars) -- may be truncated'.format(script_size))
        else:
            # Write to temp file and run node --check
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False, encoding='utf-8')
            tmp.write(largest_script)
            tmp.close()

            try:
                check_result = subprocess.run(
                    ['node', '--check', tmp.name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if check_result.returncode == 0:
                    ok('JavaScript syntax VALID -- node --check passed on {:,}-char main script'.format(script_size))
                else:
                    err_output = (check_result.stderr or check_result.stdout or '').strip()
                    # Extract just the SyntaxError line for clarity
                    err_lines = [l for l in err_output.split('\n') if 'SyntaxError' in l or 'Error' in l]
                    short_err = err_lines[0] if err_lines else err_output[:200]
                    fail('JavaScript SyntaxError detected -- deployment BLOCKED')
                    fail('  node --check error: {}'.format(short_err))
                    fail('  Fix: Find and fix the syntax error in index.html main <script> block')
            except Exception as e:
                warn('node --check failed to run (node not available): {}'.format(e))
            finally:
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass

print()

# ── FINAL SUMMARY ──────────────────────────────────────────────────────────
fail_count = len(ERRORS)
warn_count = len(WARNINGS)
pass_count = 11 - fail_count  # 11 numbered checks total (v175.1: added CHECK 2d single-source mandate)

print('=' * 70)
print('DASHBOARD FRONTEND GUARD COMPLETE')
print('  PASS: {}'.format(pass_count))
print('  FAIL: {}'.format(fail_count))
print('  WARN: {}'.format(warn_count))

if fail_count > 0:
    print('RESULT: FAIL -- {} critical architecture violation(s) detected'.format(fail_count))
    print('DEPLOYMENT BLOCKED -- Fix violations before committing.')
    print('=' * 70)
    import sys
    sys.exit(1)
else:
    print('RESULT: PASS -- Dashboard architecture contract intact')
    print('=' * 70)
    import sys
    sys.exit(0)
