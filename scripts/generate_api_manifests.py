#!/usr/bin/env python3
"""
SENTINEL APEX v160.0 — IMMUTABLE API MANIFEST GENERATOR
=========================================================
STAGE 3.93 (REPLACEMENT) — IMMUTABLE API BUNDLE GENERATION

ARCHITECTURE (v160.0 — IMMUTABLE API-FIRST):
  OLD (BROKEN): inject_embedded_intel.py mutated index.html at deploy time
  NEW (STABLE): generate_api_manifests.py generates versioned JSON bundles
                Frontend fetches from /api/v1/intel/*.json at runtime
                Zero HTML mutation — index.html is forever read-only

Outputs (all written atomically — tmp → fsync → rename):
  api/v1/intel/latest.json   — All items sorted by freshness (versioned + signed)
  api/v1/intel/top10.json    — Top 10 items by risk score + freshness
  api/v1/intel/apex.json     — Items with apex_ai enrichment data
  api/v1/intel/manifest.json — Registry: checksums, counts, timestamps, version

Why this is enterprise-grade:
  - index.html is NEVER modified by the pipeline
  - All data lives in versioned, immutable JSON files
  - Checksums allow clients to detect stale data
  - Frontend gracefully degrades: latest → apex → feed.json → raw
  - No EMBEDDED_INTEL, no HTML mutation, no deployment-time DOM rewriting

Exit 0 = SUCCESS
Exit 1 = FATAL (missing source data)
"""

import sys
import os
import json
import re
import hashlib
import datetime
import tempfile
import shutil
import traceback

# ── CONFIG ──────────────────────────────────────────────────────────────────
FEED_PATH    = 'api/feed.json'
OUT_DIR      = 'api/v1/intel'
SCRIPT_NAME  = 'generate_api_manifests.py'
VERSION      = 'v160.0'
TOP10_COUNT  = 10
SCHEMA_VER   = '1.0'

# ── HELPERS ─────────────────────────────────────────────────────────────────
def fatal(msg):
    print(f'[FATAL] {SCRIPT_NAME}: {msg}', flush=True)
    sys.exit(1)

def info(msg):
    print(f'[ OK ] {msg}', flush=True)

def warn(msg):
    print(f'[WARN] {msg}', flush=True)

def sha256_of(data_str: str) -> str:
    return hashlib.sha256(data_str.encode('utf-8')).hexdigest()

def atomic_write(path: str, data_str: str) -> None:
    """Write file atomically: tmp → fsync → rename. Never leaves partial state."""
    dir_ = os.path.dirname(os.path.abspath(path)) or '.'
    os.makedirs(dir_, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dir_, prefix='.genmanifest_', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(data_str)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

BRAND_NOISE = {
    "CYBERDUDEBIVASH(R) PRIVATE LIMITED",
    "OFFICIAL WORKPLACE",
    "GST & PAN VERIFIED",
}


def _title_hash(title: str) -> str:
    """Normalise title to a stable set-hash for dedup."""
    import re as _re
    t = (title or "").lower()
    t = _re.sub(r'\b(cve-\d{4}-\d{4,})\b', lambda m: m.group(0).upper(), t, flags=_re.I)
    t = _re.sub(r'[^a-z0-9A-Z]+', ' ', t).strip()
    return '|'.join(sorted(t.split()))


def _content_hash(item: dict) -> str:
    src   = (item.get('source') or item.get('feed_source') or '').lower()
    src   = ''.join(c for c in src if c.isalnum())
    title = _title_hash(item.get('title') or item.get('name') or '')
    cve   = (item.get('cve_id') or '').upper()
    return f'{src}::{title}::{cve}'


def deduplicate(items: list) -> list:
    """
    4-layer dedup matching the Cloudflare Worker's deduplicateFeedItems().
    L1: stix_id / id
    L2: normalised title hash
    L3: source+title content hash
    """
    seen_stix    = set()
    seen_title   = set()
    seen_content = set()
    result       = []
    dropped      = 0
    for item in items:
        t = (item.get('title') or item.get('name') or '').strip()
        if not t:
            continue
        if any(n in t for n in BRAND_NOISE):
            dropped += 1
            continue
        sid = item.get('stix_id') or item.get('id') or ''
        if sid and sid in seen_stix:
            dropped += 1
            continue
        if sid:
            seen_stix.add(sid)
        th = _title_hash(t)
        if th and th in seen_title:
            dropped += 1
            continue
        if th:
            seen_title.add(th)
        ch = _content_hash(item)
        if ch and ch in seen_content:
            dropped += 1
            continue
        seen_content.add(ch)
        result.append(item)
    if dropped:
        warn(f'Dedup: dropped {dropped} duplicate/noise items, {len(result)} unique remain')
    return result


def sort_key(item: dict) -> tuple:
    """Sort by processed_at > published_at > timestamp DESC, then risk_score DESC."""
    ts_str = (
        item.get('processed_at') or
        item.get('published_at') or
        item.get('timestamp') or
        item.get('generated_at') or
        ''
    )
    try:
        ts = datetime.datetime.fromisoformat(
            ts_str.replace('Z', '+00:00')
        ).timestamp() if ts_str else 0
    except (ValueError, AttributeError):
        ts = 0
    risk = item.get('risk_score') or item.get('cvss_score') or 0
    try:
        risk = float(risk)
    except (TypeError, ValueError):
        risk = 0.0
    return (ts, risk)

def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

# ── BANNER ──────────────────────────────────────────────────────────────────
print('=' * 68, flush=True)
print(f'SENTINEL APEX {VERSION} -- IMMUTABLE API MANIFEST GENERATOR', flush=True)
print(f'Timestamp : {now_iso()}', flush=True)
print(f'Source    : {os.path.abspath(FEED_PATH)}', flush=True)
print(f'Output    : {os.path.abspath(OUT_DIR)}/', flush=True)
print('=' * 68, flush=True)

# ── STEP 1: Load api/feed.json ───────────────────────────────────────────────
if not os.path.exists(FEED_PATH):
    fatal(f'{FEED_PATH} not found — pipeline must generate it before Stage 3.93')

try:
    with open(FEED_PATH, 'r', encoding='utf-8', errors='replace') as f:
        raw_feed = json.load(f)
except json.JSONDecodeError as e:
    fatal(f'{FEED_PATH} JSON parse error: {e}')

if not isinstance(raw_feed, list):
    fatal(f'{FEED_PATH} is not a JSON array (got {type(raw_feed).__name__})')

if len(raw_feed) == 0:
    fatal(f'{FEED_PATH} is empty — pipeline must produce intel before manifest generation')

info(f'Feed loaded: {len(raw_feed)} total items')

# ── STEP 1b: Deduplicate before manifests are generated ──────────────────────
# Mirrors the 3-layer dedup in the Cloudflare Worker's deduplicateFeedItems().
# Ensures duplicates are never baked into the immutable bundle files.
deduped_feed = deduplicate(raw_feed)
info(f'Dedup complete: {len(deduped_feed)} unique items ({len(raw_feed) - len(deduped_feed)} removed)')

# ── STEP 2: Sort by freshness ─────────────────────────────────────────────────
sorted_feed = sorted(deduped_feed, key=sort_key, reverse=True)
info(f'Sorted: {len(sorted_feed)} items by freshness DESC')

# ── STEP 3: Build /api/v1/intel/latest.json ──────────────────────────────────
timestamp_now = now_iso()
latest_payload = {
    'schema_version': SCHEMA_VER,
    'generated_at': timestamp_now,
    'generator': SCRIPT_NAME,
    'version': VERSION,
    'count': len(sorted_feed),
    'items': sorted_feed,
}
latest_str = json.dumps(latest_payload, ensure_ascii=False, separators=(',', ':'))
latest_sha  = sha256_of(latest_str)
latest_payload['sha256'] = latest_sha
latest_str  = json.dumps(latest_payload, ensure_ascii=False, separators=(',', ':'))

atomic_write(os.path.join(OUT_DIR, 'latest.json'), latest_str)
info(f'Written: {OUT_DIR}/latest.json ({len(sorted_feed)} items, {len(latest_str):,} bytes, sha256={latest_sha[:16]}...)')

# ── STEP 4: Build /api/v1/intel/top10.json ───────────────────────────────────
top10_items = sorted_feed[:TOP10_COUNT]
top10_payload = {
    'schema_version': SCHEMA_VER,
    'generated_at': timestamp_now,
    'generator': SCRIPT_NAME,
    'version': VERSION,
    'count': len(top10_items),
    'items': top10_items,
}
top10_str  = json.dumps(top10_payload, ensure_ascii=False, separators=(',', ':'))
top10_sha  = sha256_of(top10_str)
top10_payload['sha256'] = top10_sha
top10_str  = json.dumps(top10_payload, ensure_ascii=False, separators=(',', ':'))

atomic_write(os.path.join(OUT_DIR, 'top10.json'), top10_str)
info(f'Written: {OUT_DIR}/top10.json ({len(top10_items)} items, sha256={top10_sha[:16]}...)')

# ── STEP 5: Build /api/v1/intel/apex.json ────────────────────────────────────
# Items WITH apex_ai enrichment (or all if none have it — ensures non-empty file)
apex_items = [item for item in sorted_feed if item.get('apex_ai')]
if not apex_items:
    warn('No items have apex_ai enrichment — apex.json will contain all items as fallback')
    apex_items = sorted_feed

apex_payload = {
    'schema_version': SCHEMA_VER,
    'generated_at': timestamp_now,
    'generator': SCRIPT_NAME,
    'version': VERSION,
    'apex_enriched_count': len([i for i in sorted_feed if i.get('apex_ai')]),
    'count': len(apex_items),
    'items': apex_items,
}
apex_str  = json.dumps(apex_payload, ensure_ascii=False, separators=(',', ':'))
apex_sha  = sha256_of(apex_str)
apex_payload['sha256'] = apex_sha
apex_str  = json.dumps(apex_payload, ensure_ascii=False, separators=(',', ':'))

atomic_write(os.path.join(OUT_DIR, 'apex.json'), apex_str)
info(f'Written: {OUT_DIR}/apex.json ({len(apex_items)} items, sha256={apex_sha[:16]}...)')

# ── STEP 6: Build /api/v1/intel/manifest.json (registry) ─────────────────────
manifest_registry = {
    'schema_version': SCHEMA_VER,
    'generated_at': timestamp_now,
    'generator': SCRIPT_NAME,
    'version': VERSION,
    'architecture': 'immutable-api-first-v150.0',
    'bundles': {
        'latest': {
            'path': 'api/v1/intel/latest.json',
            'count': len(sorted_feed),
            'sha256': latest_sha,
            'generated_at': timestamp_now,
        },
        'top10': {
            'path': 'api/v1/intel/top10.json',
            'count': len(top10_items),
            'sha256': top10_sha,
            'generated_at': timestamp_now,
        },
        'apex': {
            'path': 'api/v1/intel/apex.json',
            'count': len(apex_items),
            'apex_enriched': len([i for i in sorted_feed if i.get('apex_ai')]),
            'sha256': apex_sha,
            'generated_at': timestamp_now,
        },
    },
    'source': {
        'path': FEED_PATH,
        'count': len(raw_feed),
        'sha256': sha256_of(json.dumps(raw_feed, ensure_ascii=False, separators=(',', ':'))),
    },
}
registry_str = json.dumps(manifest_registry, ensure_ascii=False, indent=2)
atomic_write(os.path.join(OUT_DIR, 'manifest.json'), registry_str)
info(f'Written: {OUT_DIR}/manifest.json (registry with checksums)')

# ── STEP 7: Verify all outputs ────────────────────────────────────────────────
print()
print('── VERIFICATION ─────────────────────────────────────────────────', flush=True)
all_ok = True
for fname in ['latest.json', 'top10.json', 'apex.json', 'manifest.json']:
    path = os.path.join(OUT_DIR, fname)
    if os.path.exists(path):
        sz = os.path.getsize(path)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                parsed = json.load(f)
            print(f'  [PASS] {path} ({sz:,} bytes, valid JSON)', flush=True)
        except Exception as e:
            print(f'  [FAIL] {path}: {e}', flush=True)
            all_ok = False
    else:
        print(f'  [FAIL] {path}: NOT FOUND', flush=True)
        all_ok = False

# ── FINAL REPORT ─────────────────────────────────────────────────────────────
print()
print('=' * 68, flush=True)
print(f'SENTINEL APEX {VERSION} -- MANIFEST GENERATION COMPLETE', flush=True)
print(f'  Items in latest.json : {len(sorted_feed)}', flush=True)
print(f'  Items in top10.json  : {len(top10_items)}', flush=True)
print(f'  Items in apex.json   : {len(apex_items)}', flush=True)
print(f'  Apex-enriched count  : {len([i for i in sorted_feed if i.get("apex_ai")])}', flush=True)
print(f'  Output directory     : {os.path.abspath(OUT_DIR)}', flush=True)
print(f'  Status               : {"SUCCESS" if all_ok else "PARTIAL FAILURE"}', flush=True)
print('=' * 68, flush=True)
print('[IMMUTABLE API-FIRST] index.html was NOT modified — zero HTML mutation', flush=True)
print()

if not all_ok:
    sys.exit(1)
sys.exit(0)
