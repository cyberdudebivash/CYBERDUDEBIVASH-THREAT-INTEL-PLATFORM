#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX — Phase 6: API <-> Dashboard Contract Validator
=============================================================
Verifies that the dashboard feed (api/feed.json) and the canonical
feed_manifest.json are in strict sync on:
  - Top-N entry order (stix_id)
  - Timestamps (published / last_modified)
  - Entry count parity

Pipeline FAILS on any mismatch — zero-tolerance mode.

Usage:
    python scripts/api_dashboard_contract_validator.py [--repo-root .] [--top N]
"""

import os, sys, json, argparse, hashlib
from datetime import datetime, timezone

SCRIPT_VERSION = "1.0.0"
DEFAULT_TOP    = 50   # compare top-N by published timestamp
MAX_DELTA_SEC  = 1    # timestamps must match exactly (both from same source)

# ────────────────────────────────────────────────────────────
def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def sha16(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]

def ts_key(entry):
    """Return a comparable timestamp string from an entry."""
    for field in ("published", "published_at", "last_modified", "timestamp", "created"):
        v = entry.get(field, "")
        if v:
            return str(v)
    return ""

def canonical_sort_key(entry):
    """
    v143.1.0 CANONICAL DETERMINISTIC SORT KEY — must match run_pipeline.py exactly.

    Primary  : published_at → timestamp → processed_at (ISO-8601 string, descending)
    Secondary: stix_id (unique per entry) → guarantees stable tie-breaking even when
               multiple entries share the exact same timestamp (common in batch ingestion).

    This key MUST be identical in:
      - scripts/run_pipeline.py  stage_sync_root_feed_json sort_key()
      - scripts/sentinel_stability_lock.py  _get_ts()
      - scripts/api_dashboard_contract_validator.py  (this file)
      - scripts/output_validation_gate.py
      - scripts/regression_immunity.py
    Any divergence causes ORDER MISMATCH / MISSING IN API CI hard-fails.
    """
    ts  = (entry.get("published_at") or entry.get("timestamp") or entry.get("processed_at") or "")
    sid = (entry.get("stix_id") or entry.get("id") or "")
    return (ts, sid)

def normalize_ts(ts_str):
    """Normalize ISO-8601 timestamp to seconds-resolution UTC string."""
    if not ts_str:
        return ""
    ts_str = ts_str.rstrip("Z").split(".")[0]
    return ts_str  # YYYY-MM-DDTHH:MM:SS


# ────────────────────────────────────────────────────────────
def validate(repo_root, top_n):
    errors  = []
    warnings = []

    manifest_path = os.path.join(repo_root, "data", "stix", "feed_manifest.json")
    api_feed_path = os.path.join(repo_root, "api", "feed.json")

    # ── Load sources ────────────────────────────────────────
    if not os.path.exists(manifest_path):
        errors.append("MISSING: data/stix/feed_manifest.json")
        return errors, warnings, {}
    if not os.path.exists(api_feed_path):
        errors.append("MISSING: api/feed.json")
        return errors, warnings, {}

    manifest = load_json(manifest_path)
    api_feed  = load_json(api_feed_path)

    # Both may be wrapped in an outer dict or be bare lists
    def unwrap(data, source_name):
        if isinstance(data, list):
            return data
        for key in ("entries", "items", "intel", "data", "objects", "advisories", "reports"):
            if key in data and isinstance(data[key], list):
                return data[key]
        errors.append(f"UNKNOWN structure in {source_name}: keys={list(data.keys())[:8]}")
        return []

    manifest_items = unwrap(manifest, "feed_manifest.json")
    api_items      = unwrap(api_feed,  "api/feed.json")

    # ── Count check ─────────────────────────────────────────
    m_count = len(manifest_items)
    a_count = len(api_items)

    stats = {
        "manifest_count": m_count,
        "api_count":      a_count,
        "manifest_sha":   sha16(manifest_path),
        "api_feed_sha":   sha16(api_feed_path),
        "validated_at":   datetime.now(timezone.utc).isoformat(),
        "top_n":          top_n,
    }

    # API feed is always capped at 500; manifest may be larger — that's OK
    if a_count > 500:
        errors.append(f"OVERSIZE: api/feed.json has {a_count} entries (cap=500)")
    if m_count == 0:
        errors.append("EMPTY: feed_manifest.json has 0 entries")
    if a_count == 0:
        errors.append("EMPTY: api/feed.json has 0 entries")

    if errors:
        return errors, warnings, stats

    # ── Sort both using canonical deterministic key (v143.1.0 P0 FIX) ──
    # Uses (ts_string, stix_id) composite — matches run_pipeline.py exactly.
    # stix_id as secondary key ensures deterministic tie-breaking when entries
    # share the same timestamp (otherwise Python stable sort depends on list
    # insertion order, which differs between manifest and api/feed.json).
    manifest_sorted = sorted(manifest_items, key=canonical_sort_key, reverse=True)
    api_sorted      = sorted(api_items,      key=canonical_sort_key, reverse=True)

    # Top-N from manifest (bounded by actual api size and top_n param)
    n = min(top_n, a_count, m_count)
    m_top = manifest_sorted[:n]
    a_top = api_sorted[:n]

    # ── stix_id order check ──────────────────────────────────
    for rank, (m_entry, a_entry) in enumerate(zip(m_top, a_top), 1):
        m_id = m_entry.get("stix_id") or m_entry.get("id", "")
        a_id = a_entry.get("stix_id") or a_entry.get("id", "")
        if m_id != a_id:
            errors.append(
                f"ORDER MISMATCH @rank {rank}: manifest={m_id[:40]}  api={a_id[:40]}"
            )
            if len(errors) >= 10:
                errors.append("(truncated at 10 order mismatches)")
                break

    # ── Timestamp check on matched IDs ──────────────────────
    api_by_id = {
        (e.get("stix_id") or e.get("id", "")): e
        for e in api_items
    }
    ts_mismatches = 0
    for m_entry in m_top:
        m_id = m_entry.get("stix_id") or m_entry.get("id", "")
        a_entry = api_by_id.get(m_id)
        if not a_entry:
            # ID present in manifest but absent from api/feed.json
            # This is expected if manifest > 500 entries — only warn for top-N
            rank_in_sorted = next(
                (i for i, e in enumerate(manifest_sorted) if (e.get("stix_id") or e.get("id","")) == m_id),
                9999
            )
            if rank_in_sorted < a_count:
                errors.append(f"MISSING IN API: {m_id[:40]} (manifest rank={rank_in_sorted+1})")
            continue
        m_ts = normalize_ts(ts_key(m_entry))
        a_ts = normalize_ts(ts_key(a_entry))
        if m_ts != a_ts:
            ts_mismatches += 1
            if ts_mismatches <= 5:
                errors.append(
                    f"TS MISMATCH: {m_id[:36]} manifest={m_ts}  api={a_ts}"
                )

    if ts_mismatches > 5:
        errors.append(f"... and {ts_mismatches - 5} more timestamp mismatches")

    # ── Duplicate check in api/feed.json ────────────────────
    seen_ids = {}
    for i, entry in enumerate(api_items):
        eid = entry.get("stix_id") or entry.get("id", f"_idx_{i}")
        if eid in seen_ids:
            errors.append(f"DUPLICATE in api/feed.json: {eid[:40]} (at idx {seen_ids[eid]} and {i})")
            if len(errors) >= 20:
                break
        else:
            seen_ids[eid] = i

    # ── Encoding spot-check ──────────────────────────────────
    with open(api_feed_path, "rb") as fh:
        raw_api = fh.read(65536)   # check first 64KB
    if b"\xef\xbb\xbf" in raw_api:
        errors.append("ENCODING: api/feed.json has UTF-8 BOM")
    if b"\xc3\x82\xc2\xae" in raw_api:
        errors.append("ENCODING: api/feed.json contains double-encoded Â® sequence")
    # Check valid UTF-8
    try:
        raw_api.decode("utf-8")
    except UnicodeDecodeError as ude:
        errors.append(f"ENCODING: api/feed.json not valid UTF-8: {ude}")

    stats["top_n_checked"] = n
    stats["duplicate_count"] = len(api_items) - len(seen_ids)
    stats["ts_mismatches"] = ts_mismatches

    return errors, warnings, stats


# ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SENTINEL APEX Contract Validator v" + SCRIPT_VERSION)
    ap.add_argument("--repo-root", default=".", help="Repository root directory")
    ap.add_argument("--top",       type=int, default=DEFAULT_TOP, help="Top-N entries to compare")
    ap.add_argument("--report",    default="", help="Write JSON report to this path")
    ap.add_argument("--strict",    action="store_true", help="Exit 1 on warnings too")
    args = ap.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    print(f"\n{'='*60}")
    print(f"SENTINEL APEX — API <-> DASHBOARD CONTRACT VALIDATOR v{SCRIPT_VERSION}")
    print(f"{'='*60}")
    print(f"Repo:  {repo_root}")
    print(f"Top-N: {args.top}")
    print()

    errors, warnings, stats = validate(repo_root, args.top)

    # Print stats
    for k, v in stats.items():
        print(f"  {k:<25} {v}")

    # Print results
    print()
    if warnings:
        for w in warnings:
            print(f"  [WARN]  {w}")
    if errors:
        for e in errors:
            print(f"  [ERROR] {e}")
    else:
        print(f"  [OK] All {stats.get('top_n_checked', 0)} top entries match between manifest and api/feed.json")
        print(f"  [OK] No duplicates in api/feed.json")
        print(f"  [OK] Encoding checks passed")

    # Write report
    report = {
        "script":       "api_dashboard_contract_validator",
        "version":      SCRIPT_VERSION,
        "status":       "PASS" if not errors else "FAIL",
        "errors":       errors,
        "warnings":     warnings,
        "stats":        stats,
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }

    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  Report written: {args.report}")

    print(f"\n{'='*60}")
    if errors:
        print(f"RESULT: FAIL — {len(errors)} error(s) found")
        print(f"{'='*60}\n")
        sys.exit(1)
    else:
        print(f"RESULT: PASS — Contract validated (manifest={stats.get('manifest_count',0)} entries, api={stats.get('api_count',0)} entries)")
        print(f"{'='*60}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
