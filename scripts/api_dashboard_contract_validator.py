#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX — Phase 6: API <-> Dashboard Contract Validator
=============================================================
v143.4.1 TWO-TIER ARCHITECTURE FIX:
  feed_manifest.json = full-history superset (all processed items, 2000-3000+)
  api/feed.json      = quality-filtered top 500 (what the dashboard displays)

  These are intentionally DIFFERENT SETS. The old validator compared manifest
  top-N vs api top-N position-by-position, which broke when quality-filtered
  items appeared in manifest top-50 but not in api top-50.

  New contract checks:
    1. api/feed.json is correctly sorted by canonical key (internal consistency)
    2. Every api/feed.json top-N item EXISTS in manifest (api ⊆ manifest SSOT)
    3. Relative order of api items within manifest matches api order
    4. No duplicates in api/feed.json
    5. Timestamps on matched items are consistent
    6. Encoding is valid UTF-8, no BOM, no mojibake
  Items in manifest top-N but absent from api = quality-filtered → WARNING only.

Usage:
    python scripts/api_dashboard_contract_validator.py [--repo-root .] [--top N]
"""

import os, sys, json, argparse, hashlib
from datetime import datetime, timezone

SCRIPT_VERSION = "1.1.0"  # v143.4.1: two-tier architecture
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

    # v143.4.1 TWO-TIER ARCHITECTURE:
    # manifest = full history superset (all processed items)
    # api      = quality-filtered top 500 (dashboard view)
    # Top-N from API only (bounded by actual api size and top_n param)
    n = min(top_n, a_count)
    a_top = api_sorted[:n]

    # Build lookup maps for O(1) access
    api_by_id = {
        (e.get("stix_id") or e.get("id", "")): e
        for e in api_items
    }
    # manifest index: id -> (rank_in_manifest_sorted, entry)
    manifest_by_id = {
        (e.get("stix_id") or e.get("id", "")): (i, e)
        for i, e in enumerate(manifest_sorted)
    }
    manifest_ids = set(manifest_by_id.keys())

    # ── CHECK 1: API internal sort order ────────────────────
    # Verify api/feed.json top-N is correctly sorted by canonical key.
    # This is the PRIMARY sort contract — if API itself is out of order, fail.
    api_sort_errors = 0
    for rank in range(1, len(a_top)):
        prev_key = canonical_sort_key(a_top[rank - 1])
        curr_key = canonical_sort_key(a_top[rank])
        if prev_key < curr_key:  # descending — prev must be >= curr
            p_id = a_top[rank - 1].get("stix_id") or a_top[rank - 1].get("id", "")
            c_id = a_top[rank].get("stix_id") or a_top[rank].get("id", "")
            errors.append(
                f"API SORT ERROR @rank {rank}: {p_id[:36]} should precede {c_id[:36]}"
            )
            api_sort_errors += 1
            if api_sort_errors >= 5:
                errors.append("(truncated at 5 api sort errors)")
                break

    # ── CHECK 2: API top-N items must exist in manifest ─────
    # api ⊆ manifest is the fundamental SSOT contract.
    # If an API item is missing from manifest, it's a pipeline regression.
    api_missing_from_manifest = 0
    for api_rank, a_entry in enumerate(a_top, 1):
        a_id = a_entry.get("stix_id") or a_entry.get("id", "")
        if a_id not in manifest_ids:
            errors.append(
                f"API ITEM NOT IN MANIFEST (regression): {a_id[:40]} (api rank={api_rank})"
            )
            api_missing_from_manifest += 1
            if api_missing_from_manifest >= 5:
                errors.append("(truncated at 5 missing-from-manifest errors)")
                break

    # ── CHECK 3: Relative order of API items within manifest ─
    # Items appearing earlier in API should also appear earlier in manifest.
    # Only check items that exist in both (skip any missing from manifest).
    api_manifest_ranks = []
    for a_entry in a_top:
        a_id = a_entry.get("stix_id") or a_entry.get("id", "")
        if a_id in manifest_by_id:
            api_manifest_ranks.append((a_id, manifest_by_id[a_id][0]))
    order_regressions = 0
    for i in range(1, len(api_manifest_ranks)):
        prev_id, prev_mrank = api_manifest_ranks[i - 1]
        curr_id, curr_mrank = api_manifest_ranks[i]
        if curr_mrank < prev_mrank:
            # curr item appears BEFORE prev in manifest — order regression
            errors.append(
                f"ORDER REGRESSION @api-rank {i+1}: {curr_id[:32]} "
                f"(manifest rank={curr_mrank+1}) before {prev_id[:32]} "
                f"(manifest rank={prev_mrank+1})"
            )
            order_regressions += 1
            if order_regressions >= 5:
                errors.append("(truncated at 5 order regression errors)")
                break

    # ── CHECK 4: Timestamp consistency on matched IDs ────────
    ts_mismatches = 0
    for a_entry in a_top:
        a_id = a_entry.get("stix_id") or a_entry.get("id", "")
        if a_id not in manifest_by_id:
            continue  # already flagged in CHECK 2
        _, m_entry = manifest_by_id[a_id]
        m_ts = normalize_ts(ts_key(m_entry))
        a_ts = normalize_ts(ts_key(a_entry))
        if m_ts and a_ts and m_ts != a_ts:
            ts_mismatches += 1
            if ts_mismatches <= 5:
                errors.append(
                    f"TS MISMATCH: {a_id[:36]} manifest={m_ts}  api={a_ts}"
                )
    if ts_mismatches > 5:
        errors.append(f"... and {ts_mismatches - 5} more timestamp mismatches")

    # ── WARN: manifest top-N items absent from API ──────────
    # These were quality-filtered out of feed.json — intentional, not an error.
    # v143.4.1: demoted from ERROR to WARNING.
    m_top_n = min(top_n, m_count)
    m_top = manifest_sorted[:m_top_n]
    quality_filtered_count = 0
    for m_rank, m_entry in enumerate(m_top, 1):
        m_id = m_entry.get("stix_id") or m_entry.get("id", "")
        if m_id not in api_by_id:
            quality_filtered_count += 1
            if quality_filtered_count <= 5:
                warnings.append(
                    f"QUALITY FILTERED (not in API): {m_id[:40]} (manifest rank={m_rank})"
                )
    if quality_filtered_count > 5:
        warnings.append(
            f"... and {quality_filtered_count - 5} more quality-filtered items in manifest top-{m_top_n}"
        )

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
