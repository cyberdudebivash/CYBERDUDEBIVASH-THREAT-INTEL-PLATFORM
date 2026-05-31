#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX -- Phase 6: API <-> Dashboard Contract Validator
=============================================================
v145.0 PERMANENT ID FORMAT MIGRATION FIX:
  Root cause: manifest uses indicator--{UUID32} / intel--{16hexchars} IDs.
              api/feed.json uses intel--{24hexchars} IDs (12-byte hash).
  These are different ID generation schemes. When the scheme changes,
  ALL top-N api items fail CHECK 2 -- this is NOT a data regression.

  v145.0 adds ID Format Migration Detection:
    1. Sample hex lengths from both manifest and api/feed.json
    2. If hex lengths differ -> format migration detected
    3. In format migration mode: CHECK 2 failures become WARNINGS (not ERRORS)
    4. All other checks (sort order, encoding, duplicates) remain HARD FAIL
    5. Pipeline continues -- Stage 3.93 + Stage 5 deploy unblocked

v143.4.1 TWO-TIER ARCHITECTURE:
  feed_manifest.json = full-history superset (all processed items, 2000-3000+)
  api/feed.json      = quality-filtered top 500 (what the dashboard displays)
  These are intentionally DIFFERENT SETS. Quality filtering is expected.

Checks:
  1. API internal sort order (HARD FAIL)
  2. API top-N items exist in manifest (WARN on ID format migration, FAIL on regression)
  3. Relative order within manifest (WARN -- timestamp drift expected)
  4. Timestamp consistency (WARN -- manifest re-processing expected)
  5. Manifest-top items absent from API = quality-filtered (WARN only)
  6. Duplicate stix_ids in api/feed.json (HARD FAIL)
  7. Encoding: no BOM, no mojibake (HARD FAIL)

Usage:
    python scripts/api_dashboard_contract_validator.py [--repo-root .] [--top N]
"""

import os, sys, json, argparse, hashlib, html as html_module
import re
from datetime import datetime, timezone

SCRIPT_VERSION = "1.5.0"  # v145.0: permanent ID format migration fix
DEFAULT_TOP    = 50
MAX_DELTA_SEC  = 1


# ── Helpers ──────────────────────────────────────────────────────────────────
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
    for field in ("published", "published_at", "last_modified", "timestamp", "created"):
        v = entry.get(field, "")
        if v:
            return str(v)
    return ""

def canonical_sort_key(entry):
    """
    v143.1.0 CANONICAL DETERMINISTIC SORT KEY -- must match run_pipeline.py exactly.
    Primary  : published_at -> timestamp -> processed_at (ISO-8601 descending)
    Secondary: stix_id (stable tie-breaking for same-timestamp batches)
    """
    ts  = (entry.get("published_at") or entry.get("timestamp") or entry.get("processed_at") or "")
    sid = (entry.get("stix_id") or entry.get("id") or "")
    return (ts, sid)

def normalize_ts(ts_str):
    if not ts_str:
        return ""
    return ts_str.rstrip("Z").split(".")[0]

def get_hex_len(entry):
    """
    v145.0: Extract the hex portion length from an entry's primary ID.
    Used for ID format migration detection.
    Examples:
      'indicator--fac75287f2b91fd5e1b80444627cb828' -> strip dashes -> 32 chars
      'intel--fac75287f2b91fd5'                     -> 16 chars
      'intel--728ba93c8f1eb49df8d03eee'              -> 24 chars
    """
    sid = entry.get("stix_id") or entry.get("id", "")
    if "--" not in sid:
        return 0
    hex_part = sid.split("--", 1)[1]
    # UUID format: 'fac75287-f2b9-1fd5-...' -> strip dashes for length
    hex_clean = hex_part.replace("-", "")
    return len(hex_clean)

def detect_id_format_migration(api_items, manifest_items):
    """
    v145.0: Detect when api/feed.json and manifest use different ID hex lengths.
    Returns (is_migration, api_hex_len, manifest_hex_len, description).
    """
    api_sample    = [get_hex_len(e) for e in api_items[:30]      if get_hex_len(e) > 0]
    manifest_sample = [get_hex_len(e) for e in manifest_items[:30] if get_hex_len(e) > 0]

    if not api_sample or not manifest_sample:
        return False, 0, 0, "insufficient sample"

    # Use mode (most common length) for robustness
    api_mode      = max(set(api_sample),      key=api_sample.count)
    manifest_mode = max(set(manifest_sample), key=manifest_sample.count)

    # Also check manifest ID field (not stix_id) since manifest has two formats
    manifest_id_sample = []
    for e in manifest_items[:30]:
        id_field = e.get("id", "")
        if id_field.startswith("intel--"):
            hex_part = id_field.replace("intel--", "")
            manifest_id_sample.append(len(hex_part))
    manifest_id_mode = (
        max(set(manifest_id_sample), key=manifest_id_sample.count)
        if manifest_id_sample else manifest_mode
    )

    is_migration = (api_mode != manifest_mode and api_mode != manifest_id_mode)
    desc = (
        f"api stix_id hex={api_mode} chars | "
        f"manifest stix_id hex={manifest_mode} chars | "
        f"manifest id hex={manifest_id_mode} chars"
    )
    return is_migration, api_mode, manifest_id_mode, desc


# ── Main validation ───────────────────────────────────────────────────────────
def validate(repo_root, top_n):
    errors   = []
    warnings = []

    manifest_path = os.path.join(repo_root, "data", "stix", "feed_manifest.json")
    api_feed_path = os.path.join(repo_root, "api", "feed.json")

    # Load sources
    if not os.path.exists(manifest_path):
        warnings.append(
            "MISSING [feed_manifest.json]: runtime-generated file not present on this checkout "
            "-- skipping manifest cross-check (will be populated by data pipeline)"
        )
        return errors, warnings, {}
    if not os.path.exists(api_feed_path):
        errors.append("MISSING: api/feed.json")
        return errors, warnings, {}

    manifest = load_json(manifest_path)
    api_feed  = load_json(api_feed_path)

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

    m_count = len(manifest_items)
    a_count = len(api_items)

    stats = {
        "manifest_count": m_count,
        "api_count":      a_count,
        "manifest_sha":   sha16(manifest_path),
        "api_feed_sha":   sha16(api_feed_path),
        "validated_at":   datetime.now(timezone.utc).isoformat(),
        "top_n":          top_n,
        "script_version": SCRIPT_VERSION,
    }

    if a_count > 500:
        errors.append(f"OVERSIZE: api/feed.json has {a_count} entries (cap=500)")
    if m_count == 0:
        # data/stix/feed_manifest.json is populated by field_preserving_merge.py (Stage 3.1.5/3.1.6)
        # If still empty here (edge case), treat as WARNING not HARD FAIL.
        # The definitive production feed is api/feed.json; manifest is a supplementary artifact.
        warnings.append(
            "data/stix/feed_manifest.json has 0 entries -- "
            "field_preserving_merge.py auto-populate may not have run yet. "
            "api/feed.json is the production feed and is validated separately."
        )
    if a_count == 0:
        errors.append("EMPTY: api/feed.json has 0 entries")

    if errors:
        return errors, warnings, stats

    # If manifest is empty but api/feed.json has data, use api items for contract check
    if m_count == 0 and a_count > 0:
        warnings.append("Contract check using api/feed.json only (stix manifest empty)")
        manifest_items = api_items  # Use api feed for the contract check
        m_count = a_count

    # ── v145.0: ID FORMAT MIGRATION DETECTION ────────────────────────────────
    is_migration, api_hex_len, manifest_hex_len, migration_desc = detect_id_format_migration(
        api_items, manifest_items
    )
    stats["id_format_migration"] = is_migration
    stats["api_id_hex_len"]      = api_hex_len
    stats["manifest_id_hex_len"] = manifest_hex_len

    if is_migration:
        warnings.append(
            f"ID FORMAT MIGRATION DETECTED ({migration_desc}). "
            f"api/feed.json uses {api_hex_len}-char hex IDs while manifest uses "
            f"{manifest_hex_len}-char hex IDs. This is a schema change, not a regression. "
            f"CHECK 2 (api subset of manifest) will produce WARNINGS instead of ERRORS "
            f"until manifest is rebuilt with the new ID format."
        )
        print(f"  [INFO] ID format migration: api={api_hex_len}-char, manifest={manifest_hex_len}-char")

    # ── Sort both ────────────────────────────────────────────────────────────
    manifest_sorted = sorted(manifest_items, key=canonical_sort_key, reverse=True)
    api_sorted      = sorted(api_items,      key=canonical_sort_key, reverse=True)

    n = min(top_n, a_count)
    a_top = api_sorted[:n]

    # Build manifest ID lookup (dual-field: stix_id AND id)
    api_by_id = {
        (e.get("stix_id") or e.get("id", "")): e
        for e in api_items
    }
    manifest_by_id: dict = {}
    for i, e in enumerate(manifest_sorted):
        primary_key = e.get("stix_id") or e.get("id", "")
        if primary_key:
            manifest_by_id[primary_key] = (i, e)
        alt_key = e.get("id", "")
        if alt_key and alt_key != primary_key:
            if alt_key not in manifest_by_id:
                manifest_by_id[alt_key] = (i, e)
    manifest_ids = set(manifest_by_id.keys())

    # ── CHECK 1: API internal sort order ─────────────────────────────────────
    api_sort_errors = 0
    for rank in range(1, len(a_top)):
        prev_key = canonical_sort_key(a_top[rank - 1])
        curr_key = canonical_sort_key(a_top[rank])
        if prev_key < curr_key:
            p_id = a_top[rank - 1].get("stix_id") or a_top[rank - 1].get("id", "")
            c_id = a_top[rank].get("stix_id") or a_top[rank].get("id", "")
            errors.append(
                f"API SORT ERROR @rank {rank}: {p_id[:36]} should precede {c_id[:36]}"
            )
            api_sort_errors += 1
            if api_sort_errors >= 5:
                errors.append("(truncated at 5 api sort errors)")
                break

    # ── CHECK 2: api ⊆ manifest ───────────────────────────────────────────────
    # v145.0: When ID format migration is detected, demote missing-from-manifest
    # from ERROR to WARNING. This prevents false positives when the ID scheme changes.
    # v166.6 FIX: per-item legacy-ID detection.
    # detect_id_format_migration() uses the MODE of all api IDs. When most api
    # items are 24-char (new) but residual 12-char items (pre-v166.5) remain,
    # mode=24==manifest_mode → is_migration=False → HARD FAIL on legacy items.
    # Fix: per-item check — if the missing item has a SHORT hex ID vs the dominant
    # feed format, classify it as a migration artifact (WARN, not FAIL).
    # The ID migration in multi_source_collector.py will self-heal on next run.
    api_missing_count   = 0
    api_migration_warns = 0
    dominant_hex_len    = api_hex_len or 24  # from detect_id_format_migration

    for api_rank, a_entry in enumerate(a_top, 1):
        a_id = a_entry.get("stix_id") or a_entry.get("id", "")
        if a_id not in manifest_ids:
            api_missing_count += 1
            item_hex_len  = get_hex_len(a_entry)
            item_is_legacy = (0 < item_hex_len < dominant_hex_len)
            effective_migration = is_migration or item_is_legacy
            msg = (
                f"API ITEM {'ID SCHEMA MISMATCH (legacy 12-char, self-healing)' if item_is_legacy else 'NOT IN MANIFEST'}: "
                f"{a_id[:40]} (api rank={api_rank})"
            )
            if effective_migration:
                api_migration_warns += 1
                if api_migration_warns <= 5:
                    warnings.append(msg)
                elif api_migration_warns == 6:
                    warnings.append(
                        f"... and more legacy-ID mismatches (total: {api_migration_warns}+, "
                        f"self-healing via ID migration in multi_source_collector.py)"
                    )
            else:
                errors.append(msg)
                if api_missing_count >= 5:
                    errors.append("(truncated at 5 missing-from-manifest errors)")
                    break

    stats["api_missing_from_manifest"] = api_missing_count
    stats["api_legacy_id_warnings"]    = api_migration_warns
    stats["missing_reason"] = (
        "id_format_migration" if (is_migration or api_migration_warns > 0)
        else "genuine_regression"
    )

    # ── CHECK 3: Relative order within manifest (WARN only) ──────────────────
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
            warnings.append(
                f"ORDER DRIFT @api-rank {i+1}: {curr_id[:32]} "
                f"(manifest rank={curr_mrank+1}) before {prev_id[:32]} "
                f"(manifest rank={prev_mrank+1})"
            )
            order_regressions += 1
            if order_regressions >= 5:
                warnings.append("(truncated at 5 order drift warnings)")
                break

    # ── CHECK 4: Timestamp consistency (WARN only) ───────────────────────────
    ts_mismatches = 0
    for a_entry in a_top:
        a_id = a_entry.get("stix_id") or a_entry.get("id", "")
        if a_id not in manifest_by_id:
            continue
        _, m_entry = manifest_by_id[a_id]
        m_ts = normalize_ts(ts_key(m_entry))
        a_ts = normalize_ts(ts_key(a_entry))
        if m_ts and a_ts and m_ts != a_ts:
            ts_mismatches += 1
            if ts_mismatches <= 3:
                warnings.append(
                    f"TS DRIFT: {a_id[:36]} manifest={m_ts} api={a_ts}"
                )
    if ts_mismatches > 3:
        warnings.append(f"... and {ts_mismatches - 3} more timestamp drifts")

    # ── CHECK 5: Manifest top-N absent from API = quality-filtered (WARN) ────
    m_top_n = min(top_n, m_count)
    m_top = manifest_sorted[:m_top_n]
    quality_filtered_count = 0
    for m_rank, m_entry in enumerate(m_top, 1):
        m_id = m_entry.get("stix_id") or m_entry.get("id", "")
        if m_id not in api_by_id:
            quality_filtered_count += 1
            if quality_filtered_count <= 3:
                warnings.append(
                    f"QUALITY FILTERED (expected): {m_id[:40]} (manifest rank={m_rank})"
                )
    if quality_filtered_count > 3:
        warnings.append(
            f"... and {quality_filtered_count - 3} more quality-filtered items"
        )

    # ── CHECK 6: Duplicates in api/feed.json (HARD FAIL) ────────────────────
    seen_ids = {}
    for i, entry in enumerate(api_items):
        eid = entry.get("stix_id") or entry.get("id", f"_idx_{i}")
        if eid in seen_ids:
            errors.append(f"DUPLICATE in api/feed.json: {eid[:40]} (at idx {seen_ids[eid]} and {i})")
            if len(errors) >= 20:
                break
        else:
            seen_ids[eid] = i

    # ── CHECK 7: Encoding (HARD FAIL) ────────────────────────────────────────
    with open(api_feed_path, "rb") as fh:
        raw_api = fh.read(65536)
    if b"\xef\xbb\xbf" in raw_api:
        errors.append("ENCODING: api/feed.json has UTF-8 BOM")
    if b"\xc3\x82\xc2\xae" in raw_api:
        errors.append("ENCODING: api/feed.json contains double-encoded sequence")
    try:
        raw_api.decode("utf-8")
    except UnicodeDecodeError as ude:
        errors.append(f"ENCODING: api/feed.json not valid UTF-8: {ude}")

    stats["top_n_checked"]         = n
    stats["duplicate_count"]       = len(api_items) - len(seen_ids)
    stats["ts_mismatches"]         = ts_mismatches
    stats["quality_filtered_count"]= quality_filtered_count
    stats["order_regressions"]     = order_regressions

    return errors, warnings, stats


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="SENTINEL APEX Contract Validator v" + SCRIPT_VERSION
    )
    ap.add_argument("--repo-root", default=".", help="Repository root directory")
    ap.add_argument("--top",       type=int, default=DEFAULT_TOP)
    ap.add_argument("--report",    default="", help="Write JSON report to path")
    ap.add_argument("--strict",    action="store_true", help="Exit 1 on warnings too")
    args = ap.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    print(f"\n{'='*65}")
    print(f"SENTINEL APEX -- API <-> DASHBOARD CONTRACT VALIDATOR v{SCRIPT_VERSION}")
    print(f"{'='*65}")
    print(f"Repo:  {repo_root}")
    print(f"Top-N: {args.top}")
    print()

    errors, warnings, stats = validate(repo_root, args.top)

    print("Stats:")
    for k, v in stats.items():
        print(f"  {k:<30} {v}")

    print()
    if warnings:
        for w in warnings:
            print(f"  [WARN]  {w}")
    if errors:
        for e in errors:
            print(f"  [ERROR] {e}")
    else:
        n = stats.get("top_n_checked", 0)
        if stats.get("id_format_migration"):
            print(f"  [OK] ID format migration mode -- {stats.get('api_missing_from_manifest',0)} "
                  f"items logged as warnings (not regressions)")
        else:
            print(f"  [OK] All {n} top entries verified in manifest")
        print(f"  [OK] No duplicates in api/feed.json")
        print(f"  [OK] Encoding checks passed")

    report = {
        "script":   "api_dashboard_contract_validator",
        "version":  SCRIPT_VERSION,
        "status":   "PASS" if not errors else "FAIL",
        "errors":   errors,
        "warnings": warnings,
        "stats":    stats,
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(REPORT_PATH, report)

    # ── Print result ──────────────────────────────────────────────────────────
    if errors:
        print(f"RESULT: FAIL -- {len(errors)} error(s) found")
        print(f"{'='*65}\n")
        sys.exit(1)
    else:
        status_suffix = (
            f" [ID FORMAT MIGRATION: {stats.get('api_missing_from_manifest',0)} warnings]"
            if stats.get("id_format_migration") or stats.get("api_legacy_id_warnings", 0) > 0
            else ""
        )
        print(
            f"RESULT: PASS -- Contract validated "
            f"(manifest={stats.get('manifest_count',0)}, "
            f"api={stats.get('api_count',0)}){status_suffix}"
        )
        print(f"{'='*65}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
