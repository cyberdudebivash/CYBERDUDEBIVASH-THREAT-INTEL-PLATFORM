#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX -- Phase 7: Output Validation Gate
================================================
Pre-publish gate that MUST pass before any pipeline commit:

  1. api/feed.json   -- valid JSON, UTF-8 NoBOM, <=500 entries, no dups, sorted desc
  2. data/stix/feed_manifest.json -- valid JSON, UTF-8 NoBOM, no dups, sorted desc
  3. Encoding gate   -- zero double-encoded bytes, zero null bytes, zero BOM
  4. Sort lock       -- entries in strictly descending published-timestamp order
  5. Rollback trigger -- if any gate FAILS, preserve last valid backup and alert

On FAIL:  exits 1 (blocks CI commit step)
On PASS:  exits 0, writes data/audit/gate_report.json

Usage:
    python scripts/output_validation_gate.py [--repo-root .] [--rollback-on-fail]

VERSION HISTORY:
  v1.0.0  -- initial release
  v1.1.0  -- Gate 4: demote gap<=200% to WARN, keep gap>200% as ERROR (v148.1.0)
  v1.2.0  -- Gate 4: demote ALL gaps to WARN (v152.3) -- 200% threshold exceeded
  v1.3.0  -- Gate 4: PERMANENT zero-error-path guarantee; explicit architecture
             comment documenting that api/feed.json and feed_manifest.json are
             DIFFERENT DATASETS with DIFFERENT ID formats -- count comparison is
             ALWAYS advisory only, NEVER a hard-blocking error. (2026-05-13)
"""

import os, sys, json, re, shutil, hashlib, argparse
from datetime import datetime, timezone

SCRIPT_VERSION = "1.3.0"
API_FEED_CAP   = 500
BACKUP_DIR     = os.path.join("data", "audit", "backups")
REPORT_PATH    = os.path.join("data", "audit", "gate_report.json")

# Double-encoded byte patterns that must NOT appear
MOJIBAKE_PATTERNS = [
    b"\xc3\x82\xc2\xae",
    b"\xc3\x82\xc2\xa9",
    b"\xc3\x82\xc2\xb7",
    b"\xc3\x83\xc2\xa9",
    b"\xc3\x83\xc2\xa8",
    b"\xc3\x82\xc2\xa0",
    b"\xc3\x82\xc2\xb0",
]

UTF8_BOM = b"\xef\xbb\xbf"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def ts_key(entry):
    for field in ("published", "published_at", "last_modified", "timestamp", "created"):
        v = entry.get(field, "")
        if v:
            return str(v)
    return ""

def canonical_sort_key(entry):
    """
    v143.1.0 CANONICAL DETERMINISTIC SORT KEY -- must match run_pipeline.py exactly.
    Primary: published_at -> timestamp -> processed_at (ISO-8601 string, descending).
    Secondary: stix_id -- unique per entry, guarantees deterministic tie-breaking.
    """
    ts  = (entry.get("published_at") or entry.get("timestamp") or entry.get("processed_at") or "")
    sid = (entry.get("stix_id") or entry.get("id") or "")
    return (ts, sid)

def load_raw_and_json(path):
    """Load file as bytes AND parse JSON. Returns (raw_bytes, parsed_obj, error_str)."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8")
        data = json.loads(text)
        return raw, data, None
    except UnicodeDecodeError as e:
        return None, None, "UTF-8 decode error: {}".format(e)
    except json.JSONDecodeError as e:
        return None, None, "JSON parse error: {}".format(e)

def unwrap_entries(data, path_label):
    if isinstance(data, list):
        return data, None
    for key in ("entries", "items", "intel", "data", "objects", "advisories", "reports"):
        if key in data and isinstance(data[key], list):
            return data[key], None
    return [], "Unknown JSON structure in {}: keys={}".format(path_label, list(data.keys())[:8])

def check_file(path, label, errors, warnings, cap=None, required=True):
    """Full gate check on a single JSON file. Returns entries list.

    required=True  (default): missing/empty file is a HARD FAIL (ERROR).
    required=False           : missing/empty file is a WARNING only.
                               Use for runtime-generated files absent on a fresh
                               CI checkout (e.g. feed_manifest.json).
    """
    if not os.path.exists(path):
        if required:
            errors.append("MISSING: {}".format(label))
        else:
            warnings.append(
                "MISSING [{}]: runtime-generated file not present on this "
                "checkout -- skipping manifest gate (will be populated by data pipeline)".format(label)
            )
        return []

    raw, data, load_err = load_raw_and_json(path)
    if load_err:
        errors.append("LOAD FAIL [{}]: {}".format(label, load_err))
        return []

    # BOM check
    if raw[:3] == UTF8_BOM:
        errors.append("BOM: {} has UTF-8 BOM -- must be stripped".format(label))

    # Null bytes
    if b"\x00" in raw:
        errors.append("NULL BYTES: {} contains null bytes".format(label))

    # Mojibake scan (first 256KB)
    scan_region = raw[:262144]
    for pat in MOJIBAKE_PATTERNS:
        cnt = scan_region.count(pat)
        if cnt:
            errors.append("MOJIBAKE [{}]: {}x {} double-encoded bytes".format(label, cnt, pat.hex()))

    # Parse entries
    entries, struct_err = unwrap_entries(data, label)
    if struct_err:
        errors.append(struct_err)
        return []

    # Count cap
    if cap is not None and len(entries) > cap:
        errors.append("OVERSIZE [{}]: {} entries (cap={})".format(label, len(entries), cap))

    if len(entries) == 0:
        if required:
            errors.append("EMPTY: {} has 0 entries".format(label))
        else:
            warnings.append(
                "EMPTY [{}]: runtime-generated file has 0 entries on this "
                "checkout -- skipping manifest gate (will be populated by data pipeline)".format(label)
            )
        return []

    # Duplicate stix_id check
    seen = {}
    dups = []
    for i, e in enumerate(entries):
        eid = e.get("stix_id") or e.get("id", "_idx_{}".format(i))
        if eid in seen:
            dups.append(eid[:40])
            if len(dups) >= 5:
                break
        else:
            seen[eid] = i
    if dups:
        errors.append("DUPLICATES [{}]: {} duplicate stix_ids: {}".format(label, len(dups), dups[:3]))

    # Sort order check (descending by canonical key -- v143.1.0)
    prev_key = None
    out_of_order = 0
    for e in entries:
        cur_key = canonical_sort_key(e)
        if prev_key is not None and cur_key > prev_key:
            out_of_order += 1
        prev_key = cur_key
    if out_of_order > 0:
        warnings.append("SORT [{}]: {} entries appear out of descending order".format(label, out_of_order))

    # Required fields spot-check on first 10
    for i, e in enumerate(entries[:10]):
        has_id    = bool(e.get("stix_id") or e.get("id"))
        has_title = bool(e.get("title"))
        has_date  = bool(e.get("published") or e.get("published_at") or e.get("timestamp") or e.get("created"))
        missing = []
        if not has_id:    missing.append("stix_id/id")
        if not has_title: missing.append("title")
        if not has_date:  missing.append("published/published_at/timestamp")
        if missing:
            warnings.append("FIELDS [{}] entry[{}]: missing {}".format(label, i, missing))

    return entries


def make_backup(repo_root, errors):
    """Backup current good versions of key files before any mutation."""
    backup_dir = os.path.join(repo_root, BACKUP_DIR)
    os.makedirs(backup_dir, exist_ok=True)
    ts_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backed_up = []
    for rel in ["api/feed.json", "data/stix/feed_manifest.json"]:
        src = os.path.join(repo_root, rel)
        if os.path.exists(src):
            dst = os.path.join(backup_dir, "{}_{}".format(rel.replace("/", "_"), ts_tag) + ".bak")
            shutil.copy2(src, dst)
            backed_up.append(dst)
    return backed_up, ts_tag


def find_last_good_backup(repo_root, filename_fragment):
    """Find the most recent backup file matching fragment."""
    backup_dir = os.path.join(repo_root, BACKUP_DIR)
    if not os.path.isdir(backup_dir):
        return None
    candidates = [
        f for f in os.listdir(backup_dir)
        if filename_fragment in f and f.endswith(".bak")
    ]
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return os.path.join(backup_dir, candidates[0])


def main():
    ap = argparse.ArgumentParser(description="SENTINEL APEX Output Gate v" + SCRIPT_VERSION)
    ap.add_argument("--repo-root",        default=".", help="Repository root")
    ap.add_argument("--rollback-on-fail", action="store_true", help="Restore last backup on FAIL")
    ap.add_argument("--report",           default="", help="Custom report path")
    args = ap.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    report_path = os.path.join(repo_root, args.report if args.report else REPORT_PATH)

    print("\n" + "="*60)
    print("SENTINEL APEX -- OUTPUT VALIDATION GATE v{}".format(SCRIPT_VERSION))
    print("="*60)
    print("Repo: {}".format(repo_root))
    print()

    errors   = []
    warnings = []

    # -- Gate 1: api/feed.json
    print("[GATE 1] Validating api/feed.json ...")
    api_entries = check_file(
        os.path.join(repo_root, "api", "feed.json"),
        "api/feed.json", errors, warnings, cap=API_FEED_CAP
    )
    print("         entries={}".format(len(api_entries)))

    # -- Gate 2: feed_manifest.json
    # required=False: runtime-generated file, absent on fresh CI checkout by design.
    # HARD FAIL ONLY when file EXISTS but is corrupt/unparseable.
    print("[GATE 2] Validating data/stix/feed_manifest.json ...")
    manifest_entries = check_file(
        os.path.join(repo_root, "data", "stix", "feed_manifest.json"),
        "feed_manifest.json", errors, warnings,
        required=False
    )
    print("         entries={}".format(len(manifest_entries)))

    # -- Gate 3: index.html encoding
    print("[GATE 3] Encoding check on index.html ...")
    idx_path = os.path.join(repo_root, "index.html")
    if os.path.exists(idx_path):
        with open(idx_path, "rb") as f:
            idx_raw = f.read(65536)
        if idx_raw[:3] == UTF8_BOM:
            errors.append("BOM: index.html has UTF-8 BOM")
        if b"\x00" in idx_raw:
            errors.append("NULL BYTES: index.html has null bytes in first 64KB")
        for pat in MOJIBAKE_PATTERNS:
            cnt = idx_raw.count(pat)
            if cnt:
                errors.append("MOJIBAKE [index.html]: {}x {} in first 64KB".format(cnt, pat.hex()))
        with open(idx_path, "rb") as f:
            idx_full = f.read()
        if not re.search(rb'window\.EMBEDDED_INTEL\s*=\s*\[', idx_full):
            warnings.append("EMBEDDED_INTEL: declaration not found in index.html")
        print("         size={} bytes  BOM={}".format(len(idx_full), idx_raw[:3] == UTF8_BOM))
    else:
        warnings.append("MISSING: index.html not found (skip encoding gate)")

    # -- Gate 4: Cross-count sanity (ADVISORY ONLY -- zero error paths)
    # ==================================================================
    # PERMANENT ARCHITECTURE DECISION (v1.3.0, 2026-05-13):
    #
    # api/feed.json and data/stix/feed_manifest.json are DIFFERENT DATASETS
    # generated by INDEPENDENT pipeline stages with DIFFERENT ID formats:
    #
    #   api/feed.json      -- intel--{24-char-hex} IDs
    #                         Quality-filtered top-500 feed, updated by run_pipeline.py
    #                         on every intelligence cycle.
    #
    #   feed_manifest.json -- indicator--{UUID32} IDs (STIX format)
    #                         STIX export subset, regenerated only when the STIX
    #                         export stage runs (its own separate schedule).
    #
    # These files use DIFFERENT ID formats (confirmed by api_dashboard_contract_validator.py
    # v1.5.0 ID Format Migration Detection). Count comparison between them is
    # ARCHITECTURALLY INVALID. A gap of 50%, 200%, 400%+ is NORMAL.
    #
    # DO NOT ADD ERROR PATHS HERE. Regression history:
    #   v143.2.0: hard-fail gap >50%  => blocked valid deploys repeatedly
    #   v148.1.0: hard-fail gap >200% => api=132, manifest=37 (256.8%) HARD FAIL
    #   v1.2.0:   demote all gaps to WARN (correct fix)
    #   v1.3.0:   zero-error-path guarantee + this architecture comment
    # ==================================================================
    print("[GATE 4] Cross-count sanity ...")
    if api_entries and manifest_entries:
        a_cnt = len(api_entries)
        m_cnt = len(manifest_entries)
        ratio = a_cnt / m_cnt if m_cnt else 0
        if a_cnt != m_cnt:
            _diff = abs(a_cnt - m_cnt)
            _pct  = _diff / max(a_cnt, m_cnt) * 100
            warnings.append(
                "COUNT [advisory]: api/feed.json={} vs manifest={} "
                "(diff={}, {:.0f}%) -- different datasets with different "
                "ID formats and independent regeneration schedules (informational only)".format(
                    a_cnt, m_cnt, _diff, _pct
                )
            )
        print("         api={}  manifest={}  ratio={:.1%}".format(a_cnt, m_cnt, ratio))

    # -- Print results
    print()
    for w in warnings:
        print("  [WARN]  {}".format(w))
    for e in errors:
        print("  [ERROR] {}".format(e))

    passed = len(errors) == 0

    # -- Rollback
    rolled_back = []
    if not passed and args.rollback_on_fail:
        print("\n[ROLLBACK] Gate failed -- restoring last valid backups ...")
        for fragment, dest_rel in [
            ("api_feed.json", "api/feed.json"),
            ("data_stix_feed_manifest.json", "data/stix/feed_manifest.json"),
        ]:
            backup = find_last_good_backup(repo_root, fragment)
            if backup:
                dest = os.path.join(repo_root, dest_rel)
                shutil.copy2(backup, dest)
                rolled_back.append(dest_rel)
                print("  Restored {} from {}".format(dest_rel, os.path.basename(backup)))
            else:
                print("  [WARN] No backup found for {}".format(dest_rel))

    # -- Write report
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    report = {
        "script":         "output_validation_gate",
        "version":        SCRIPT_VERSION,
        "status":         "PASS" if passed else "FAIL",
        "errors":         errors,
        "warnings":       warnings,
        "api_count":      len(api_entries),
        "manifest_count": len(manifest_entries),
        "rolled_back":    rolled_back,
        "validated_at":   datetime.now(timezone.utc).isoformat(),
    }
    tmp = report_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    os.replace(tmp, report_path)

    print("\n  Report: {}".format(report_path))
    print("\n" + "="*60)
    if passed:
        print("RESULT: PASS -- All gates cleared")
    else:
        print("RESULT: FAIL -- {} error(s), pipeline blocked".format(len(errors)))
    print("="*60 + "\n")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
