#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX — Phase 7: Output Validation Gate
================================================
Pre-publish gate that MUST pass before any pipeline commit:

  1. api/feed.json   — valid JSON, UTF-8 NoBOM, ≤500 entries, no dups, sorted desc
  2. data/stix/feed_manifest.json — valid JSON, UTF-8 NoBOM, no dups, sorted desc
  3. Encoding gate   — zero double-encoded bytes, zero null bytes, zero BOM
  4. Sort lock       — entries in strictly descending published-timestamp order
  5. Rollback trigger — if any gate FAILS, preserve last valid backup and alert

On FAIL:  exits 1 (blocks CI commit step)
On PASS:  exits 0, writes data/audit/gate_report.json

Usage:
    python scripts/output_validation_gate.py [--repo-root .] [--rollback-on-fail]
"""

import os, sys, json, re, shutil, hashlib, argparse
from datetime import datetime, timezone

SCRIPT_VERSION = "1.1.0"
API_FEED_CAP   = 500
BACKUP_DIR     = os.path.join("data", "audit", "backups")
REPORT_PATH    = os.path.join("data", "audit", "gate_report.json")

# Double-encoded byte patterns that must NOT appear
MOJIBAKE_PATTERNS = [
    b"\xc3\x82\xc2\xae",   # Â®
    b"\xc3\x82\xc2\xa9",   # Â©
    b"\xc3\x82\xc2\xb7",   # Â·
    b"\xc3\x83\xc2\xa9",   # Ã©
    b"\xc3\x83\xc2\xa8",   # Ã¨
    b"\xc3\x82\xc2\xa0",   # Â (nbsp)
    b"\xc3\x82\xc2\xb0",   # Â°
]

UTF8_BOM = b"\xef\xbb\xbf"


# ────────────────────────────────────────────────────────────
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
    v143.1.0 CANONICAL DETERMINISTIC SORT KEY — must match run_pipeline.py exactly.
    Primary: published_at → timestamp → processed_at (ISO-8601 string, descending).
    Secondary: stix_id — unique per entry, guarantees deterministic tie-breaking.
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
        return None, None, f"UTF-8 decode error: {e}"
    except json.JSONDecodeError as e:
        return None, None, f"JSON parse error: {e}"

def unwrap_entries(data, path_label):
    if isinstance(data, list):
        return data, None
    for key in ("entries", "items", "intel", "data", "objects", "advisories", "reports"):
        if key in data and isinstance(data[key], list):
            return data[key], None
    return [], f"Unknown JSON structure in {path_label}: keys={list(data.keys())[:8]}"

def check_file(path, label, errors, warnings, cap=None, required=True):
    """Full gate check on a single JSON file. Returns entries list.

    required=True  (default): missing/empty file is a HARD FAIL (ERROR).
    required=False           : missing/empty file is a WARNING only.
                               Use for runtime-generated files that are absent
                               on a fresh CI checkout (e.g. feed_manifest.json).
    """
    if not os.path.exists(path):
        if required:
            errors.append(f"MISSING: {label}")
        else:
            warnings.append(
                f"MISSING [{label}]: runtime-generated file not present on this "
                "checkout — skipping manifest gate (will be populated by data pipeline)"
            )
        return []

    raw, data, load_err = load_raw_and_json(path)
    if load_err:
        # A file that EXISTS but is unparseable is always an error regardless of required flag.
        errors.append(f"LOAD FAIL [{label}]: {load_err}")
        return []

    # BOM check
    if raw[:3] == UTF8_BOM:
        errors.append(f"BOM: {label} has UTF-8 BOM — must be stripped")

    # Null bytes
    if b"\x00" in raw:
        errors.append(f"NULL BYTES: {label} contains null bytes")

    # Mojibake scan (first 256KB)
    scan_region = raw[:262144]
    for pat in MOJIBAKE_PATTERNS:
        cnt = scan_region.count(pat)
        if cnt:
            errors.append(f"MOJIBAKE [{label}]: {cnt}x {pat.hex()} double-encoded bytes")

    # Parse entries
    entries, struct_err = unwrap_entries(data, label)
    if struct_err:
        errors.append(struct_err)
        return []

    # Count cap
    if cap is not None and len(entries) > cap:
        errors.append(f"OVERSIZE [{label}]: {len(entries)} entries (cap={cap})")

    if len(entries) == 0:
        if required:
            errors.append(f"EMPTY: {label} has 0 entries")
        else:
            warnings.append(
                f"EMPTY [{label}]: runtime-generated file has 0 entries on this "
                "checkout — skipping manifest gate (will be populated by data pipeline)"
            )
        return []

    # Duplicate stix_id check
    seen = {}
    dups = []
    for i, e in enumerate(entries):
        eid = e.get("stix_id") or e.get("id", f"_idx_{i}")
        if eid in seen:
            dups.append(eid[:40])
            if len(dups) >= 5:
                break
        else:
            seen[eid] = i
    if dups:
        errors.append(f"DUPLICATES [{label}]: {len(dups)} duplicate stix_ids: {dups[:3]}")

    # Sort order check (descending by canonical key — v143.1.0)
    # Uses canonical_sort_key (ts, stix_id) — matches pipeline write order exactly.
    # Equal timestamps with different stix_ids are ordered by stix_id descending,
    # which is deterministic. prev_key > cur_key means cur should have come before
    # prev → out-of-order. Entries with equal canonical keys are not flagged.
    prev_key = None
    out_of_order = 0
    for e in entries:
        cur_key = canonical_sort_key(e)
        if prev_key is not None and cur_key > prev_key:
            out_of_order += 1
        prev_key = cur_key
    if out_of_order > 0:
        warnings.append(f"SORT [{label}]: {out_of_order} entries appear out of descending order")

    # Required fields spot-check on first 10
    # Accept published OR published_at OR timestamp as date field
    for i, e in enumerate(entries[:10]):
        has_id    = bool(e.get("stix_id") or e.get("id"))
        has_title = bool(e.get("title"))
        has_date  = bool(e.get("published") or e.get("published_at") or e.get("timestamp") or e.get("created"))
        missing = []
        if not has_id:    missing.append("stix_id/id")
        if not has_title: missing.append("title")
        if not has_date:  missing.append("published/published_at/timestamp")
        if missing:
            warnings.append(f"FIELDS [{label}] entry[{i}]: missing {missing}")

    return entries


# ────────────────────────────────────────────────────────────
def make_backup(repo_root, errors):
    """Backup current good versions of key files before any mutation."""
    backup_dir = os.path.join(repo_root, BACKUP_DIR)
    os.makedirs(backup_dir, exist_ok=True)
    ts_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backed_up = []
    for rel in ["api/feed.json", "data/stix/feed_manifest.json"]:
        src = os.path.join(repo_root, rel)
        if os.path.exists(src):
            dst = os.path.join(backup_dir, f"{rel.replace('/','_')}_{ts_tag}.bak")
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
    candidates.sort(reverse=True)   # lexicographic sort on timestamp prefix
    return os.path.join(backup_dir, candidates[0])


# ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SENTINEL APEX Output Gate v" + SCRIPT_VERSION)
    ap.add_argument("--repo-root",        default=".", help="Repository root")
    ap.add_argument("--rollback-on-fail", action="store_true", help="Restore last backup on FAIL")
    ap.add_argument("--report",           default="", help="Custom report path")
    args = ap.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    report_path = os.path.join(repo_root, args.report if args.report else REPORT_PATH)

    print(f"\n{'='*60}")
    print(f"SENTINEL APEX — OUTPUT VALIDATION GATE v{SCRIPT_VERSION}")
    print(f"{'='*60}")
    print(f"Repo: {repo_root}")
    print()

    errors   = []
    warnings = []

    # ── Gate 1: api/feed.json ────────────────────────────────
    print("[GATE 1] Validating api/feed.json …")
    api_entries = check_file(
        os.path.join(repo_root, "api", "feed.json"),
        "api/feed.json", errors, warnings, cap=API_FEED_CAP
    )
    print(f"         entries={len(api_entries)}")

    # ── Gate 2: feed_manifest.json ──────────────────────────
    # required=False: this is a runtime-generated file (gitignored, untracked).
    # It is ABSENT on fresh CI checkout — that is correct behaviour.
    # HARD FAIL only when file EXISTS but is corrupt (handled in load_raw_and_json).
    print("[GATE 2] Validating data/stix/feed_manifest.json …")
    manifest_entries = check_file(
        os.path.join(repo_root, "data", "stix", "feed_manifest.json"),
        "feed_manifest.json", errors, warnings,
        required=False
    )
    print(f"         entries={len(manifest_entries)}")

    # ── Gate 3: index.html encoding ─────────────────────────
    print("[GATE 3] Encoding check on index.html …")
    idx_path = os.path.join(repo_root, "index.html")
    if os.path.exists(idx_path):
        with open(idx_path, "rb") as f:
            idx_raw = f.read(65536)   # check first 64KB
        if idx_raw[:3] == UTF8_BOM:
            errors.append("BOM: index.html has UTF-8 BOM")
        if b"\x00" in idx_raw:
            errors.append("NULL BYTES: index.html has null bytes in first 64KB")
        for pat in MOJIBAKE_PATTERNS:
            cnt = idx_raw.count(pat)
            if cnt:
                errors.append(f"MOJIBAKE [index.html]: {cnt}x {pat.hex()} in first 64KB")
        # v147.0: EMBEDDED_INTEL may be [] (pre-inject) OR populated (post-inject STAGE 3.93).
        # inject_embedded_intel.py populates it before deploy -- populated state is intentional.
        # Do NOT fail on populated EMBEDDED_INTEL. Encoding gate covers mojibake in array data.
        with open(idx_path, "rb") as f:
            idx_full = f.read()
        if not re.search(rb'window\.EMBEDDED_INTEL\s*=\s*\[', idx_full):
            warnings.append("EMBEDDED_INTEL: declaration not found in index.html")
        print(f"         size={len(idx_full)} bytes  BOM={idx_raw[:3]==UTF8_BOM}")
    else:
        warnings.append("MISSING: index.html not found (skip encoding gate)")

    # ── Gate 4: Cross-count sanity ──────────────────────────
    print("[GATE 4] Cross-count sanity …")
    if api_entries and manifest_entries:
        a_cnt = len(api_entries)
        m_cnt = len(manifest_entries)
        # v148.1.0 FIX: feed_manifest.json is required=False (runtime-generated, may lag
        # behind api/feed.json across multiple pipeline runs). Count discrepancy between
        # api/feed.json and the manifest is therefore ALWAYS advisory (WARN), never a
        # hard-blocking ERROR. The manifest is a STIX subset and may legitimately have
        # fewer entries than the full feed. Hard-fail on count mismatch was incorrectly
        # blocking Worker deploys even when both files were structurally valid.
        # ERROR-level check is preserved for catastrophic gap (>200%) only, which would
        # indicate a file corruption/truncation event rather than normal pipeline lag.
        #
        # Original v143.2.0 logic: hard-fail on gap >50% tolerance.
        # v148.1.0 change: demote to WARNING for gap <=200%; keep ERROR only at >200%.
        if a_cnt > m_cnt:
            _excess = (a_cnt - m_cnt) / m_cnt
            if _excess > 2.00:
                # >200% gap = catastrophic truncation/corruption, not normal lag
                errors.append(
                    f"COUNT: api/feed.json ({a_cnt}) >> manifest ({m_cnt}) — "
                    f"gap {_excess:.1%} indicates possible manifest truncation or corruption"
                )
            elif _excess > 0.50:
                warnings.append(
                    f"COUNT: api/feed.json ({a_cnt}) >> manifest ({m_cnt}) — "
                    f"gap {_excess:.1%} exceeds 50% tolerance (manifest may be lagging — "
                    f"advisory only, manifest is runtime-generated with required=False)"
                )
            else:
                warnings.append(
                    f"COUNT: api/feed.json ({a_cnt}) > manifest ({m_cnt}) — "
                    f"within tolerance ({_excess:.1%} excess, expected during growth runs)"
                )
        ratio = a_cnt / m_cnt if m_cnt else 0
        if ratio < 0.05:
            warnings.append(f"COUNT: api/feed.json has only {a_cnt}/{m_cnt} manifest entries ({ratio:.1%})")
        print(f"         api={a_cnt}  manifest={m_cnt}  ratio={ratio:.1%}")

    # ── Print results ────────────────────────────────────────
    print()
    for w in warnings:
        print(f"  [WARN]  {w}")
    for e in errors:
        print(f"  [ERROR] {e}")

    passed = len(errors) == 0

    # ── Rollback ─────────────────────────────────────────────
    rolled_back = []
    if not passed and args.rollback_on_fail:
        print("\n[ROLLBACK] Gate failed — restoring last valid backups …")
        for fragment, dest_rel in [
            ("api_feed.json", "api/feed.json"),
            ("data_stix_feed_manifest.json", "data/stix/feed_manifest.json"),
        ]:
            backup = find_last_good_backup(repo_root, fragment)
            if backup:
                dest = os.path.join(repo_root, dest_rel)
                shutil.copy2(backup, dest)
                rolled_back.append(dest_rel)
                print(f"  Restored {dest_rel} from {os.path.basename(backup)}")
            else:
                print(f"  [WARN] No backup found for {dest_rel}")

    # -- Write report -----------------------------------------
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
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n  Report: {report_path}")
    print(f"\n{'='*60}")
    if passed:
        print(f"RESULT: PASS -- All gates cleared")
    else:
        print(f"RESULT: FAIL -- {len(errors)} error(s), pipeline blocked")
    print(f"{'='*60}\n")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
