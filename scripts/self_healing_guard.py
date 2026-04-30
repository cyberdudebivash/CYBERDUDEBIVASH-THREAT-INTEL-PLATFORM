#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL APEX — Phase 8: Self-Healing Guard
===========================================
Detects and auto-repairs data corruption without human intervention:

  1. Validates api/feed.json + feed_manifest.json integrity
  2. On corruption: restores last known-good backup
  3. Rebuilds api/feed.json from manifest if backup unavailable
  4. Re-validates after repair
  5. Writes data/audit/self_heal_report.json
  6. Returns exit 0 on healthy/healed, exit 2 on unrecoverable

Designed to run:
  - As a pre-flight step before every pipeline run
  - As a GitHub Actions cron check
  - Manually via: python scripts/self_healing_guard.py

Usage:
    python scripts/self_healing_guard.py [--repo-root .] [--dry-run]
"""

import os, sys, json, re, shutil, hashlib, argparse
from datetime import datetime, timezone

SCRIPT_VERSION = "1.0.0"
BACKUP_DIR     = os.path.join("data", "audit", "backups")
CHECKSUM_FILE  = os.path.join("data", "audit", "feed_checksums.json")
HEAL_REPORT    = os.path.join("data", "audit", "self_heal_report.json")
API_FEED_CAP   = 500
UTF8_BOM       = b"\xef\xbb\xbf"

MOJIBAKE_PATTERNS = [
    b"\xc3\x82\xc2\xae", b"\xc3\x82\xc2\xa9", b"\xc3\x82\xc2\xb7",
    b"\xc3\x83\xc2\xa9", b"\xc3\x83\xc2\xa8", b"\xc3\x82\xc2\xa0",
]


# ────────────────────────────────────────────────────────────
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def ts_key(e):
    for f in ("published", "last_modified", "timestamp", "created"):
        v = e.get(f, "")
        if v: return str(v)
    return ""

def load_json_safe(path):
    """Returns (data, error). data=None on error."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        raw.decode("utf-8")          # validate UTF-8
        return json.loads(raw), None
    except Exception as e:
        return None, str(e)

def unwrap(data, label):
    if isinstance(data, list): return data
    for k in ("entries","items","intel","data","objects"):
        if k in data and isinstance(data[k], list): return data[k]
    return []


# ────────────────────────────────────────────────────────────
def is_healthy(path, label, cap=None):
    """Quick integrity check. Returns (ok:bool, reason:str)."""
    if not os.path.exists(path):
        return False, f"MISSING: {path}"
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception as e:
        return False, f"READ ERROR: {e}"

    if raw[:3] == UTF8_BOM:
        return False, "UTF-8 BOM present"
    if b"\x00" in raw:
        return False, "Null bytes present"
    for pat in MOJIBAKE_PATTERNS:
        if pat in raw[:65536]:
            return False, f"Mojibake: {pat.hex()}"

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return False, f"JSON invalid: {e}"

    entries = unwrap(data, label)
    if not entries:
        return False, "Zero entries"
    if cap and len(entries) > cap:
        return False, f"Entry count {len(entries)} exceeds cap {cap}"

    # Duplicate check
    ids = [e.get("stix_id") or e.get("id","") for e in entries]
    if len(ids) != len(set(ids)):
        dup_count = len(ids) - len(set(ids))
        return False, f"{dup_count} duplicate stix_ids"

    return True, "OK"


# ────────────────────────────────────────────────────────────
def find_latest_backup(backup_dir, fragment):
    """Return path to most recent backup matching fragment."""
    if not os.path.isdir(backup_dir):
        return None
    candidates = sorted(
        [f for f in os.listdir(backup_dir) if fragment in f and f.endswith(".bak")],
        reverse=True
    )
    return os.path.join(backup_dir, candidates[0]) if candidates else None


def save_backup(src, backup_dir, dry_run=False):
    """Backup a file with timestamp tag."""
    if dry_run:
        return None
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = os.path.basename(src).replace("/", "_")
    dst = os.path.join(backup_dir, f"{fname}_{ts}.bak")
    shutil.copy2(src, dst)
    return dst


def rebuild_api_feed(repo_root, dry_run=False):
    """Rebuild api/feed.json from feed_manifest.json."""
    manifest_path = os.path.join(repo_root, "data", "stix", "feed_manifest.json")
    api_path      = os.path.join(repo_root, "api", "feed.json")

    data, err = load_json_safe(manifest_path)
    if err or data is None:
        return False, f"Cannot load manifest: {err}"

    entries = unwrap(data, "feed_manifest.json")
    if not entries:
        return False, "Manifest has no entries"

    # Sort descending by timestamp
    entries_sorted = sorted(entries, key=ts_key, reverse=True)

    # Deduplicate
    seen = {}
    deduped = []
    for e in entries_sorted:
        eid = e.get("stix_id") or e.get("id", "")
        if eid not in seen:
            seen[eid] = True
            deduped.append(e)

    # Cap at 500
    output = deduped[:API_FEED_CAP]

    if not dry_run:
        os.makedirs(os.path.dirname(api_path), exist_ok=True)
        tmp = api_path + ".heal_tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, api_path)

    return True, f"Rebuilt {len(output)} entries from manifest ({len(deduped)} deduped)"


# ────────────────────────────────────────────────────────────
def update_checksums(repo_root, checksums, dry_run=False):
    cs_path = os.path.join(repo_root, CHECKSUM_FILE)
    if not dry_run:
        os.makedirs(os.path.dirname(cs_path), exist_ok=True)
        existing = {}
        if os.path.exists(cs_path):
            try:
                with open(cs_path) as f:
                    existing = json.load(f)
            except Exception:
                pass
        existing.update(checksums)
        existing["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(cs_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)


# ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SENTINEL APEX Self-Healing Guard v" + SCRIPT_VERSION)
    ap.add_argument("--repo-root", default=".", help="Repository root")
    ap.add_argument("--dry-run",   action="store_true", help="Check only, no writes")
    ap.add_argument("--report",    default="", help="Custom report path")
    args = ap.parse_args()

    repo_root   = os.path.abspath(args.repo_root)
    backup_dir  = os.path.join(repo_root, BACKUP_DIR)
    report_path = os.path.join(repo_root, args.report if args.report else HEAL_REPORT)

    print(f"\n{'='*60}")
    print(f"SENTINEL APEX — SELF-HEALING GUARD v{SCRIPT_VERSION}")
    print(f"{'='*60}")
    if args.dry_run:
        print("  [DRY RUN — no writes]")
    print(f"  Repo: {repo_root}\n")

    heals    = []
    failures = []
    final_status = "HEALTHY"

    TARGETS = [
        ("api/feed.json",                   "api_feed.json",                  API_FEED_CAP),
        ("data/stix/feed_manifest.json",    "data_stix_feed_manifest.json",   None),
    ]

    for rel_path, backup_frag, cap in TARGETS:
        abs_path = os.path.join(repo_root, rel_path)
        ok, reason = is_healthy(abs_path, rel_path, cap=cap)
        print(f"  [{'OK' if ok else 'FAIL'}] {rel_path}: {reason}")

        if ok:
            # Save a fresh baseline backup
            save_backup(abs_path, backup_dir, dry_run=args.dry_run)
            continue

        # ── File is corrupt / missing — attempt healing ──
        final_status = "HEALED"
        print(f"  [HEAL] Attempting recovery for {rel_path} …")

        # Strategy 1: Restore from backup
        backup_path = find_latest_backup(backup_dir, backup_frag)
        if backup_path:
            backup_ok, backup_reason = is_healthy(backup_path, f"backup:{os.path.basename(backup_path)}", cap=cap)
            if backup_ok:
                if not args.dry_run:
                    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
                    shutil.copy2(backup_path, abs_path)
                heals.append({
                    "file": rel_path, "method": "backup_restore",
                    "backup": os.path.basename(backup_path),
                    "original_reason": reason
                })
                print(f"  [HEALED] Restored from {os.path.basename(backup_path)}")
                continue
            else:
                print(f"  [WARN] Backup also corrupt ({backup_reason}) — trying rebuild …")

        # Strategy 2: Rebuild api/feed.json from manifest
        if rel_path == "api/feed.json":
            success, msg = rebuild_api_feed(repo_root, dry_run=args.dry_run)
            if success:
                # Re-validate rebuilt file
                ok2, reason2 = is_healthy(abs_path, rel_path, cap=cap)
                if ok2:
                    heals.append({
                        "file": rel_path, "method": "rebuild_from_manifest",
                        "detail": msg, "original_reason": reason
                    })
                    print(f"  [HEALED] Rebuilt: {msg}")
                    save_backup(abs_path, backup_dir, dry_run=args.dry_run)
                    continue
                else:
                    print(f"  [FAIL] Rebuild produced invalid file: {reason2}")
            else:
                print(f"  [FAIL] Rebuild failed: {msg}")

        # Unrecoverable
        final_status = "UNRECOVERABLE"
        failures.append({"file": rel_path, "reason": reason})
        print(f"  [UNRECOVERABLE] {rel_path}: manual intervention required")

    # ── Update checksums ────────────────────────────────────
    checksums = {}
    for rel_path, _, _ in TARGETS:
        abs_path = os.path.join(repo_root, rel_path)
        if os.path.exists(abs_path):
            checksums[rel_path] = sha256(abs_path)
    update_checksums(repo_root, checksums, dry_run=args.dry_run)

    # ── Write report ─────────────────────────────────────────
    report = {
        "script":      "self_healing_guard",
        "version":     SCRIPT_VERSION,
        "status":      final_status,
        "heals":       heals,
        "failures":    failures,
        "checksums":   checksums,
        "dry_run":     args.dry_run,
        "checked_at":  datetime.now(timezone.utc).isoformat(),
    }
    if not args.dry_run:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  Report: {report_path}")

    print(f"\n{'='*60}")
    if final_status == "HEALTHY":
        print(f"RESULT: HEALTHY — All data files intact")
        exit_code = 0
    elif final_status == "HEALED":
        print(f"RESULT: HEALED — {len(heals)} file(s) auto-repaired")
        exit_code = 0
    else:
        print(f"RESULT: UNRECOVERABLE — {len(failures)} file(s) need manual repair")
        exit_code = 2
    print(f"{'='*60}\n")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
