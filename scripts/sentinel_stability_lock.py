#!/usr/bin/env python3
"""
scripts/sentinel_stability_lock.py
CYBERDUDEBIVASH(R) SENTINEL APEX v142.3.0 -- Permanent Stability Lock
=====================================================================
Six enforcement phases:
  Phase 1  Final Output Contract   dedup + sort + future-date guard
  Phase 2  Version Lock            config/version.json = single SSOT
  Phase 3  Post-Pipeline Validator manifest/API/feed triple-sync check
  Phase 4  Atomic Write + Checksum SHA-256 guard on every write
  Phase 5  UI Consistency Check    verify index.html render guards present
  Phase 6  Self-Healing            rollback manifest + rebuild feed on corruption

Public API (called from run_pipeline.py):
  validate_version_lock(repo_root, pipeline_version)  -> ViolationReport (Phase 2)
  enforce_output_contract(entries, repo_root)          -> list (Phase 1+4)
  run_post_pipeline_validation(repo_root)              -> ViolationReport (Phase 3+5+6)
  create_manifest_backup(repo_root)                    -> bool (Phase 6 prerequisite)

(c) 2026 CyberDudeBivash Pvt. Ltd.  CONFIDENTIAL. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("sentinel_stability_lock")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[SSL] %(levelname)s %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)

_SCHEMA_VERSION  = "v142.3.0"
_MANIFEST_PATH   = Path("data/stix/feed_manifest.json")
_FEED_PATHS      = [Path("feed.json"), Path("api/feed.json")]
_VERSION_PATH    = Path("config/version.json")
_BACKUP_SUFFIX   = ".ssl_backup"
_CHECKSUM_PATH   = Path("data/audit/feed_checksums.json")
_REPORT_PATH     = Path("data/audit/stability_report.json")
_PIPELINE_FEED_CAP = 500   # run_pipeline.py: out_count = min(len(manifest_items), 500)


@dataclass
class ViolationReport:
    phase:              str
    violations:         list = field(default_factory=list)
    fixes_applied:      list = field(default_factory=list)
    health:             str  = "PASS"
    entries_before:     int  = 0
    entries_after:      int  = 0
    duplicates_removed: int  = 0
    metadata:           dict = field(default_factory=dict)

    def add_violation(self, msg, *, fatal=False):
        self.violations.append(msg)
        self.health = "FAIL" if fatal else "WARN"
        log.warning("[%s] VIOLATION: %s", self.phase, msg)

    def add_fix(self, msg):
        self.fixes_applied.append(msg)
        log.info("[%s] FIX: %s", self.phase, msg)

    def to_dict(self):
        return {
            "phase":              self.phase,
            "schema_version":     _SCHEMA_VERSION,
            "generated_at":       _utc_now(),
            "health":             self.health,
            "violations":         self.violations,
            "fixes_applied":      self.fixes_applied,
            "entries_before":     self.entries_before,
            "entries_after":      self.entries_after,
            "duplicates_removed": self.duplicates_removed,
            "metadata":           self.metadata,
        }


def _utc_now():
    return datetime.now(timezone.utc).isoformat()

def _utc_ts():
    return time.time()

def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def _write_atomic(path, obj, *, validate=True):
    serialised = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    if validate:
        json.loads(serialised)
    tmp = Path(str(path) + ".ssl.tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(serialised, encoding="utf-8")
    if validate:
        json.loads(tmp.read_text(encoding="utf-8"))
    os.replace(str(tmp), str(path))
    return _sha256(serialised)

def _get_ts(entry):
    """
    v143.1.0 CANONICAL DETERMINISTIC SORT KEY — must match run_pipeline.py exactly.

    Returns (float_ts, stix_id) composite tuple.
    Primary  : ISO-8601 timestamp converted to float seconds (descending).
    Secondary: stix_id string (descending) — unique per entry, guarantees
               deterministic tie-breaking when entries share the same timestamp.

    PREVIOUS BUG: returned only float_ts with no secondary key.
    Multiple entries with the same timestamp received the same sort key,
    so Python's stable sort preserved their insertion order — which varied
    between the manifest (not pre-sorted) and api/feed.json (pipeline-sorted).
    This caused ORDER MISMATCH / MISSING IN API in the CI contract validator.

    The (float_ts, stix_id) tuple is consistent with run_pipeline.py sort_key()
    which uses (ts_string, stix_id). Since ISO-8601 strings are monotone in
    lexicographic order, both keys produce the same primary sort order.
    The stix_id secondary key is identical in both, so tie-breaking matches.
    """
    for key in ("published_at", "timestamp", "processed_at", "generated_at"):
        val = entry.get(key)
        if val and isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                sid = entry.get("stix_id") or entry.get("id") or ""
                return (dt.timestamp(), sid)
            except Exception:
                pass
    sid = entry.get("stix_id") or entry.get("id") or ""
    return (0.0, sid)

def _parse_ts(val):
    if not val:
        return None
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


# ============================================================================
# PHASE 1 -- FINAL OUTPUT CONTRACT
# ============================================================================

def enforce_output_contract(entries, repo_root, *, strict=True):
    """Phase 1: Enforce Final Output Contract before any feed.json write."""
    report = ViolationReport(phase="Phase1_OutputContract")
    report.entries_before = len(entries)
    now_ts = _utc_ts()

    if not isinstance(entries, list):
        report.add_violation(f"entries is {type(entries).__name__}, expected list", fatal=True)
        return [], report

    # 1a. Dedup by stix_id
    seen_ids = set()
    unique = []
    dup_ids = 0
    for e in entries:
        sid = e.get("stix_id") or e.get("id", "")
        if sid and sid in seen_ids:
            dup_ids += 1
            continue
        if sid:
            seen_ids.add(sid)
        unique.append(e)
    if dup_ids:
        report.add_violation(f"Duplicate stix_id: {dup_ids} entries removed")
        report.add_fix(f"Deduped by stix_id: {len(entries)} -> {len(unique)}")
    entries = unique

    # 1b. Dedup by title (case-insensitive)
    seen_titles = set()
    unique2 = []
    dup_titles = 0
    for e in entries:
        title_key = (e.get("title") or "").strip().lower()
        if title_key and title_key in seen_titles:
            dup_titles += 1
            continue
        if title_key:
            seen_titles.add(title_key)
        unique2.append(e)
    if dup_titles:
        report.add_violation(f"Duplicate title: {dup_titles} entries removed")
        report.add_fix(f"Deduped by title: {len(entries)} -> {len(unique2)}")
    entries = unique2

    report.duplicates_removed = dup_ids + dup_titles

    # 1c. Future-date guard (5-min grace window for clock skew)
    future_grace = 300
    future_ids = []
    valid = []
    for e in entries:
        pa = e.get("published_at") or e.get("timestamp")
        ts = _parse_ts(pa)
        if ts is not None and ts > (now_ts + future_grace):
            fid = e.get("stix_id", "unknown")
            future_ids.append(fid)
            e = {**e, "published_at": _utc_now()}
            report.add_fix(f"Future-dated entry clamped: {fid}")
        valid.append(e)
    if future_ids:
        report.add_violation(
            f"{len(future_ids)} future-dated entries clamped to UTC now: {future_ids[:5]}"
        )
    entries = valid

    # 1d. Sort by published_at DESC
    try:
        entries.sort(key=_get_ts, reverse=True)
        report.add_fix("Sorted by published_at DESC")
    except Exception as e:
        report.add_violation(f"Sort failed: {e}")

    # 1e. Final assertions
    final_ids = [e.get("stix_id") for e in entries if e.get("stix_id")]
    if len(final_ids) != len(set(final_ids)):
        report.add_violation("ASSERTION FAILED: duplicate stix_ids remain after dedup", fatal=True)
        if strict:
            raise ValueError("[SSL Phase1] Duplicate stix_ids remain -- aborting write")

    final_titles = [(e.get("title") or "").strip().lower() for e in entries if e.get("title")]
    if len(final_titles) != len(set(final_titles)):
        report.add_violation("ASSERTION FAILED: duplicate titles remain after dedup", fatal=True)
        if strict:
            raise ValueError("[SSL Phase1] Duplicate titles remain -- aborting write")

    report.entries_after = len(entries)
    if not report.violations:
        log.info("[Phase1] Output contract satisfied: %d entries, %d dups removed",
                 len(entries), report.duplicates_removed)
    return entries, report


# ============================================================================
# PHASE 2 -- VERSION LOCK
# ============================================================================

def validate_version_lock(repo_root, pipeline_version, *, hard_fail=False):
    """Phase 2: Validate config/version.json is the SSOT for all components."""
    report = ViolationReport(phase="Phase2_VersionLock")
    version_file = repo_root / _VERSION_PATH

    if not version_file.exists():
        report.add_violation(f"config/version.json not found", fatal=True)
        _maybe_fail(report, hard_fail, "config/version.json missing")
        return report

    try:
        vcfg = json.loads(version_file.read_text(encoding="utf-8"))
    except Exception as e:
        report.add_violation(f"config/version.json parse error: {e}", fatal=True)
        _maybe_fail(report, hard_fail, "version.json parse failure")
        return report

    ssot_version = vcfg.get("version", "").strip()
    report.metadata["ssot_version"] = ssot_version
    report.metadata["pipeline_version"] = pipeline_version

    if not ssot_version:
        report.add_violation("config/version.json missing 'version' key", fatal=True)
        _maybe_fail(report, hard_fail, "version key absent")
        return report

    # PIPELINE_VERSION vs SSOT
    if pipeline_version and pipeline_version != ssot_version:
        report.add_violation(
            f"PIPELINE_VERSION mismatch: env='{pipeline_version}' vs config='{ssot_version}'"
        )
    else:
        log.info("[Phase2] PIPELINE_VERSION=%s matches config/version.json", ssot_version)

    # wrangler.toml GATEWAY_VERSION
    wrangler_path = repo_root / "workers" / "intel-gateway" / "wrangler.toml"
    if wrangler_path.exists():
        import re
        m = re.search(r'GATEWAY_VERSION\s*=\s*["\']([^"\']+)["\']',
                      wrangler_path.read_text(encoding="utf-8"))
        if m:
            wv = m.group(1).strip()
            report.metadata["wrangler_version"] = wv
            if wv != ssot_version:
                report.add_violation(f"wrangler.toml GATEWAY_VERSION='{wv}' != SSOT='{ssot_version}'")
            else:
                log.info("[Phase2] wrangler.toml GATEWAY_VERSION=%s", wv)

    # index.html PLATFORM_VERSION (read first 600k chars)
    index_path = repo_root / "index.html"
    if index_path.exists():
        import re
        with open(index_path, encoding="utf-8", errors="replace") as fh:
            chunk = fh.read(600000)
        m2 = re.search(r"const PLATFORM_VERSION\s*=\s*['\"]([^'\"]+)['\"];", chunk)
        if m2:
            uv = m2.group(1).strip()
            report.metadata["ui_platform_version"] = uv
            if uv != ssot_version:
                report.add_violation(f"index.html PLATFORM_VERSION='{uv}' != SSOT='{ssot_version}'")
            else:
                log.info("[Phase2] index.html PLATFORM_VERSION=%s", uv)

    if not report.violations:
        report.health = "PASS"
        log.info("[Phase2] Version lock: ALL components at %s", ssot_version)
    elif report.health != "FAIL":
        report.health = "WARN"
    return report


# ============================================================================
# PHASE 3 -- POST-PIPELINE VALIDATOR  (+ Phase 5 check + Phase 6 self-heal)
# ============================================================================

def run_post_pipeline_validation(repo_root):
    """Phase 3+5+6: Validate after all pipeline stages complete."""
    report = ViolationReport(phase="Phase3_PostPipelineValidator")
    manifest_path = repo_root / _MANIFEST_PATH

    # 3a. Manifest existence + parse
    if not manifest_path.exists():
        report.add_violation("feed_manifest.json not found", fatal=True)
        _run_phase6_selfheal(repo_root, report, reason="manifest_missing")
        return _finalize_report(report, repo_root)

    try:
        manifest_raw  = manifest_path.read_text(encoding="utf-8")
        manifest_data = json.loads(manifest_raw)
        if isinstance(manifest_data, dict):
            manifest_entries = next(
                (manifest_data[k] for k in ("advisories", "reports", "items")
                 if k in manifest_data and isinstance(manifest_data[k], list)),
                []
            )
        elif isinstance(manifest_data, list):
            manifest_entries = manifest_data
        else:
            manifest_entries = []
    except Exception as e:
        report.add_violation(f"feed_manifest.json parse error: {e}", fatal=True)
        _run_phase6_selfheal(repo_root, report, reason="manifest_corrupt")
        return _finalize_report(report, repo_root)

    manifest_count = len(manifest_entries)
    report.metadata["manifest_count"] = manifest_count
    log.info("[Phase3] Manifest: %d entries", manifest_count)

    if manifest_count == 0:
        report.add_violation("feed_manifest.json is empty (0 entries)", fatal=True)
        _run_phase6_selfheal(repo_root, report, reason="manifest_empty")
        return _finalize_report(report, repo_root)

    # 3b. Delta detection (v166.2 — hard-fail on >30% shrink, quarantine audit)
    prev_count = _load_prev_manifest_count(repo_root)
    if prev_count is not None:
        delta = manifest_count - prev_count
        report.metadata.update({"prev_manifest_count": prev_count, "delta_entries": delta})
        if delta < 0:
            drop_pct = abs(delta) / prev_count if prev_count > 0 else 0
            report.metadata["drop_pct"] = round(drop_pct * 100, 1)
            if drop_pct > 0.30:
                report.health = "FAIL"
                report.add_violation(
                    f"[HARD-FAIL] Manifest SHRANK >{int(drop_pct*100)}%: "
                    f"{prev_count} -> {manifest_count} ({abs(delta)} entries lost). "
                    f"Exceeds 30% drop threshold. Check quarantine log."
                )
                log.error(
                    "[Phase3] HARD FAIL: manifest dropped %d/%d entries (%.1f%%) — exceeds 30%% threshold",
                    abs(delta), prev_count, drop_pct * 100,
                )
            else:
                report.add_violation(
                    f"Manifest SHRANK: {prev_count} -> {manifest_count} ({abs(delta)} entries lost, "
                    f"{int(drop_pct*100)}% drop — within tolerance but investigate)"
                )
                log.warning(
                    "[Phase3] Manifest shrank %d -> %d (-%d entries, %.1f%%)",
                    prev_count, manifest_count, abs(delta), drop_pct * 100,
                )
            _write_shrink_audit(repo_root, prev_count, manifest_count, delta)
        else:
            log.info("[Phase3] No new entries added (manifest stable at %d)", manifest_count)
    else:
        log.info("[Phase3] First run or no previous manifest count recorded")

    # 3c. Feed file checksums + count validation
    feed_checksums = {}
    feed_counts    = {}
    for fp in [manifest_path] + [repo_root / p for p in _FEED_PATHS]:
        if not fp.exists():
            report.add_violation(f"Required feed file missing: {fp.relative_to(repo_root)}")
            continue
        try:
            content = fp.read_text(encoding="utf-8")
            parsed  = json.loads(content)
            entries = parsed if isinstance(parsed, list) else parsed.get("entries", [])
            feed_checksums[str(fp)] = _sha256(content)
            feed_counts[str(fp)]    = len(entries)
            log.info("[Phase3] %s: %d entries, SHA=%s...",
                     fp.relative_to(repo_root), len(entries), feed_checksums[str(fp)][:12])
        except Exception as e:
            report.add_violation(f"{fp.relative_to(repo_root)} parse error: {e}", fatal=True)

    # feed.json == api/feed.json
    fa, fb = str(repo_root / "feed.json"), str(repo_root / "api" / "feed.json")
    if fa in feed_counts and fb in feed_counts:
        if feed_counts[fa] != feed_counts[fb]:
            report.add_violation(
                f"feed.json ({feed_counts[fa]}) != api/feed.json ({feed_counts[fb]}) count mismatch"
            )
        else:
            log.info("[Phase3] feed.json == api/feed.json: %d entries", feed_counts[fa])

    # feed vs manifest (respects pipeline cap of 500)
    for fp in [repo_root / p for p in _FEED_PATHS]:
        key = str(fp)
        if key not in feed_counts:
            continue
        fc = feed_counts[key]
        expected_min = min(manifest_count, _PIPELINE_FEED_CAP) - 50
        if fc == 0:
            report.add_violation(f"{fp.relative_to(repo_root)}: EMPTY -- feed write failed")
        elif fc > manifest_count:
            report.add_violation(
                f"{fp.relative_to(repo_root)}: {fc} entries > manifest {manifest_count} -- impossible"
            )
        elif fc < max(expected_min, 1):
            report.add_violation(
                f"{fp.relative_to(repo_root)}: {fc} entries suspiciously low "
                f"(expected ~{min(manifest_count, _PIPELINE_FEED_CAP)}, manifest={manifest_count})"
            )
        else:
            log.info("[Phase3] %s: %d entries (cap=%d, manifest=%d)",
                     fp.relative_to(repo_root), fc, _PIPELINE_FEED_CAP, manifest_count)

    # 3d. Manifest dedup assertion
    stix_ids = [e.get("stix_id") for e in manifest_entries if e.get("stix_id")]
    if len(stix_ids) != len(set(stix_ids)):
        dup_count = len(stix_ids) - len(set(stix_ids))
        report.add_violation(
            f"Manifest: {dup_count} duplicate stix_ids -- Phase 1 will clean on next write",
            fatal=False
        )
        log.info("[Phase3] Note: Phase 1 contract enforced BEFORE write -- dups cleared each run")
    else:
        log.info("[Phase3] Manifest dedup: 0 duplicate stix_ids")

    titles = [(e.get("title") or "").strip().lower() for e in manifest_entries if e.get("title")]
    if len(titles) != len(set(titles)):
        report.add_violation(
            f"Manifest: {len(titles) - len(set(titles))} duplicate titles -- Phase 1 will clean on next write",
            fatal=False
        )

    # Phase 5: UI consistency check
    _run_phase5_ui_check(repo_root, report)

    # Persist checksums
    _save_checksums(repo_root, feed_checksums, manifest_count)

    return _finalize_report(report, repo_root)


# ============================================================================
# PHASE 4 -- ATOMIC WRITE + CHECKSUM GUARD
# ============================================================================

def atomic_write_with_checksum(path, data, *, repo_root, label=""):
    """Phase 4: Atomic write with SHA-256 checksum guard."""
    label = label or path.name
    store = _load_checksum_store(repo_root)
    path_key = str(path.relative_to(repo_root)) if repo_root in path.parents else str(path)

    if path.exists() and path_key in store:
        current_sha = _sha256(path.read_text(encoding="utf-8"))
        if store[path_key] != current_sha:
            log.warning("[Phase4] CHECKSUM MISMATCH on %s -- possible out-of-band write", label)

    try:
        new_sha = _write_atomic(path, data)
        store[path_key] = new_sha
        _save_checksum_store(repo_root, store)
        log.info("[Phase4] Atomic write OK: %s SHA=%s...", label, new_sha[:12])
        return True, new_sha
    except Exception as e:
        log.error("[Phase4] Atomic write FAILED: %s -- %s", label, e)
        return False, ""


# ============================================================================
# PHASE 5 -- UI CONSISTENCY CHECK (read-only)
# ============================================================================

def _run_phase5_ui_check(repo_root, report):
    index_path = repo_root / "index.html"
    if not index_path.exists():
        log.info("[Phase5] index.html not found -- skipping")
        return

    required_guards = [
        ("window.__INTEL_RENDERED__", "Global render lock flag v142.3.0"),
        ("window.__DATA_LOADED__",    "Global data-load lock flag v142.3.0"),
        ("container.innerHTML",       "DOM hard-clear before render"),
    ]

    # v166.2 FIX: Read full file — guards sit at ~730k bytes in current index.html;
    # the previous 700k cap caused false-positive MISSING violations every run.
    with open(index_path, encoding="utf-8", errors="replace") as fh:
        chunk = fh.read()

    missing = [g for g, _ in required_guards if g not in chunk]
    if missing:
        for mg in missing:
            report.add_violation(f"[Phase5] UI render guard MISSING: {mg}")
        report.metadata["ui_guards_missing"] = missing
    else:
        log.info("[Phase5] All UI render guards present (__INTEL_RENDERED__, __DATA_LOADED__, RENDER_LOCK)")
        report.metadata["ui_guards_ok"] = True


# ============================================================================
# PHASE 6 -- SELF-HEALING
# ============================================================================

def _run_phase6_selfheal(repo_root, report, *, reason):
    log.warning("[Phase6] SELF-HEAL triggered: reason=%s", reason)
    report.metadata.update({"selfheal_triggered": True, "selfheal_reason": reason})

    manifest_path = repo_root / _MANIFEST_PATH
    backup_path   = Path(str(manifest_path) + _BACKUP_SUFFIX)

    if backup_path.exists():
        try:
            backup_data = json.loads(backup_path.read_text(encoding="utf-8"))
            entries = backup_data if isinstance(backup_data, list) else []
            if entries:
                _write_atomic(manifest_path, entries)
                log.info("[Phase6] Manifest RESTORED from backup: %d entries", len(entries))
                report.add_fix(f"Manifest restored from backup ({len(entries)} entries)")
                for target in [repo_root / p for p in _FEED_PATHS]:
                    try:
                        _write_atomic(target, entries[:_PIPELINE_FEED_CAP])
                        report.add_fix(f"Feed rebuilt: {target.relative_to(repo_root)}")
                    except Exception as e:
                        report.add_violation(f"[Phase6] Feed rebuild failed: {target.name}: {e}")
                report.metadata["selfheal_result"] = "RESTORED"
            else:
                report.metadata["selfheal_result"] = "BACKUP_EMPTY"
        except Exception as e:
            log.error("[Phase6] Self-heal failed: %s", e)
            report.metadata["selfheal_result"] = f"ERROR: {e}"
    else:
        log.warning("[Phase6] No backup at %s -- cannot self-heal", backup_path)
        report.metadata["selfheal_result"] = "NO_BACKUP"

    log.info("[Phase6] Self-heal: %s", report.metadata.get("selfheal_result", "UNKNOWN"))


def create_manifest_backup(repo_root):
    """Phase 6 prerequisite: backup manifest before pipeline modifies it."""
    manifest_path = repo_root / _MANIFEST_PATH
    backup_path   = Path(str(manifest_path) + _BACKUP_SUFFIX)

    if not manifest_path.exists():
        log.warning("[Phase6] Cannot backup: manifest not found")
        return False
    try:
        content = manifest_path.read_text(encoding="utf-8")
        data    = json.loads(content)
        entries = data if isinstance(data, list) else data.get("advisories", data.get("reports", []))
        if not entries:
            log.info("[Phase6] Manifest empty -- skipping backup")
            return False
        backup_path.write_text(content, encoding="utf-8")
        log.info("[Phase6] Manifest backup: %d entries -> %s", len(entries), backup_path.name)
        return True
    except Exception as e:
        log.warning("[Phase6] Backup failed (non-fatal): %s", e)
        return False


# ============================================================================
# INTERNAL HELPERS
# ============================================================================


def _write_shrink_audit(repo_root, prev_count, current_count, delta):
    """Write shrink audit record to data/quarantine/shrink_audit.json (v166.2)."""
    import datetime as _dt
    audit_dir = repo_root / "data" / "quarantine"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / "shrink_audit.json"
    existing = []
    if audit_path.exists():
        try:
            existing = json.loads(audit_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except Exception:
            existing = []
    entry = {
        "timestamp": _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "prev_count": prev_count,
        "current_count": current_count,
        "lost": abs(delta),
        "drop_pct": round(abs(delta) / prev_count * 100, 1) if prev_count > 0 else 0,
        "threshold_exceeded": (abs(delta) / prev_count > 0.30) if prev_count > 0 else False,
    }
    existing.append(entry)
    audit_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    log.info("[Phase3] Shrink audit written: %s", audit_path)

def _load_checksum_store(repo_root):
    cpath = repo_root / _CHECKSUM_PATH
    if cpath.exists():
        try:
            return json.loads(cpath.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def _save_checksum_store(repo_root, store):
    cpath = repo_root / _CHECKSUM_PATH
    cpath.parent.mkdir(parents=True, exist_ok=True)
    try:
        _write_atomic(cpath, store, validate=False)
    except Exception as e:
        log.warning("[Phase4] Cannot save checksum store: %s", e)

def _load_prev_manifest_count(repo_root):
    return _load_checksum_store(repo_root).get("_manifest_count")

def _save_checksums(repo_root, checksums, manifest_count):
    store = _load_checksum_store(repo_root)
    store.update(checksums)
    store["_manifest_count"] = manifest_count
    store["_last_validated"] = _utc_now()
    _save_checksum_store(repo_root, store)

def _maybe_fail(report, hard_fail, reason):
    if hard_fail and report.health == "FAIL":
        log.critical("[SSL] HARD FAIL: %s", reason)
        raise SystemExit(1)

def _finalize_report(report, repo_root):
    if not report.violations:
        report.health = "PASS"
    report_path = repo_root / _REPORT_PATH
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        _write_atomic(report_path, report.to_dict(), validate=False)
        log.info("[SSL] Stability report: %s | health=%s | violations=%d",
                 report_path.relative_to(repo_root), report.health, len(report.violations))
    except Exception as e:
        log.warning("[SSL] Cannot write report: %s", e)
    _log_summary(report)
    return report

def _log_summary(report):
    sep = "=" * 60
    log.info(sep)
    log.info("[SSL] %s -- %s", report.phase, report.health)
    log.info("  Violations : %d", len(report.violations))
    log.info("  Fixes      : %d", len(report.fixes_applied))
    if report.entries_before or report.entries_after:
        log.info("  Entries    : %d -> %d (-%d dups)",
                 report.entries_before, report.entries_after, report.duplicates_removed)
    for v in report.violations:
        log.warning("  WARN  %s", v)
    for f in report.fixes_applied:
        log.info("  FIX   %s", f)
    log.info(sep)


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import sys, argparse

    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Stability Lock -- standalone diagnostic runner"
    )
    parser.add_argument("--repo-root", default=".", help="Path to repository root")
    parser.add_argument("--pipeline-version",
                        default=os.environ.get("PIPELINE_VERSION", "142.3.0"))
    parser.add_argument("--phase", choices=["1", "2", "3", "all"], default="all")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    print(f"SENTINEL APEX Stability Lock {_SCHEMA_VERSION}")
    print(f"Repo root : {repo_root}")
    print(f"UTC now   : {_utc_now()}")
    print()

    overall = "PASS"
    reports = []

    if args.phase in ("2", "all"):
        r = validate_version_lock(repo_root, args.pipeline_version)
        reports.append(r)
        if r.health == "FAIL":
            overall = "FAIL"
        elif r.health == "WARN" and overall == "PASS":
            overall = "WARN"

    if args.phase in ("1", "all"):
        mp = repo_root / _MANIFEST_PATH
        if mp.exists():
            try:
                raw = json.loads(mp.read_text(encoding="utf-8"))
                entries = raw if isinstance(raw, list) else []
                clean, r1 = enforce_output_contract(entries, repo_root, strict=False)
                reports.append(r1)
                print(f"Phase 1: {r1.health} | {r1.entries_before}->{r1.entries_after} entries | {r1.duplicates_removed} dups removed")
                if r1.health == "FAIL":
                    overall = "FAIL"
                elif r1.health == "WARN" and overall == "PASS":
                    overall = "WARN"
            except Exception as e:
                print(f"Phase 1 ERROR: {e}")
                overall = "FAIL"
        else:
            print(f"Phase 1: SKIP (manifest not found)")

    if args.phase in ("3", "all"):
        r = run_post_pipeline_validation(repo_root)
        reports.append(r)
        if r.health == "FAIL":
            overall = "FAIL"
        elif r.health == "WARN" and overall == "PASS":
            overall = "WARN"

    print()
    print("=" * 60)
    print(f"FINAL SYSTEM HEALTH: {overall}")
    print(f"Reports : {repo_root / _REPORT_PATH}")
    print("=" * 60)

    sys.exit(0 if overall in ("PASS", "WARN") else 1)
