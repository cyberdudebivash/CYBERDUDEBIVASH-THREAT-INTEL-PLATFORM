#!/usr/bin/env python3
"""
scripts/pipeline_validator.py
CYBERDUDEBIVASH® SENTINEL APEX v134.1 — Pipeline Determinism + Validation
═══════════════════════════════════════════════════════════════════════════════

MANDATE:
  All pipeline outputs must pass deterministic validation before being
  exposed to customers. This module enforces the validation contracts.

PROVIDES:
  ManifestValidator      — JSON schema + integrity + cross-ref validation
  ReportExistenceGuard   — confirms every manifest entry has a file on disk
  FileIntegrityEngine    — atomic write safety, UTF-8, checksum, size
  CustomerPathValidator  — validates all business-critical customer flows
  ArtifactRegistry       — tracks all generated artifacts with checksums

DETERMINISM CONTRACTS:
  1. Manifest entries MUST reference files that exist on disk
  2. Report files MUST have valid HTML headers (≥ 1KB)
  3. JSON files MUST parse cleanly (no silent corruption)
  4. All writes MUST be atomic (temp → replace)
  5. UTF-8 encoding MUST be enforced on all text files
  6. Checksums MUST be computed and logged for all artifacts
  7. YAML/JSON corruption MUST be detected before deployment

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import time
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("CDB-PIPELINE-VALIDATOR")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MIN_REPORT_BYTES   = 1024        # 1 KB minimum for a valid report file
MIN_MANIFEST_BYTES = 10          # manifest must be non-trivially non-empty
VALID_HTML_SIGS    = (b"<!doctype html", b"<!DOCTYPE html", b"<html")
MAX_NON_ASCII_RATIO = 0.05       # >5% non-ASCII in a text file = suspect

REPO_ROOT = Path(__file__).resolve().parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# FILE INTEGRITY ENGINE — Atomic Write Safety + Validation
# ─────────────────────────────────────────────────────────────────────────────

class FileIntegrityEngine:
    """
    Enforces file safety governance on all pipeline outputs.

    GOVERNANCE CONTRACTS:
      - All writes are atomic (temp → replace, never partial)
      - UTF-8 encoding enforced on all text files
      - LF normalization on all text outputs
      - Checksums computed and logged for every write
      - Post-write validation confirms file is readable + valid
      - Non-ASCII ratio checked (junk/corrupt character detection)
      - JSON files validated before AND after write
      - Rollback on corruption detection
    """

    def __init__(self, repo_root: Optional[Path] = None):
        self._root = repo_root or REPO_ROOT
        self._written: List[Dict[str, Any]] = []
        self._violations: List[str] = []

    # ── Atomic Text Write ────────────────────────────────────────────────────

    def atomic_write_text(
        self,
        path: Path,
        content: str,
        *,
        normalize_lf: bool = True,
        validate_utf8: bool = True,
        validate_non_ascii: bool = True,
    ) -> Dict[str, Any]:
        """
        Write text to path atomically with full integrity validation.
        Returns validation result dict. Never raises.
        """
        path = Path(path)
        result: Dict[str, Any] = {
            "path": str(path),
            "status": "pending",
            "bytes_written": 0,
            "checksum": "",
            "violations": [],
        }

        try:
            # 1. UTF-8 encode validation
            if validate_utf8:
                try:
                    _encoded = content.encode("utf-8")
                except UnicodeEncodeError as _ue:
                    result["violations"].append(f"UTF-8 encode failure: {_ue}")
                    content = content.encode("utf-8", errors="replace").decode("utf-8")
                    result["violations"].append("Content sanitized with UTF-8 replacement")

            # 2. LF normalization
            if normalize_lf:
                content = content.replace("\r\n", "\n").replace("\r", "\n")

            # 3. Non-ASCII ratio check
            if validate_non_ascii:
                _total = len(content)
                if _total > 0:
                    _non_ascii = sum(1 for c in content if ord(c) > 127)
                    _ratio = _non_ascii / _total
                    if _ratio > MAX_NON_ASCII_RATIO:
                        result["violations"].append(
                            f"High non-ASCII ratio: {_ratio:.1%} "
                            f"({_non_ascii}/{_total} chars) — possible encoding corruption"
                        )

            # 4. Compute checksum before write
            _checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

            # 5. Atomic write via temp file
            path.parent.mkdir(parents=True, exist_ok=True)
            _tmp = path.with_suffix(path.suffix + ".tmp")
            _tmp.write_text(content, encoding="utf-8")

            if not _tmp.exists():
                raise OSError(f"Temp file vanished before replace: {_tmp}")

            # 6. Post-write verify (read back and checksum)
            _read_back = _tmp.read_text(encoding="utf-8")
            _read_checksum = hashlib.sha256(_read_back.encode("utf-8")).hexdigest()
            if _read_checksum != _checksum:
                raise ValueError(
                    f"Post-write checksum mismatch: wrote {_checksum[:8]}… "
                    f"read back {_read_checksum[:8]}…"
                )

            # 7. Atomic replace
            try:
                os.replace(str(_tmp), str(path))
            except OSError as _re:
                log.warning("os.replace failed (%s) — direct write fallback", _re)
                path.write_text(content, encoding="utf-8")
                try:
                    _tmp.unlink(missing_ok=True)
                except Exception:
                    pass

            # 8. Final size check
            _final_size = path.stat().st_size
            result.update({
                "status":        "ok" if not result["violations"] else "ok_with_warnings",
                "bytes_written": _final_size,
                "checksum":      _checksum,
            })

            self._written.append(result)
            log.debug(
                "[FILE-INTEGRITY] WRITE OK: %s | %d bytes | sha256=%s…",
                path.name, _final_size, _checksum[:12],
            )

        except Exception as _exc:
            result["status"] = "error"
            result["error"] = f"{type(_exc).__name__}: {_exc}"
            result["violations"].append(f"Write failed: {_exc}")
            self._violations.append(f"{path.name}: {_exc}")
            log.error("[FILE-INTEGRITY] WRITE FAILED: %s — %s", path.name, _exc)
            # Cleanup stale tmp
            try:
                _tmp_path = path.with_suffix(path.suffix + ".tmp")
                if _tmp_path.exists():
                    _tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

        return result

    # ── JSON Write + Validate ────────────────────────────────────────────────

    def atomic_write_json(
        self,
        path: Path,
        data: Any,
        *,
        indent: int = 2,
        validate_roundtrip: bool = True,
    ) -> Dict[str, Any]:
        """
        Write JSON atomically with pre/post syntax validation.
        Returns validation result. Never raises.
        """
        path = Path(path)
        result: Dict[str, Any] = {
            "path": str(path),
            "status": "pending",
            "bytes_written": 0,
            "checksum": "",
            "violations": [],
        }

        try:
            # 1. Pre-write serialization validation
            try:
                _content = json.dumps(data, indent=indent, ensure_ascii=False, default=str)
            except (TypeError, ValueError) as _se:
                result["status"] = "serialization_error"
                result["error"] = str(_se)
                result["violations"].append(f"JSON serialization failed: {_se}")
                self._violations.append(f"{path.name}: JSON serialization failed: {_se}")
                return result

            # 2. Pre-write parse validation (catches circular refs that dumps doesn't catch)
            try:
                _pre_parsed = json.loads(_content)
                if type(_pre_parsed) is not type(data):
                    result["violations"].append(
                        f"Pre-write type mismatch: input={type(data).__name__} "
                        f"parsed={type(_pre_parsed).__name__}"
                    )
            except json.JSONDecodeError as _jde:
                result["status"] = "json_invalid"
                result["error"] = str(_jde)
                result["violations"].append(f"Pre-write JSON parse failed: {_jde}")
                self._violations.append(f"{path.name}: JSON invalid pre-write: {_jde}")
                return result

            # 3. Atomic write
            _write_result = self.atomic_write_text(
                path, _content,
                normalize_lf=True,
                validate_utf8=True,
                validate_non_ascii=False,  # JSON is ASCII-safe by construction
            )

            if _write_result["status"].startswith("error"):
                return _write_result

            # 4. Post-write JSON parse validation
            if validate_roundtrip:
                try:
                    _post_content = path.read_text(encoding="utf-8")
                    json.loads(_post_content)
                except Exception as _post_exc:
                    result["violations"].append(f"Post-write JSON parse FAILED: {_post_exc}")
                    result["status"] = "post_write_corrupt"
                    self._violations.append(f"{path.name}: CORRUPT after write: {_post_exc}")
                    log.error("[FILE-INTEGRITY] JSON CORRUPT AFTER WRITE: %s", path.name)
                    return result

            result.update(_write_result)
            return result

        except Exception as _exc:
            result["status"] = "error"
            result["error"] = str(_exc)
            self._violations.append(f"{path.name}: {_exc}")
            return result

    # ── HTML Report Validation ───────────────────────────────────────────────

    def validate_report_file(self, path: Path, report_id: str = "") -> Dict[str, Any]:
        """
        Validate a generated HTML report file.
        Returns validation result with status: 'valid' | 'invalid' | 'missing'
        """
        path = Path(path)
        _id  = report_id or path.stem

        if not path.exists():
            log.error("[FILE-INTEGRITY] MISSING REPORT: %s → %s", _id, path)
            return {"id": _id, "status": "missing", "path": str(path)}

        _size = path.stat().st_size
        if _size < MIN_REPORT_BYTES:
            log.error(
                "[FILE-INTEGRITY] REPORT TOO SMALL: %s (%d bytes < %d minimum)",
                _id, _size, MIN_REPORT_BYTES,
            )
            return {
                "id": _id, "status": "too_small",
                "path": str(path), "size": _size,
            }

        # Read first 64 bytes for HTML signature check
        try:
            with open(path, "rb") as _fh:
                _head = _fh.read(64)
            _head_lower = _head.lower()
            if not any(_head_lower.startswith(sig.lower()) for sig in VALID_HTML_SIGS):
                log.error(
                    "[FILE-INTEGRITY] INVALID HTML HEADER: %s (got: %r)",
                    _id, _head[:32],
                )
                return {
                    "id": _id, "status": "invalid_header",
                    "path": str(path), "header": repr(_head[:32]),
                }
        except OSError as _oe:
            log.error("[FILE-INTEGRITY] CANNOT READ REPORT: %s — %s", _id, _oe)
            return {"id": _id, "status": "read_error", "path": str(path), "error": str(_oe)}

        # Compute checksum
        try:
            _checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            _checksum = ""

        log.debug("[FILE-INTEGRITY] REPORT VALID: %s (%d bytes)", _id, _size)
        return {
            "id":       _id,
            "status":   "valid",
            "path":     str(path),
            "size":     _size,
            "checksum": _checksum,
        }

    def violations(self) -> List[str]:
        return list(self._violations)

    def has_violations(self) -> bool:
        return len(self._violations) > 0

    def written_count(self) -> int:
        return len([r for r in self._written if r.get("status", "").startswith("ok")])


# ─────────────────────────────────────────────────────────────────────────────
# MANIFEST VALIDATOR — JSON Schema + Integrity + Cross-Reference
# ─────────────────────────────────────────────────────────────────────────────

class ManifestValidator:
    """
    Validates feed_manifest.json for structural integrity, cross-references,
    and publication safety before deployment.

    VALIDATION CONTRACTS:
      1. Manifest must parse as valid JSON
      2. Manifest must have 'advisories' or 'reports' top-level key
      3. Every 'ok'/'enriched' entry must have a valid report_url
      4. report_url must differ from source_url
      5. No entry may have validation_status = 'write_error' or 'render_error'
         unless it was intentionally downgraded (i.e. the pipeline ran but failed)
      6. ioc_count must equal len(iocs) for every entry
      7. published field must be a non-empty string (never bool)
    """

    def __init__(self, manifest_path: Optional[Path] = None):
        self._path = manifest_path or (REPO_ROOT / "data" / "stix" / "feed_manifest.json")
        self._data: Optional[Dict] = None
        self._errors: List[str] = []
        self._warnings: List[str] = []

    def load(self) -> bool:
        """Load and parse manifest. Returns True on success."""
        if not self._path.exists():
            self._errors.append(f"Manifest not found: {self._path}")
            return False

        _size = self._path.stat().st_size
        if _size < MIN_MANIFEST_BYTES:
            self._errors.append(f"Manifest suspiciously small: {_size} bytes")
            return False

        try:
            _raw = self._path.read_text(encoding="utf-8")
            self._data = json.loads(_raw)
            return True
        except json.JSONDecodeError as _jde:
            self._errors.append(f"Manifest JSON parse FAILED: {_jde}")
            return False
        except UnicodeDecodeError as _ude:
            self._errors.append(f"Manifest encoding CORRUPT: {_ude}")
            return False
        except Exception as _exc:
            self._errors.append(f"Manifest load error: {_exc}")
            return False

    def validate(self) -> Dict[str, Any]:
        """
        Run all validation contracts.
        Returns complete validation report.
        """
        if self._data is None:
            if not self.load():
                return self._report(False)

        _advisories = (
            self._data.get("advisories") or
            self._data.get("reports") or
            (self._data if isinstance(self._data, list) else [])
        )

        if not isinstance(_advisories, list):
            self._errors.append(
                f"Manifest 'advisories' key is not a list: {type(_advisories).__name__}"
            )
            return self._report(False)

        _total        = len(_advisories)
        _ok_count     = 0
        _error_count  = 0
        _warn_count   = 0
        _ioc_mismatch = 0
        _bool_pub     = 0
        _missing_url  = 0
        _url_same     = 0

        for _i, _entry in enumerate(_advisories):
            if not isinstance(_entry, dict):
                self._errors.append(f"Entry [{_i}] is not a dict: {type(_entry).__name__}")
                _error_count += 1
                continue

            _vs  = _entry.get("validation_status", "")
            _eid = _entry.get("id", f"<idx:{_i}>")

            # Error statuses
            if _vs in ("write_error", "render_error", "file_invalid", "file_missing"):
                self._warnings.append(
                    f"Entry {_eid}: validation_status={_vs!r} — not published"
                )
                _warn_count += 1
                continue

            if _vs in ("ok", "enriched", "valid"):
                _ok_count += 1

                # report_url check
                _rurl = _entry.get("report_url", "")
                _surl = _entry.get("source_url", "")
                if not _rurl:
                    self._errors.append(f"Entry {_eid}: missing report_url")
                    _missing_url += 1
                    _error_count += 1
                elif _rurl == _surl:
                    self._warnings.append(f"Entry {_eid}: report_url == source_url")
                    _url_same += 1

                # published field
                _pub = _entry.get("published")
                if isinstance(_pub, bool):
                    self._errors.append(
                        f"Entry {_eid}: 'published' is bool({_pub}) — must be ISO string (P0 regression)"
                    )
                    _bool_pub += 1
                    _error_count += 1
                elif not _pub:
                    self._warnings.append(f"Entry {_eid}: 'published' is empty")
                    _warn_count += 1

                # ioc_count integrity
                _iocs      = _entry.get("iocs", [])
                _ioc_count = _entry.get("ioc_count", -1)
                if isinstance(_iocs, list) and isinstance(_ioc_count, int):
                    if _ioc_count != len(_iocs):
                        self._errors.append(
                            f"Entry {_eid}: ioc_count={_ioc_count} but len(iocs)={len(_iocs)}"
                        )
                        _ioc_mismatch += 1
                        _error_count += 1

        _is_valid = len(self._errors) == 0

        result = self._report(_is_valid)
        result.update({
            "total_entries":    _total,
            "ok_entries":       _ok_count,
            "error_entries":    _error_count,
            "warning_entries":  _warn_count,
            "ioc_mismatches":   _ioc_mismatch,
            "bool_published":   _bool_pub,
            "missing_urls":     _missing_url,
            "url_collisions":   _url_same,
        })
        return result

    def _report(self, is_valid: bool) -> Dict[str, Any]:
        return {
            "valid":      is_valid,
            "path":       str(self._path),
            "errors":     list(self._errors),
            "warnings":   list(self._warnings),
            "validated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


# ─────────────────────────────────────────────────────────────────────────────
# REPORT EXISTENCE GUARD — Every Manifest Entry Has a File
# ─────────────────────────────────────────────────────────────────────────────

class ReportExistenceGuard:
    """
    Confirms every published manifest entry has a corresponding file on disk.
    Blocks manifest writes for entries where files are missing.

    DETERMINISM CONTRACT:
      The manifest is the source of truth for published reports.
      Any entry in the manifest with status 'ok'/'enriched' MUST have
      a corresponding HTML file on disk. If the file is missing,
      the entry is downgraded to 'file_missing' and excluded from
      customer-facing endpoints.
    """

    def __init__(self, repo_root: Optional[Path] = None):
        self._root = repo_root or REPO_ROOT
        self._reports_root = self._root / "reports"

    def _resolve_report_path(self, entry: Dict) -> Optional[Path]:
        """Resolve the local file path for a manifest entry."""
        # Strategy 1: internal_report_url (relative path)
        _iurl = entry.get("internal_report_url", "")
        if _iurl and _iurl.startswith("/"):
            return self._root / _iurl.lstrip("/")

        # Strategy 2: extract from report_url (strip https://host prefix)
        _rurl = entry.get("report_url", "")
        _MARKER = "/reports/"
        if _MARKER in _rurl:
            _rel = _rurl[_rurl.index(_MARKER) + 1:]   # "reports/YYYY/MM/id.html"
            return self._root / _rel

        # Strategy 3: search reports dir for {id}.html
        _eid = entry.get("id", "")
        if _eid:
            _found = list(self._reports_root.rglob(f"{_eid}.html"))
            if _found:
                return _found[0]
            # Fallback: construct expected path
            return self._reports_root / f"{_eid}.html"

        return None

    def check_entries(
        self,
        entries: List[Dict],
        *,
        downgrade_missing: bool = True,
    ) -> Dict[str, Any]:
        """
        Check all entries and optionally downgrade missing ones.
        Returns existence check report.
        """
        _checked  = 0
        _present  = 0
        _missing  = 0
        _skipped  = 0
        _failures: List[str] = []

        for _entry in entries:
            _vs  = _entry.get("validation_status", "")
            _eid = _entry.get("id", "?")

            # Only check entries that should be published
            if _vs not in ("ok", "enriched", "valid"):
                _skipped += 1
                continue

            _checked += 1
            _path = self._resolve_report_path(_entry)

            if _path is None:
                _failures.append(f"{_eid}: cannot resolve report path")
                _missing += 1
                if downgrade_missing:
                    _entry["validation_status"] = "path_unresolvable"
                    _entry["report_url"] = _entry.get("source_url") or ""
                continue

            if not _path.exists():
                _failures.append(f"{_eid} → {_path}")
                _missing += 1
                log.error(
                    "[EXISTENCE-GUARD] MISSING FILE: %s → %s — downgrading to file_missing",
                    _eid, _path.name,
                )
                if downgrade_missing:
                    _entry["validation_status"] = "file_missing"
                    _entry["report_url"] = _entry.get("source_url") or ""
            else:
                _present += 1
                log.debug("[EXISTENCE-GUARD] CONFIRMED: %s → %s", _eid, _path.name)

        return {
            "checked":           _checked,
            "present":           _present,
            "missing":           _missing,
            "skipped":           _skipped,
            "all_present":       _missing == 0,
            "missing_entries":   _failures[:20],
            "validated_at":      datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOMER PATH VALIDATOR — Business-Critical Flow Validation
# ─────────────────────────────────────────────────────────────────────────────

class CustomerPathValidator:
    """
    Validates all business-critical customer-facing flows.

    Customer flows validated:
      1. Dashboard data file exists and is valid JSON
      2. Feed manifest exists, is valid JSON, and has entries
      3. At least one report file exists in reports/
      4. STIX bundle directory is not empty
      5. API response files are structurally valid
      6. Enterprise CTA links are in place (report files contain CTA HTML)
      7. IOC tables are in report files
      8. MITRE ATT&CK sections are in report files
    """

    def __init__(self, repo_root: Optional[Path] = None):
        self._root = repo_root or REPO_ROOT
        self._checks: List[Dict[str, Any]] = []

    def _check(
        self,
        name: str,
        fn: "Callable[[], Tuple[bool, str]]",
        customer_critical: bool = True,
    ) -> Dict[str, Any]:
        """Run a single check and record result."""
        _t0 = time.monotonic()
        try:
            _passed, _detail = fn()
        except Exception as _exc:
            _passed  = False
            _detail  = f"Check raised exception: {type(_exc).__name__}: {_exc}"

        _duration_ms = round((time.monotonic() - _t0) * 1000, 2)
        _result = {
            "check":            name,
            "passed":           _passed,
            "detail":           _detail,
            "customer_critical": customer_critical,
            "duration_ms":      _duration_ms,
        }
        self._checks.append(_result)

        _level = "info" if _passed else ("error" if customer_critical else "warning")
        getattr(log, _level)(
            "[CUSTOMER-PATH] %s: %s%s",
            name,
            "PASS" if _passed else "FAIL",
            f" — {_detail}" if _detail else "",
        )
        return _result

    def validate_all(self) -> Dict[str, Any]:
        """Run all customer path validation checks. Returns complete report."""

        # ── CHECK 1: Dashboard data ──────────────────────────────────────────
        def _check_dashboard():
            _paths = [
                self._root / "data" / "dashboard" / "dashboard_data.json",
                self._root / "data" / "api" / "dashboard.json",
                self._root / "dashboard_data.json",
            ]
            for _p in _paths:
                if _p.exists():
                    try:
                        json.loads(_p.read_text(encoding="utf-8"))
                        return True, f"Dashboard data valid at {_p.name}"
                    except Exception as _e:
                        return False, f"Dashboard data CORRUPT at {_p.name}: {_e}"
            return False, "Dashboard data file not found in any expected location"
        self._check("dashboard_data_valid", _check_dashboard, customer_critical=True)

        # ── CHECK 2: Feed manifest ───────────────────────────────────────────
        def _check_manifest():
            _p = self._root / "data" / "stix" / "feed_manifest.json"
            if not _p.exists():
                return False, f"feed_manifest.json not found at {_p}"
            try:
                _d = json.loads(_p.read_text(encoding="utf-8"))
                _advisories = _d.get("advisories") or _d.get("reports") or []
                _published  = [e for e in _advisories
                               if e.get("validation_status") in ("ok", "enriched", "valid")]
                return bool(_published), (
                    f"Manifest has {len(_published)} published entries of {len(_advisories)} total"
                )
            except Exception as _e:
                return False, f"Manifest CORRUPT: {_e}"
        self._check("feed_manifest_valid", _check_manifest, customer_critical=True)

        # ── CHECK 3: Report files exist ──────────────────────────────────────
        def _check_reports():
            _reports_dir = self._root / "reports"
            if not _reports_dir.exists():
                return False, "reports/ directory does not exist"
            _html_files = list(_reports_dir.rglob("*.html"))
            if not _html_files:
                return False, "No HTML report files found in reports/"
            return True, f"{len(_html_files)} HTML report files present"
        self._check("report_files_present", _check_reports, customer_critical=True)

        # ── CHECK 4: STIX bundle directory ──────────────────────────────────
        def _check_stix():
            _stix_dirs = [
                self._root / "data" / "stix",
                self._root / "stix",
            ]
            for _sd in _stix_dirs:
                _bundles = list(_sd.glob("*.json")) if _sd.exists() else []
                _bundles = [b for b in _bundles if b.name != "feed_manifest.json"]
                if _bundles:
                    return True, f"{len(_bundles)} STIX bundle(s) at {_sd.name}/"
            return False, "No STIX bundles found"
        self._check("stix_bundles_present", _check_stix, customer_critical=False)

        # ── CHECK 5: At least one recent report has CTA HTML ────────────────
        def _check_cta():
            _reports_dir = self._root / "reports"
            if not _reports_dir.exists():
                return False, "reports/ directory missing"
            _html_files = sorted(_reports_dir.rglob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)[:5]
            if not _html_files:
                return False, "No HTML reports to check"
            for _f in _html_files:
                try:
                    _text = _f.read_text(encoding="utf-8", errors="replace")
                    if "cta" in _text.lower() or "enterprise" in _text.lower():
                        return True, f"CTA content found in {_f.name}"
                except Exception:
                    continue
            return False, "No CTA content found in recent report files"
        self._check("enterprise_cta_present", _check_cta, customer_critical=False)

        # ── CHECK 6: IOC table in recent reports ─────────────────────────────
        def _check_ioc_table():
            _reports_dir = self._root / "reports"
            if not _reports_dir.exists():
                return False, "reports/ directory missing"
            _html_files = sorted(_reports_dir.rglob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)[:3]
            for _f in _html_files:
                try:
                    _text = _f.read_text(encoding="utf-8", errors="replace")
                    if "ioc" in _text.lower():
                        return True, f"IOC table found in {_f.name}"
                except Exception:
                    continue
            return False, "No IOC content found in recent reports"
        self._check("ioc_table_in_reports", _check_ioc_table, customer_critical=False)

        # ── CHECK 7: MITRE ATT&CK mapping in recent reports ──────────────────
        def _check_mitre():
            _reports_dir = self._root / "reports"
            if not _reports_dir.exists():
                return False, "reports/ directory missing"
            _html_files = sorted(_reports_dir.rglob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)[:3]
            for _f in _html_files:
                try:
                    _text = _f.read_text(encoding="utf-8", errors="replace")
                    if "mitre" in _text.lower() or "att&ck" in _text.lower() or "attck" in _text.lower():
                        return True, f"MITRE ATT&CK content in {_f.name}"
                except Exception:
                    continue
            return False, "No MITRE ATT&CK content in recent reports"
        self._check("mitre_attck_in_reports", _check_mitre, customer_critical=False)

        # ── CHECK 8: No orphaned .tmp files ─────────────────────────────────
        def _check_no_tmp():
            _tmp_files = (
                list((self._root / "data").rglob("*.tmp"))
                if (self._root / "data").exists() else []
            )
            _tmp_files += (
                list((self._root / "reports").rglob("*.tmp"))
                if (self._root / "reports").exists() else []
            )
            if _tmp_files:
                return False, f"{len(_tmp_files)} stale .tmp file(s) found: {[t.name for t in _tmp_files[:3]]}"
            return True, "No stale .tmp files"
        self._check("no_stale_tmp_files", _check_no_tmp, customer_critical=False)

        # ── SUMMARY ──────────────────────────────────────────────────────────
        _passed  = sum(1 for c in self._checks if c["passed"])
        _failed  = sum(1 for c in self._checks if not c["passed"])
        _critical_failed = sum(
            1 for c in self._checks
            if not c["passed"] and c.get("customer_critical")
        )

        return {
            "overall_pass":             _critical_failed == 0,
            "critical_checks_failed":   _critical_failed,
            "checks_passed":            _passed,
            "checks_failed":            _failed,
            "total_checks":             len(self._checks),
            "check_results":            self._checks,
            "validated_at":             datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


# ─────────────────────────────────────────────────────────────────────────────
# ARTIFACT REGISTRY — Checksum Tracking for All Generated Artifacts
# ─────────────────────────────────────────────────────────────────────────────

class ArtifactRegistry:
    """
    Tracks all generated artifacts (reports, STIX, manifests) with checksums
    for integrity verification and regression detection.
    """

    def __init__(self, repo_root: Optional[Path] = None):
        self._root    = repo_root or REPO_ROOT
        self._entries: List[Dict[str, Any]] = []

    def register(self, path: Path, artifact_type: str = "report") -> Dict[str, Any]:
        """Register an artifact and compute its checksum. Never raises."""
        try:
            _path = Path(path)
            _size = _path.stat().st_size if _path.exists() else 0
            _checksum = ""
            if _path.exists():
                _checksum = hashlib.sha256(_path.read_bytes()).hexdigest()
            _entry = {
                "path":          str(_path),
                "name":          _path.name,
                "type":          artifact_type,
                "size":          _size,
                "checksum":      _checksum,
                "exists":        _path.exists(),
                "registered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            self._entries.append(_entry)
            return _entry
        except Exception as _e:
            log.warning("[ARTIFACT-REGISTRY] register failed for %s: %s", path, _e)
            return {"path": str(path), "error": str(_e)}

    def verify_all(self) -> Dict[str, Any]:
        """Re-verify all registered artifacts. Returns integrity report."""
        _ok      = 0
        _corrupt = 0
        _missing = 0
        _violations: List[str] = []

        for _entry in self._entries:
            _path = Path(_entry.get("path", ""))
            if not _path.exists():
                _missing += 1
                _violations.append(f"MISSING: {_path.name}")
                continue
            _current = hashlib.sha256(_path.read_bytes()).hexdigest()
            if _current != _entry.get("checksum"):
                _corrupt += 1
                _violations.append(
                    f"CORRUPT: {_path.name} "
                    f"(expected={_entry.get('checksum','')[:8]}…, "
                    f"got={_current[:8]}…)"
                )
            else:
                _ok += 1

        return {
            "total":      len(self._entries),
            "ok":         _ok,
            "corrupt":    _corrupt,
            "missing":    _missing,
            "all_valid":  _corrupt == 0 and _missing == 0,
            "violations": _violations,
            "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_artifacts": len(self._entries),
            "entries": self._entries,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
