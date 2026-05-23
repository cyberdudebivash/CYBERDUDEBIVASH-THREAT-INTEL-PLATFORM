#!/usr/bin/env python3
"""
scripts/sanitize_repo.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0.0 — Production JSON Sanitizer & Self-Healing Engine
============================================================================================
Runs as the FIRST step in sentinel-blogger.yml and deploy-worker.yml (after checkout,
before ANY Python or validation step).

Responsibilities:
  1. Scan every .json file in the repo.
  2. Strip UTF-8 BOM (\\xef\\xbb\\xbf) from any infected file.
  3. Normalize encoding to UTF-8 (no BOM, no null bytes, no CRLF).
  4. Validate JSON structure (attempt json.loads()).
  5. Auto-fix minor corruption:
       - Truncated JSON array/object → close with ] or }
       - Trailing commas (Python json can't parse these)
       - NUL bytes inside JSON strings
  6. If JSON is unrecoverable → regenerate minimal valid structure.
  7. Emit SECURITY_HUB_KV log entry for every event.
  8. Exit 0 ALWAYS — this script MUST NOT break the pipeline.

Distinct from sanitize_encoding.py:
  - sanitize_encoding.py: broad text-file encoding fix (BOM, CRLF, null bytes, ctrl chars)
  - sanitize_repo.py: JSON-specific — validates/heals JSON structure, regenerates on failure

Root cause of run #793: advisory data had "published": true (boolean) stored in JSON
manifests, which caused downstream AttributeError in threat_scoring.py:288.
This script detects and normalises such structural issues at the source.

Usage:
  python3 scripts/sanitize_repo.py             # scan + fix + heal
  python3 scripts/sanitize_repo.py --dry-run   # report only, no writes
  python3 scripts/sanitize_repo.py --json      # output JSONL report to stdout

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# SafeIO -- optional import; falls back to legacy I/O if not available
try:
    _SELF_DIR = pathlib.Path(__file__).resolve().parent
    if str(_SELF_DIR) not in sys.path:
        sys.path.insert(0, str(_SELF_DIR))
    from safe_io import atomic_json_write as _atomic_write_json
    _SAFE_IO_AVAILABLE = True
except ImportError:
    _SAFE_IO_AVAILABLE = False

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [sanitize_repo] %(levelname)s: %(message)s",
)
logger = logging.getLogger("sentinel.sanitize_repo")

# ── Configuration ────────────────────────────────────────────────────────────
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BOM = b"\xef\xbb\xbf"

# Directories to never touch
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
    # Historical backup archives — read-only, never rewrite or re-sanitize
    ".manifest_backups", "manifest_backups",
}

# Files that have known minimal fallback structures when unrecoverable
MANIFEST_FALLBACKS: Dict[str, Any] = {
    "data/stix/feed_manifest.json": {
        "version": "v134.0",
        "schema_version": "v70.0",
        "platform": "SENTINEL-APEX",
        "generated_at": "",  # filled at runtime
        "total_reports": 0,
        "entry_count": 0,
        "sort_order": "timestamp DESC, risk_score DESC",
        "advisories": [],
        "_regenerated_by": "sanitize_repo.py",
        "_reason": "JSON corruption detected and auto-healed",
    },
    "data/feed_manifest.json": {
        "version": "v134.0",
        "schema_version": "v70.0",
        "platform": "SENTINEL-APEX",
        "generated_at": "",
        "total_reports": 0,
        "entry_count": 0,
        "sort_order": "timestamp DESC, risk_score DESC",
        "advisories": [],
        "_regenerated_by": "sanitize_repo.py",
        "_reason": "JSON corruption detected and auto-healed",
    },
    "data/publish_queue.json": {
        "queue": [],
        "version": "111.0",
        "_regenerated_by": "sanitize_repo.py",
    },
    "config/version.json": {
        "version": "141.0.0",
        "platform": "SENTINEL-APEX",
        "build": "v141.0.0",
        "_regenerated_by": "sanitize_repo.py",
    },
    # Root version.json — complete fallback added run #871 (P0 fix)
    # apply_v131_upgrades.py will atomically overwrite this in Stage 9
    "version.json": {
        "version": "141.0.0",
        "platform": "SENTINEL-APEX",
        "release": "v141.0.0",
        "pipeline_version": "141.0.0",
        "updated_at": "",
        "build": "v141-PRODUCTION",
        "stability": "stable",
        "changelog": "v141: sentinel-apex production pipeline",
        "generated_at": "",
        "_generator": "sanitize_repo.py emergency fallback",
        "_regenerated_by": "sanitize_repo.py",
        "_reason": "JSON corruption detected — apply_v131_upgrades.py will overwrite in Stage 9",
    },
    # Root feed.json -- must always be a valid JSON array (never YAML content)
    "feed.json": [],
    # API feed -- always a valid JSON array; real data written by api_layer_v101.py
    "api/feed.json": [],
}

# ── Protected files: parse errors are LOGGED + auto-heal attempted but NEVER regenerated ──
# These are SSOT / governance files whose content is irreplaceable.
# If they are corrupted beyond auto-heal, the pipeline logs CRITICAL and preserves the file
# as-is (or attempts truncation repair only) rather than wiping it to a minimal stub.
# v160.0: Added config/platform_version.json after recurring REGENERATE → STAGE 5.8.4 HARD_FAIL
SKIP_REGENERATE: set = {
    "config/platform_version.json",        # SSOT — wipe = global version loss
    "config/stability_lock.json",          # baseline stability contract
    "data/governance/governance_report.json",  # enterprise governance audit trail
    "data/telemetry/global_release_governance.json",  # release governance telemetry
}

# SECURITY_HUB_KV log path
HUB_LOG = REPO_ROOT / "data" / "logs" / "security_hub_kv.jsonl"

# ── Result tracking ──────────────────────────────────────────────────────────
class SanitizeEvent:
    def __init__(self, path: str, action: str, detail: str, severity: str = "INFO"):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.path = path
        self.action = action
        self.detail = detail
        self.severity = severity

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "event_type": f"json_sanitize_{self.action.lower().replace(' ', '_')}",
            "pipeline": "sentinel-blogger",
            "component": "sanitize_repo",
            "severity": self.severity,
            "path": self.path,
            "action": self.action,
            "detail": self.detail,
        }


# ── Core functions ───────────────────────────────────────────────────────────

def strip_bom_and_normalize(data: bytes) -> Tuple[bytes, bool]:
    """Remove BOM, null bytes, CRLF. Returns (clean_data, was_modified)."""
    original = data
    if data.startswith(BOM):
        data = data[3:]
    data = data.replace(b"\x00", b"")
    data = data.replace(b"\r\n", b"\n")
    return data, data != original


def try_parse_json(text: str) -> Tuple[Optional[Any], Optional[str]]:
    """Try to parse JSON. Returns (parsed_object, error_message)."""
    try:
        return json.loads(text), None
    except json.JSONDecodeError as e:
        return None, str(e)


def auto_heal_json(text: str) -> Tuple[Optional[str], str]:
    """
    Attempt to auto-heal minor JSON corruption.
    Returns (healed_text_or_None, description_of_action).
    """
    original = text.strip()
    if not original:
        return None, "empty"

    # Attempt 1: Remove trailing comma before ] or }
    healed = re.sub(r",\s*([\]\}])", r"\1", original)
    if healed != original:
        obj, err = try_parse_json(healed)
        if obj is not None:
            return healed, "removed trailing commas"

    # Attempt 2: Close truncated array
    if original.startswith("[") and not original.endswith("]"):
        # Find last complete element
        candidate = original.rstrip().rstrip(",") + "\n]"
        obj, err = try_parse_json(candidate)
        if obj is not None:
            return candidate, "closed truncated JSON array"

    # Attempt 3: Close truncated object
    if original.startswith("{") and not original.endswith("}"):
        candidate = original.rstrip().rstrip(",") + "\n}"
        obj, err = try_parse_json(candidate)
        if obj is not None:
            return candidate, "closed truncated JSON object"

    # Attempt 4: Remove single-line comments (// ...) — not valid JSON
    if "//" in original:
        healed = re.sub(r"//[^\n]*", "", original)
        obj, err = try_parse_json(healed)
        if obj is not None:
            return healed, "removed single-line comments"

    # Attempt 5: utf-8-sig parse (BOM slipped through as text)
    if original.startswith("\ufeff"):
        healed = original[1:]
        obj, err = try_parse_json(healed)
        if obj is not None:
            return healed, "stripped text BOM marker"

    return None, "unrecoverable"


def get_fallback_structure(rel_path: str) -> Any:
    """Return minimal valid JSON fallback for known critical files."""
    # Normalise path separators for lookup
    norm = rel_path.replace("\\", "/")
    fallback = MANIFEST_FALLBACKS.get(norm)
    if fallback is not None:
        # List fallbacks (e.g. feed.json) returned as-is -- [] is valid JSON
        if isinstance(fallback, list):
            return list(fallback)
        result = dict(fallback)
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        return result
    # Generic fallback: empty object for any .json we can't parse
    return {"_regenerated_by": "sanitize_repo.py", "_reason": "JSON corruption"}


def audit_json_structure(obj: Any, rel_path: str) -> List[str]:
    """
    Audit a parsed JSON object for known P0 structural issues.
    Returns list of warning strings (empty = clean).
    """
    warnings = []
    if not isinstance(obj, (dict, list)):
        return warnings

    # Check advisory arrays for boolean published_date (root cause of run #793)
    items = []
    if isinstance(obj, list):
        items = obj
    elif isinstance(obj, dict):
        for key in ("advisories", "reports", "items"):
            if key in obj and isinstance(obj[key], list):
                items = obj[key]
                break

    bool_pub_count = 0
    ioc_mismatch_count = 0
    fixed_count = 0
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for item in items:
        if not isinstance(item, dict):
            continue

        # ── Fix #1: boolean 'published' → ISO-8601 string (P0 guard, run #793) ──
        pub = item.get("published")
        if isinstance(pub, bool):
            bool_pub_count += 1
            # Prefer an existing string date from adjacent fields
            real_date = (
                item.get("published_date") or
                item.get("timestamp") or
                item.get("created_at") or
                item.get("date") or
                now_iso
            )
            real_date = real_date if isinstance(real_date, str) and real_date.strip() else now_iso
            # CRITICAL: overwrite the boolean with the ISO string
            item["published"] = real_date.strip()
            item.setdefault("published_date", real_date.strip())
            fixed_count += 1

        # ── Fix #2: ioc_count integrity ──
        iocs = item.get("iocs")
        ioc_count = item.get("ioc_count")
        if isinstance(iocs, list) and ioc_count is not None:
            if ioc_count != len(iocs):
                item["ioc_count"] = len(iocs)
                ioc_mismatch_count += 1

    if bool_pub_count:
        warnings.append(
            f"FIXED {fixed_count}/{bool_pub_count} advisory entries: boolean 'published' "
            f"-> ISO-8601 string (root cause: run #793 — P0 fix applied)"
        )
    if ioc_mismatch_count:
        warnings.append(
            f"FIXED {ioc_mismatch_count} advisory entries: ioc_count corrected to match len(iocs)"
        )

    return warnings


def process_json_file(
    path: pathlib.Path,
    repo_root: pathlib.Path,
    dry_run: bool,
    events: List[SanitizeEvent],
) -> bool:
    """
    Process a single .json file. Returns True if file was modified.
    Emits events for every action taken.
    """
    rel = str(path.relative_to(repo_root)).replace("\\", "/")
    modified = False

    # ── Read raw bytes ──
    try:
        raw = path.read_bytes()
    except OSError as e:
        events.append(SanitizeEvent(rel, "READ_ERROR", str(e), "WARNING"))
        return False

    # ── Normalize encoding (BOM, nulls, CRLF) ──
    clean_bytes, encoding_changed = strip_bom_and_normalize(raw)
    if encoding_changed:
        events.append(SanitizeEvent(
            rel, "BOM_STRIPPED",
            f"Removed BOM/null-bytes/CRLF from {rel}",
            "WARNING",
        ))
        modified = True

    # ── Decode to string ──
    try:
        text = clean_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = clean_bytes.decode("latin-1")
            events.append(SanitizeEvent(rel, "ENCODING_COERCED", "Re-encoded latin-1→utf-8", "WARNING"))
            clean_bytes = text.encode("utf-8")
            modified = True
        except Exception as e:
            events.append(SanitizeEvent(rel, "DECODE_FAILED", str(e), "ERROR"))
            return False

    # Skip empty files silently
    if not text.strip():
        return modified

    # ── Parse JSON ──
    obj, parse_err = try_parse_json(text)

    if obj is None:
        # ── Attempt auto-heal ──
        events.append(SanitizeEvent(
            rel, "PARSE_ERROR",
            f"JSONDecodeError: {parse_err}",
            "ERROR",
        ))
        healed_text, heal_action = auto_heal_json(text)

        if healed_text is not None:
            obj, _ = try_parse_json(healed_text)
            text = healed_text
            clean_bytes = healed_text.encode("utf-8")
            modified = True
            events.append(SanitizeEvent(
                rel, "AUTO_HEALED",
                f"Healed via: {heal_action}",
                "WARNING",
            ))
        else:
            # ── Protected SSOT files: log CRITICAL but DO NOT regenerate ──
            if rel in SKIP_REGENERATE:
                events.append(SanitizeEvent(
                    rel, "PROTECTED_PARSE_ERROR",
                    f"SSOT file unrecoverable but SKIP_REGENERATE protected — preserving original. "
                    f"Manual intervention required. Error: {parse_err}",
                    "CRITICAL",
                ))
                # Do not set modified — leave file intact
            else:
                # ── Regenerate minimal valid structure ──
                fallback = get_fallback_structure(rel)
                healed_text = json.dumps(fallback, indent=2, ensure_ascii=False)
                obj = fallback
                text = healed_text
                clean_bytes = healed_text.encode("utf-8")
                modified = True
                events.append(SanitizeEvent(
                    rel, "REGENERATED",
                    f"File was unrecoverable JSON — regenerated with minimal valid structure",
                    "CRITICAL",
                ))

    # ── Audit structure for semantic P0 issues ──
    if obj is not None:
        audit_warnings = audit_json_structure(obj, rel)
        if audit_warnings:
            for w in audit_warnings:
                events.append(SanitizeEvent(rel, "STRUCTURE_FIXED", w, "WARNING"))
            # Re-serialize with fixes applied
            try:
                healed_text = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
                clean_bytes = healed_text.encode("utf-8")
                modified = True
            except Exception as e:
                events.append(SanitizeEvent(rel, "SERIALIZE_ERROR", str(e), "ERROR"))

    # ── Write back if changed (atomic: temp-file + os.replace) ──
    if modified and not dry_run:
        try:
            if _SAFE_IO_AVAILABLE and obj is not None:
                # Use SafeIO atomic writer with post-write verification
                _atomic_write_json(path, obj, locked=False)
            else:
                # Legacy fallback: raw bytes temp-file + replace
                tmp = path.with_suffix(".sanitize_tmp")
                tmp.write_bytes(clean_bytes)
                os.replace(tmp, path)
        except OSError as e:
            events.append(SanitizeEvent(rel, "WRITE_ERROR", str(e), "ERROR"))
            return False
        except Exception as e:
            events.append(SanitizeEvent(rel, "WRITE_ERROR", f"atomic write failed: {e}", "ERROR"))
            # Last-resort: raw write
            try:
                path.write_bytes(clean_bytes)
            except Exception:
                return False

    return modified


def scan_repo(root: pathlib.Path) -> List[pathlib.Path]:
    """Walk repo, yield all .json files excluding skip dirs."""
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.lower().endswith(".json"):
                result.append(pathlib.Path(dirpath) / fname)
    return sorted(result)


def write_security_hub_kv(events: List[SanitizeEvent], log_path: pathlib.Path) -> None:
    """Append all events to SECURITY_HUB_KV JSONL log. Non-blocking."""
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev.to_dict(), ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        logger.warning(f"SECURITY_HUB_KV write failed (non-fatal): {e}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX — JSON Sanitizer & Self-Healing Engine v134.0.0"
    )
    parser.add_argument("--dry-run", action="store_true", help="Report only, no writes")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output JSONL report to stdout")
    parser.add_argument("--root", type=pathlib.Path, default=REPO_ROOT,
                        help=f"Repository root (default: {REPO_ROOT})")
    args = parser.parse_args()

    root = args.root
    t_start = time.monotonic()

    print("=" * 72)
    print("SENTINEL APEX — JSON Sanitizer & Self-Healing Engine v134.0.0")
    print(f"Root   : {root}")
    print(f"Mode   : {'DRY-RUN (no writes)' if args.dry_run else 'FIX (auto-heal enabled)'}")
    print("=" * 72)

    files = scan_json_files = scan_repo(root)
    print(f"Scanning {len(files)} JSON files...")

    all_events: List[SanitizeEvent] = []
    modified_count = 0
    error_count = 0
    healed_count = 0
    regenerated_count = 0

    for path in files:
        file_events: List[SanitizeEvent] = []
        was_modified = process_json_file(path, root, args.dry_run, file_events)

        for ev in file_events:
            if ev.action == "REGENERATED":
                regenerated_count += 1
            elif ev.action in ("AUTO_HEALED", "BOM_STRIPPED", "STRUCTURE_FIXED"):
                healed_count += 1
            elif ev.action in ("PARSE_ERROR", "READ_ERROR", "WRITE_ERROR", "DECODE_FAILED"):
                error_count += 1

            severity_prefix = {
                "INFO": "  [OK]    ",
                "WARNING": "  [WARN]  ",
                "ERROR": "  [ERROR] ",
                "CRITICAL": "  [CRIT]  ",
            }.get(ev.severity, "  [?]     ")
            rel = ev.path
            print(f"{severity_prefix}{ev.action}: {rel} — {ev.detail}")

        all_events.extend(file_events)
        if was_modified:
            modified_count += 1

    elapsed = time.monotonic() - t_start

    print()
    print("=" * 72)
    print(f"Scan complete in {elapsed:.2f}s")
    print(f"  Files scanned     : {len(files)}")
    print(f"  Files modified    : {modified_co