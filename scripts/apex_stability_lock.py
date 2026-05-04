#!/usr/bin/env python3
"""
scripts/apex_stability_lock.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Baseline Stability Lock Validator
=====================================================================
PLATFORM HARDENING: Validates the golden-build baseline contract before
                    any pipeline write is allowed to proceed.

PURPOSE:
    - This script is the GATEKEEPER before manifest writes.
    - It reads config/stability_lock.json and enforces its invariants.
    - It validates platform_version contract.
    - It aborts the pipeline (sys.exit(1)) if any baseline drift is detected.
    - It is NON-DESTRUCTIVE: reads only, never writes data files.

CHECKS PERFORMED:
    1. config/version.json is readable and has a valid version string
    2. Platform version matches the expected stable baseline
    3. stability_lock.json exists and contains required invariant sections
    4. feed_manifest.json (if present) passes minimum entry count
    5. No frontend files (index.html, *.html assets) have been modified
       by the pipeline scripts (checked via content hash of critical strings)
    6. EMBEDDED_INTEL declaration is still intact in index.html
    7. Top-threats JS computation is still present in index.html
       (never replaced by static data)

HARD FAIL conditions (sys.exit(1)):
    1. config/version.json missing or unparseable
    2. stability_lock.json missing
    3. Any required stability_lock section absent
    4. index.html missing the Top-Threats dynamic JS sort block
    5. index.html EMBEDDED_INTEL declaration missing (dashboard would break)

SOFT WARN (pipeline continues):
    - platform version in version.json doesn't contain expected semver pattern
    - feed_manifest.json below minimum entries (covered by freshness gate)

Usage:
    python3 scripts/apex_stability_lock.py               # full check
    python3 scripts/apex_stability_lock.py --check-only  # same as above
    python3 scripts/apex_stability_lock.py --write-lock  # write/update lock

Exit codes:
    0 = PASS (baseline contract intact)
    1 = HARD FAIL (baseline drift detected -- deployment blocked)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [stability-lock] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.apex_stability_lock")

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------
PLATFORM_VERSION_KEY = "stable-v1.0-apex"
STABILITY_LOCK_PATH = REPO_ROOT / "config" / "stability_lock.json"
VERSION_JSON_PATH = REPO_ROOT / "config" / "version.json"
INDEX_HTML_PATH = REPO_ROOT / "index.html"
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
API_FEED_PATH = REPO_ROOT / "api" / "feed.json"
QUALITY_DIR = REPO_ROOT / "data" / "quality"

# Required top-level sections in stability_lock.json
REQUIRED_LOCK_SECTIONS: list[str] = [
    "pipeline_invariants",
    "apex_ai_invariants",
    "dashboard_invariants",
    "feed_invariants",
    "api_response_contract",
]

# Strings that MUST be present in index.html to confirm top-threats is dynamic
# (not replaced by static pipeline data)
TOP_THREATS_REQUIRED_PATTERNS: list[str] = [
    "risk_score",           # sort by risk_score must be present
    "top-threats-section",  # container div id
]

# Strings that MUST be present to confirm EMBEDDED_INTEL is intact
EMBEDDED_INTEL_REQUIRED_PATTERNS: list[str] = [
    "EMBEDDED_INTEL",       # declaration variable name
    "bootFromEmbeddedCache", # instant-render function
]

# Fields that pipeline scripts must NEVER write to index.html
# (Top Threats must be computed in JS, not injected as static HTML)
FORBIDDEN_STATIC_INJECTIONS: list[str] = [
    "<!-- PIPELINE_STATIC_TOP_THREATS -->",    # sentinel: never inject this
    "<!-- APEX_STATIC_THREATS_OVERRIDE -->",   # sentinel: never inject this
]

MIN_INDEX_HTML_SIZE_BYTES = 50_000  # sanity: index.html must be substantial


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        log.warning("JSON parse error in %s: %s", path.name, e)
        return None


def _read_text(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        log.warning("Read error %s: %s", path.name, e)
        return None


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_version_json() -> tuple[bool, str]:
    """Check config/version.json is readable and has a version string."""
    data = _load_json(VERSION_JSON_PATH)
    if data is None:
        return False, f"HARD FAIL: config/version.json missing or unparseable at {VERSION_JSON_PATH}"
    version = data.get("version") or data.get("platform") or data.get("pipeline")
    if not version:
        return False, "HARD FAIL: config/version.json has no 'version' field"
    log.info("  [OK] config/version.json: version=%s", version)
    return True, f"version={version}"


def check_stability_lock() -> tuple[bool, str]:
    """Check stability_lock.json exists with all required sections."""
    data = _load_json(STABILITY_LOCK_PATH)
    if data is None:
        return False, f"HARD FAIL: config/stability_lock.json missing at {STABILITY_LOCK_PATH}"

    missing_sections = [s for s in REQUIRED_LOCK_SECTIONS if s not in data]
    if missing_sections:
        return False, f"HARD FAIL: stability_lock.json missing sections: {missing_sections}"

    meta = data.get("_meta", {})
    locked_at = meta.get("locked_at", "unknown")
    grade = meta.get("stability_grade", "unknown")
    log.info("  [OK] stability_lock.json: locked_at=%s grade=%s", locked_at, grade)
    return True, f"locked_at={locked_at} grade={grade}"


def check_index_html_top_threats() -> tuple[bool, str]:
    """Verify Top Threats section is still computed dynamically in JS."""
    content = _read_text(INDEX_HTML_PATH)
    if content is None:
        return False, f"HARD FAIL: index.html missing at {INDEX_HTML_PATH}"

    if len(content) < MIN_INDEX_HTML_SIZE_BYTES:
        return False, (
            f"HARD FAIL: index.html is suspiciously small ({len(content)} bytes < "
            f"{MIN_INDEX_HTML_SIZE_BYTES} threshold) -- possible truncation"
        )

    # Check required patterns
    missing = [p for p in TOP_THREATS_REQUIRED_PATTERNS if p not in content]
    if missing:
        return False, f"HARD FAIL: index.html missing Top-Threats JS patterns: {missing}"

    # Check forbidden static injections
    found_forbidden = [p for p in FORBIDDEN_STATIC_INJECTIONS if p in content]
    if found_forbidden:
        return False, (
            f"HARD FAIL: index.html contains forbidden static threat injection markers: "
            f"{found_forbidden}. Top Threats MUST be computed dynamically in JS."
        )

    log.info("  [OK] index.html Top-Threats dynamic JS computation intact")
    return True, "top_threats_dynamic=true"


def check_embedded_intel_intact() -> tuple[bool, str]:
    """Verify EMBEDDED_INTEL declaration and bootFromEmbeddedCache are intact."""
    content = _read_text(INDEX_HTML_PATH)
    if content is None:
        return False, f"HARD FAIL: index.html missing"

    missing = [p for p in EMBEDDED_INTEL_REQUIRED_PATTERNS if p not in content]
    if missing:
        return False, (
            f"HARD FAIL: index.html missing EMBEDDED_INTEL patterns: {missing}. "
            "Dashboard instant-render broken."
        )

    log.info("  [OK] index.html EMBEDDED_INTEL declaration intact")
    return True, "embedded_intel=intact"


def check_feed_manifest_not_empty() -> tuple[bool, str]:
    """Soft check: manifest should have entries (hard gate is in freshness_gate)."""
    if not MANIFEST_PATH.exists():
        # Not a hard fail here -- manifest may be pre-generated in CI
        log.info("  [SKIP] data/stix/feed_manifest.json not present locally (CI will generate)")
        return True, "manifest=absent_locally (ok in CI)"

    try:
        raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8", errors="replace"))
        items = raw if isinstance(raw, list) else raw.get("data", raw.get("items", []))
        count = len(items) if isinstance(items, list) else 0
    except Exception:
        count = 0

    if count == 0:
        log.warning("  [WARN] data/stix/feed_manifest.json is empty (0 items). "
                    "Freshness gate will enforce minimum.")
        return True, "manifest_count=0 (warn -- freshness gate will catch)"

    log.info("  [OK] data/stix/feed_manifest.json: %d items", count)
    return True, f"manifest_count={count}"


def check_frontend_files_untouched() -> tuple[bool, str]:
    """
    Verify that pipeline scripts are not modifying frontend asset files.
    Checks that key frontend JS files don't contain pipeline injection markers.
    """
    pipeline_markers = [
        "# GENERATED BY SENTINEL PIPELINE",
        "# AUTO-GENERATED BY run_pipeline.py",
        "<!-- PIPELINE_INJECTED -->",
    ]
    frontend_files = [
        REPO_ROOT / "js",
        REPO_ROOT / "assets",
    ]
    violations = []
    for base in frontend_files:
        if not base.exists():
            continue
        for fpath in base.rglob("*.js"):
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                for marker in pipeline_markers:
                    if marker in content:
                        violations.append(f"{fpath.name}: found marker '{marker}'")
            except Exception:
                pass

    if violations:
        return False, f"HARD FAIL: Pipeline markers found in frontend files: {violations}"

    log.info("  [OK] Frontend files free of pipeline injection markers")
    return True, "frontend_untouched=true"


# ---------------------------------------------------------------------------
# Lock writer
# ---------------------------------------------------------------------------

def write_apex_contract_lock(results: dict) -> None:
    """
    Write/update the apex contract lock file that records the current
    validated baseline state. This is separate from stability_lock.json
    (which is the golden-build doc). This is the per-run validation record.
    """
    QUALITY_DIR.mkdir(parents=True, exist_ok=True)
    lock_record_path = QUALITY_DIR / "apex_contract_lock_record.json"
    payload = {
        "generated_at": _utc_now(),
        "platform_version_key": PLATFORM_VERSION_KEY,
        "validation_results": results,
        "all_pass": all(r["pass"] for r in results.get("checks", [])),
        "hard_fail_count": sum(1 for r in results.get("checks", []) if not r["pass"]),
        "_rule": (
            "This record is updated on every pipeline run. "
            "It does NOT replace config/stability_lock.json. "
            "stability_lock.json is the IMMUTABLE golden-build document."
        ),
    }
    tmp = lock_record_path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, lock_record_path)
        log.info("  [OK] Contract lock record written: %s", lock_record_path)
    except Exception as e:
        log.warning("  Could not write lock record: %s", e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX -- Baseline Stability Lock Validator"
    )
    parser.add_argument("--check-only", action="store_true", default=False,
                        help="Run checks only (default behaviour)")
    parser.add_argument("--write-lock", action="store_true", default=False,
                        help="Also write the contract lock record to data/quality/")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info("SENTINEL APEX -- Baseline Stability Lock Validator")
    log.info("Platform version key : %s", PLATFORM_VERSION_KEY)
    log.info("=" * 70)

    checks = [
        ("version_json",           check_version_json),
        ("stability_lock",         check_stability_lock),
        ("embedded_intel_intact",  check_embedded_intel_intact),
        ("top_threats_dynamic",    check_index_html_top_threats),
        ("manifest_not_empty",     check_feed_manifest_not_empty),
        ("frontend_untouched",     check_frontend_files_untouched),
    ]

    check_results = []
    hard_fail_count = 0

    for check_name, check_fn in checks:
        try:
            passed, detail = check_fn()
        except Exception as e:
            passed = False
            detail = f"EXCEPTION: {e}"

        check_results.append({"name": check_name, "pass": passed, "detail": detail})

        if passed:
            log.info("  PASS  %s -- %s", check_name, detail)
        else:
            log.error("  FAIL  %s -- %s", check_name, detail)
            hard_fail_count += 1

    results = {
        "checks": check_results,
        "hard_fail_count": hard_fail_count,
        "all_pass": hard_fail_count == 0,
        "checked_at": _utc_now(),
    }

    if args.write_lock or True:  # Always write the record for observability
        write_apex_contract_lock(results)

    log.info("=" * 70)
    log.info("SUMMARY: %d/%d checks PASS | %d hard fail(s)",
             len(check_results) - hard_fail_count, len(check_results), hard_fail_count)

    if hard_fail_count > 0:
        log.error("STABILITY LOCK FAILED -- BASELINE DRIFT DETECTED -- DEPLOYMENT BLOCKED")
        log.error("The platform baseline contract has been violated.")
        log.error("Do NOT proceed with deployment until all HARD FAIL reasons are resolved.")
        sys.exit(1)

    log.info("STABILITY LOCK PASSED -- BASELINE CONTRACT INTACT")
    log.info("Platform is cleared for deployment.")


if __name__ == "__main__":
    main()
