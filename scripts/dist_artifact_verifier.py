#!/usr/bin/env python3
"""
scripts/dist_artifact_verifier.py
CYBERDUDEBIVASH(R) SENTINEL APEX v156.0 -- Pre-Deploy Dist Artifact Verifier
================================================================================
Pre-deployment gate: verifies dist/ integrity against deployment_manifest.json.

MANDATE:
  Pages deployment MUST NOT proceed if dist/ is inconsistent with the manifest.
  This is the last line of defense before customer-facing URLs are served.

VERIFICATION CHECKS:
  1. dist/deployment_manifest.json exists and is parseable
  2. Every file listed in manifest exists in dist/
  3. SHA-256 checksums match for all report HTML files
  4. No zero-byte report files
  5. Report count >= minimum threshold (adjusted for REPORT_RETENTION_DAYS mode)
  6. All report_url paths from feed files exist in dist/
  7. dist/ does NOT contain .github/ or scripts/ (artifact purity check)
  8. .nojekyll present (prevents Jekyll processing)

REPORT_RETENTION_DAYS AWARENESS (v156.0):
  When REPORT_RETENTION_DAYS > 0 (HOT-tier only deployment), dist/ will contain
  fewer reports than a full-history build.  The minimum threshold check is
  relaxed to MIN_REPORT_COUNT_RETENTION (default 1) so a recently-bootstrapped
  platform is not hard-blocked.  The full minimum (MIN_REPORT_COUNT = 10)
  applies only when REPORT_RETENTION_DAYS == 0 (full copy mode).

  CRITICAL: even in retention mode, all report_url feed paths MUST resolve in
  dist/ (Check 6).  The assumption is that report_archive_manager.py has already
  run git rm --cached on archived reports AND that the feed manifests have been
  updated to reference only HOT-tier reports.

EXIT CODES:
  0 = ALL checks passed -- dist/ is a valid, consistent deployment artifact
  1 = HARD FAIL -- dist/ is corrupt, incomplete, or inconsistent

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-DIST-VERIFIER] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.dist_artifact_verifier")

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR  = REPO_ROOT / "dist"
MANIFEST_PATH = DIST_DIR / "deployment_manifest.json"

# Minimum reports required for a valid deployment artifact (full-copy mode)
MIN_REPORT_COUNT = 10
# Minimum reports when REPORT_RETENTION_DAYS > 0 (HOT-tier retention mode)
# Set to 1: a freshly bootstrapped platform with 1 day of history is valid
MIN_REPORT_COUNT_RETENTION = 1
# Verify checksums for this many report files (sampling for speed)
CHECKSUM_SAMPLE_SIZE = 20
# These directories must NOT appear in dist/
PROHIBITED_DIST_DIRS = {".github", "scripts", "data", "config", "agent"}

# ── REPORT_RETENTION_DAYS awareness (v156.0) ─────────────────────────────────
# When > 0 the dist/ artifact contains only HOT-tier reports.  The verifier
# relaxes the minimum report count check accordingly and emits a clear INFO
# annotation so pipeline logs are self-documenting.
REPORT_RETENTION_DAYS = int(os.environ.get("REPORT_RETENTION_DAYS", "0"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_report_urls_from_feeds() -> List[str]:
    """Extract all report_url values from public feed files."""
    urls: List[str] = []
    feed_paths = [
        REPO_ROOT / "api" / "feed.json",
        REPO_ROOT / "feed.json",
        REPO_ROOT / "data" / "stix" / "feed_manifest.json",
    ]
    for fp in feed_paths:
        if not fp.exists():
            continue
        try:
            raw = fp.read_bytes().rstrip(b"\x00")
            data = json.loads(raw.decode("utf-8", errors="replace"))
            items = data if isinstance(data, list) else []
            for item in items:
                ru = (item.get("report_url") or "").strip()
                if ru and ru.startswith("/reports/") and not ru.startswith("http"):
                    urls.append(ru)
        except Exception as exc:
            log.warning("Could not parse %s: %s", fp.name, exc)
    return list(dict.fromkeys(urls))


def run_checks(manifest: Dict, retention_days: int = 0) -> Tuple[int, int]:
    """Run all verification checks. Returns (pass_count, fail_count).

    Args:
        manifest: Parsed deployment_manifest.json.
        retention_days: Value of REPORT_RETENTION_DAYS (0 = full-copy mode).
    """
    passes = 0
    fails  = 0

    def ok(msg: str):
        nonlocal passes
        log.info("  [PASS] %s", msg)
        passes += 1

    def fail(msg: str):
        nonlocal fails
        log.error("  [FAIL] %s", msg)
        fails += 1

    manifest_files = manifest.get("files", {})
    manifest_report_count = manifest.get("report_count", 0)

    # CHECK 1: Manifest sanity
    if manifest.get("schema") == "sentinel_apex_deployment_manifest_v1":
        ok(f"Manifest schema valid (v1), total_files={manifest.get('total_files')}, reports={manifest_report_count}")
    else:
        fail(f"Manifest schema unknown: {manifest.get('schema')}")

    # CHECK 2: Every manifest entry exists on disk
    missing_files: List[str] = []
    for rel_path in manifest_files:
        full_path = DIST_DIR / rel_path
        if not full_path.exists():
            missing_files.append(rel_path)
    if missing_files:
        fail(f"{len(missing_files)} manifest file(s) MISSING from dist/: {missing_files[:5]}...")
    else:
        ok(f"All {len(manifest_files)} manifest files present in dist/")

    # CHECK 3: SHA-256 checksum spot-check on report HTML files
    report_files = [k for k in manifest_files if k.startswith("reports/") and k.endswith(".html")]
    sample = report_files[:CHECKSUM_SAMPLE_SIZE]
    checksum_mismatches: List[str] = []
    for rel_path in sample:
        full_path = DIST_DIR / rel_path
        if not full_path.exists():
            continue
        expected = manifest_files[rel_path]["sha256"]
        actual   = sha256_file(full_path)
        if actual != expected:
            checksum_mismatches.append(rel_path)
    if checksum_mismatches:
        fail(f"Checksum mismatch for {len(checksum_mismatches)} report(s): {checksum_mismatches[:3]}")
    else:
        ok(f"Checksum spot-check passed ({len(sample)} sample reports)")

    # CHECK 4: No zero-byte report files
    zero_byte: List[str] = []
    for rel_path in report_files[:200]:
        full_path = DIST_DIR / rel_path
        if full_path.exists() and full_path.stat().st_size == 0:
            zero_byte.append(rel_path)
    if zero_byte:
        fail(f"{len(zero_byte)} zero-byte report file(s) detected: {zero_byte[:3]}")
    else:
        ok(f"No zero-byte report files (checked {min(len(report_files), 200)} reports)")

    # CHECK 5: Report count threshold (retention-mode aware)
    if retention_days > 0:
        min_count = MIN_REPORT_COUNT_RETENTION
        mode_tag  = f"RETENTION-MODE (last {retention_days} days)"
    else:
        min_count = MIN_REPORT_COUNT
        mode_tag  = "FULL-COPY mode"
    if manifest_report_count >= min_count:
        ok(f"Report count {manifest_report_count} >= minimum {min_count} [{mode_tag}]")
    else:
        fail(
            f"Report count {manifest_report_count} < minimum {min_count} "
            f"[{mode_tag}] (HARD FAIL)"
        )

    # CHECK 6: All report_url feed paths exist in dist/
    feed_urls = load_report_urls_from_feeds()
    missing_urls: List[str] = []
    for ru in feed_urls:
        dist_path = DIST_DIR / ru.lstrip("/")
        if not dist_path.exists():
            missing_urls.append(ru)
    if missing_urls:
        fail(f"{len(missing_urls)} report_url path(s) from feeds MISSING in dist/: {missing_urls[:5]}...")
    else:
        ok(f"All {len(feed_urls)} report_url feed paths present in dist/")

    # CHECK 7: Artifact purity — prohibited dirs must not be in dist/
    contaminated: List[str] = []
    for prohibited in PROHIBITED_DIST_DIRS:
        if (DIST_DIR / prohibited).exists():
            contaminated.append(prohibited)
    if contaminated:
        fail(f"dist/ contains prohibited dirs: {contaminated} (artifact contaminated)")
    else:
        ok("Artifact purity confirmed -- no internal dirs in dist/")

    # CHECK 8: .nojekyll present
    if (DIST_DIR / ".nojekyll").exists():
        ok("dist/.nojekyll present (Jekyll processing disabled)")
    else:
        fail("dist/.nojekyll MISSING -- GitHub Pages may attempt Jekyll processing")

    # CHECK 9: index.html present
    if (DIST_DIR / "index.html").exists():
        ok("dist/index.html present")
    else:
        fail("dist/index.html MISSING -- dashboard root inaccessible")

    # CHECK 10: deployment_manifest.json present
    if MANIFEST_PATH.exists():
        ok("dist/deployment_manifest.json present")
    else:
        fail("dist/deployment_manifest.json MISSING")

    return passes, fails


def main() -> int:
    t0 = time.time()
    log.info("=" * 70)
    log.info("SENTINEL APEX -- Pre-Deploy Dist Artifact Verifier v156.0")
    log.info("=" * 70)

    # ── Prerequisite: dist/ must exist ───────────────────────────────────────
    if not DIST_DIR.exists():
        log.error("HARD FAIL: dist/ directory does not exist.")
        log.error("Run: python3 scripts/build_dist_artifact.py FIRST")
        return 1

    # ── Prerequisite: manifest must exist ────────────────────────────────────
    if not MANIFEST_PATH.exists():
        log.error("HARD FAIL: dist/deployment_manifest.json not found.")
        log.error("Run: python3 scripts/build_dist_artifact.py FIRST")
        return 1

    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("HARD FAIL: Could not parse deployment_manifest.json: %s", exc)
        return 1

    retention_days = REPORT_RETENTION_DAYS
    if retention_days > 0:
        log.info("REPORT_RETENTION_DAYS=%d -- verifying in HOT-tier retention mode", retention_days)
    else:
        log.info("REPORT_RETENTION_DAYS=0 -- verifying in full-copy mode")

    log.info("Manifest loaded: %d files, %d reports, run_id=%s",
             manifest.get("total_files", 0),
             manifest.get("report_count", 0),
             manifest.get("pipeline_run_id", "?"))

    # ── Run all checks ────────────────────────────────────────────────────────
    log.info("")
    log.info("Running artifact verification checks...")
    passes, fails = run_checks(manifest, retention_days=retention_days)

    elapsed = time.time() - t0
    log.info("")
    log.info("=" * 70)
    log.info("DIST ARTIFACT VERIFICATION RESULT")
    log.info("=" * 70)
    log.info("  Passed : %d", passes)
    log.info("  Failed : %d", fails)
    log.info("  Elapsed: %.1fs", elapsed)
    log.info("=" * 70)

    if fails > 0:
        log.error("HARD FAIL: %d verification check(s) FAILED.", fails)
        log.error("Do NOT proceed with Pages deployment.")
        log.error("Fix the issues above before re-running the pipeline.")
        return 1

    log.info("ALL CHECKS PASSED -- dist/ is a valid, consistent deployment artifact.")
    log.info("Proceeding to GitHub Pages deployment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
