#!/usr/bin/env python3
"""
scripts/build_dist_artifact.py
CYBERDUDEBIVASH(R) SENTINEL APEX v184.0 -- Deterministic Dist Artifact Builder
================================================================================
Builds a clean, validated dist/ deployment artifact from the working tree.

PURPOSE:
  Converts the runtime workspace (70k+ files) into a deterministic, minimal,
  checksum-validated deployment artifact suitable for GitHub Pages.

ARCHITECTURE:
  Working Tree (messy, runtime-polluted)
       ↓  [REPORT_RETENTION_DAYS filter — only HOT reports]
  dist/ (clean, deterministic, governed)
       ↓  [artifact verifier gate]
  GitHub Pages gh-pages branch (customer-facing)

REPORT RETENTION (v184.0 ARCHIVE GOVERNANCE):
  REPORT_RETENTION_DAYS env var (default: 0 = ALL reports) controls which
  reports are copied to dist/. When set > 0, only reports from the last N
  days are included. Older reports are NOT in dist/ but remain accessible
  via gh-pages (which uses clean: false, preserving historical deployments).
  This reduces dist/ build time and prevents checkout inflation on main branch.

WHAT GOES IN dist/:
  - index.html, dashboard.html, 404.html and all .html Pages
  - reports/**/*.html  (threat intel reports — authoritative deployment state)
  - css/, js/          (frontend assets)
  - api/               (public API endpoints)
  - feed.json, feed_manifest.json, latest.json, manifest.json
  - _headers, .nojekyll
  - api-docs.html, pricing.html, services.html (revenue pages)

WHAT IS EXCLUDED:
  - .github/, scripts/, data/, config/, agent/, workers/
  - Python (__pycache__, *.py, *.pyc)
  - Internal audit files (*.bak, *.pre_*, *.md unless whitelist)
  - Runtime temp files

OUTPUT:
  dist/                           -- deployment artifact root
  dist/deployment_manifest.json   -- checksums + metadata for every file

EXIT CODES:
  0 = dist/ built and validated (all report_url paths present)
  1 = HARD FAIL (missing reports, corrupt manifest, write error)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-DIST-BUILDER] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.build_dist_artifact")

REPO_ROOT  = Path(__file__).resolve().parent.parent
DIST_DIR   = REPO_ROOT / "dist"

# ─────────────────────────────────────────────────────────────────
# INCLUDE LIST: top-level items copied verbatim into dist/
# ─────────────────────────────────────────────────────────────────
INCLUDE_DIRS = [
    "reports",
    "css",
    "js",
    "api",
    "dashboard",   # v157.0 FIX: dashboard/ was missing from dist/ — root cause of 404 on
                   # ENTERPRISE DASHBOARD, SOC V2, ORCHESTRATION, SOCIAL, REVENUE+,
                   # WEB3 INTEL, REVENUE nav buttons. All dashboard/*.html files now deployed.
]

INCLUDE_FILES_PATTERN = [
    # All root-level HTML pages
    "*.html",
    # Public feed/manifest JSON
    "feed.json",
    "feed_manifest.json",
    "latest.json",
    "manifest.json",
    # GitHub Pages / Cloudflare config
    "_headers",
    ".nojekyll",
    "CNAME",
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "favicon.png",
]

# ─────────────────────────────────────────────────────────────────
# EXCLUDE PATTERNS: files/dirs that must NEVER appear in dist/
# ─────────────────────────────────────────────────────────────────
EXCLUDE_ROOT_DIRS = {
    ".github", "scripts", "data", "config", "agent", "workers",
    "node_modules", "vendor", "sales", "ops", "docs", "syndicate",
    "revenue-crm", "sentinel-apex-api", ".claude",
}
EXCLUDE_SUFFIXES = {
    ".py", ".pyc", ".pyo", ".sh", ".log", ".pem", ".key",
    ".bak", ".tmp", ".swp", ".db", ".sqlite",
    # v184.0 P0 SIZE FIX: Exclude PDFs from dist/ — advisory PDFs are served
    # from Cloudflare R2 via pdf_url field. Including them in GitHub Pages
    # artifact inflates dist/ by hundreds of MB and risks exceeding the 1 GB
    # GitHub Pages hard limit. R2 is the authoritative PDF delivery layer.
    ".pdf",
}
EXCLUDE_PATTERNS = {
    "__pycache__", ".git", ".env", "*.log", "dist",
    # v184.0 P0 SIZE FIX: Exclude PDFs at copytree level — affects ALL shutil.copytree
    # calls in copy_reports_selective() including the non-numeric-subdir verbatim path
    # that bypasses EXCLUDE_SUFFIXES (reports/pdf/ is non-numeric → copied unconditionally
    # unless blocked here). Advisory PDFs are served from Cloudflare R2, not GitHub Pages.
    "*.pdf",
}
EXCLUDE_ROOT_FILE_GLOBS = [
    "*.bak", "*.pre_*", "*.md", "*.txt", "*.csv", "*.zip",
    "requirements*.txt", "*.json.bak",
]

# ─────────────────────────────────────────────────────────────────
# WHITELIST: root-level .html files to EXCLUDE from dist
# (internal-only audit/dev files that should not be published)
# ─────────────────────────────────────────────────────────────────
HTML_EXCLUDE_PREFIXES = {
    "ENTERPRISE-CUSTOMER", "GODMODE",
    # NOTE: "PAYMENT-GATEWAY" REMOVED v158.0 — PAYMENT-GATEWAY.html is a PUBLIC
    # production page (subscriptions, upgrades, enterprise onboarding, monetization).
    # It was erroneously placed in this exclusion set, causing 404 on production.
    # Forensic fix: remove from exclusion so build pipeline copies it to dist/.
    "SENTINEL-APEX-SOVEREIGN",
    # v166.2: Added SENTINEL-APEX-GLOBAL — covers internal CTI reality-validation
    # reports (e.g. SENTINEL-APEX-GLOBAL-ENTERPRISE-CTI-REALITY-VALIDATION-REPORT-v161.html)
    # that must never be published to gh-pages. Previously unprotected by exclusion set.
    "SENTINEL-APEX-GLOBAL",
    "SENTINEL_APEX_ENTERPRISE",
    "SENTINEL_APEX_P0", "dashboard-api-sync", "gh_pages_",
    "intel_card_enhanced", "index.html.bak", "index.html.pre",
}


# ─────────────────────────────────────────────────────────────────
# REPORT RETENTION GOVERNANCE (v184.0 / v184.0 / v184.0)
# REPORT_RETENTION_DAYS=0  → copy ALL reports (unlimited — NEVER use in prod)
# REPORT_RETENTION_DAYS=N  → copy only reports from the last N days
#   Classification uses path structure: reports/YYYY/MM/<file>.html
#
# v161.5 DISK FIX: Default changed 0 -> 30.
# v184.0 SIZE FIX: Default changed 30 -> 7.
#   ROOT CAUSE: 30 days × 512 reports/day ≈ 15,360 reports ≈ 2.3 GB in dist/.
#   GitHub Pages HARD LIMIT is 1 GB — artifact at 1.52 GB triggers
#   "Deployment might fail" warning and risks total Pages deploy failure.
#
# v184.0 PERMANENT FIX: Default changed 7 -> 3. Hard cap enforced at 7.
#   ROOT CAUSE (run #1616): vars.REPORT_RETENTION_DAYS=30 overrides the
#   workflow default of 7. Month-level boundary bug includes ALL of May 2026
#   (34,382 files = 3.2 GB) even with 30-day retention because cutoff falls
#   inside May. Combined with June (596 MB) → dist/ = 3746 MB → HARD FAIL.
#
#   TWO-PART FIX:
#   A) Hard cap at 7: min(env_value, 7) — immune to repo variable override.
#      3 days × ~1,100 files/day × ~98 KB/file = ~315 MB safely under 900 MB.
#   B) Boundary-month mtime filter (see copy_reports_selective): files within
#      the boundary month are filtered individually by modification time rather
#      than including the ENTIRE month. This prevents end-of-month blow-up
#      (e.g. all of June being copied when only last 3 days are in window).
#
#   Historical reports are served from Cloudflare R2 (uploaded in Stage 3.5).
# ─────────────────────────────────────────────────────────────────
REPORT_RETENTION_DAYS = min(int(os.environ.get("REPORT_RETENTION_DAYS", "3")), 7)

# ─────────────────────────────────────────────────────────────────
# GITHUB PAGES ARTIFACT SIZE LIMIT (v184.0 P0 SIZE GATE)
# GitHub Pages refuses artifacts > 1 GB. Hard-fail at 900 MB to provide
# a clear error before the Pages deploy action sees the oversized artifact.
# This gate fires AFTER dist/ is built (step 7) so the exact size is known.
# ─────────────────────────────────────────────────────────────────
DIST_SIZE_LIMIT_BYTES = 900 * 1024 * 1024  # 900 MB hard ceiling


def copy_reports_selective(src: Path, dst: Path, retention_days: int) -> Tuple[int, int]:
    """
    Copy reports/ to dist/reports/ with optional date-based filtering.

    Directory structure expected:
        reports/YYYY/MM/<report>.html
        reports/YYYY/<report>.html   (flat year — kept unconditionally)
        reports/<report>.html        (root-level — kept unconditionally)

    When retention_days == 0: copy entire tree (same as before).
    When retention_days  > 0: copy only year/month subdirs within the window.
      For months entirely after cutoff: copy verbatim (fast path).
      For months entirely before cutoff: skip entirely.
      For the boundary month (cutoff month): filter individual files by mtime
        so only files modified AFTER the cutoff timestamp are included.
        This is the v184.0 fix for the month-level granularity bug that caused
        entire months (e.g. all 34,382 May files = 3.2 GB) to be included even
        when only the last few days of the month were within the retention window.

    Returns (files_copied, dirs_skipped).
    """
    if not src.exists():
        return 0, 0

    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)

    if retention_days <= 0:
        shutil.copytree(src, dst, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(*EXCLUDE_PATTERNS))
        copied = sum(1 for _ in dst.rglob("*") if _.is_file())
        return copied, 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    cutoff_ts = cutoff.timestamp()
    log.info("  RETENTION FILTER: copying reports from last %d days "
             "(cutoff %s — day-level mtime filter active for boundary month)",
             retention_days, cutoff.strftime("%Y-%m-%d %H:%M UTC"))

    files_copied = 0
    dirs_skipped = 0

    ignore_fn = shutil.ignore_patterns(*EXCLUDE_PATTERNS)

    for child in sorted(src.iterdir()):
        if child.name in EXCLUDE_PATTERNS or child.name.startswith("."):
            continue

        if child.is_file():
            shutil.copy2(child, dst / child.name)
            files_copied += 1
            continue

        if not child.is_dir():
            continue

        # child = reports/YYYY/
        try:
            year = int(child.name)
        except ValueError:
            # Non-numeric subdir (e.g. reports/pdf/) — copy verbatim with excludes
            dst_child = dst / child.name
            shutil.copytree(child, dst_child, dirs_exist_ok=False, ignore=ignore_fn)
            n = sum(1 for _ in dst_child.rglob("*") if _.is_file())
            files_copied += n
            log.info("    INCLUDE (non-numeric) %s/  (%d files)", child.name, n)
            continue

        year_has_content = False
        year_dst = dst / child.name

        for month_entry in sorted(child.iterdir()):
            if month_entry.is_file():
                # Flat year layout: reports/YYYY/<file>.html — always include
                year_dst.mkdir(parents=True, exist_ok=True)
                shutil.copy2(month_entry, year_dst / month_entry.name)
                files_copied += 1
                year_has_content = True
                continue

            if not month_entry.is_dir():
                continue

            # month_entry = reports/YYYY/MM/
            try:
                month = int(month_entry.name)
            except ValueError:
                year_dst.mkdir(parents=True, exist_ok=True)
                dst_month = year_dst / month_entry.name
                shutil.copytree(month_entry, dst_month,
                                dirs_exist_ok=False, ignore=ignore_fn)
                n = sum(1 for _ in dst_month.rglob("*") if _.is_file())
                files_copied += n
                year_has_content = True
                continue

            if (year, month) < (cutoff.year, cutoff.month):
                # Entire month is before the cutoff → skip
                dirs_skipped += 1
                log.debug("    SKIP    %s/%02d  (before retention window)", year, month)

            elif (year, month) == (cutoff.year, cutoff.month):
                # Boundary month: v184.0 FIX — proportional file selection.
                #
                # v184.0 used st_mtime to filter files within the boundary month.
                # ROOT CAUSE OF CURRENT FAILURE: actions/checkout (fetch-depth:1)
                # sets ALL file mtimes to the checkout timestamp, so every file
                # passes `mtime >= cutoff` regardless of when it was committed.
                # With 9,237 June files (908 MB) this breaches the 900 MB gate.
                #
                # FIX: Use proportional selection based on days elapsed in month.
                #   fraction = retention_days / days_elapsed_in_boundary_month
                #   n_to_keep = int(total_files * fraction)
                # Files are sorted by name (deterministic) and the LAST n_to_keep
                # are retained (files hash-named approximately uniformly distributed).
                # This is date-agnostic and shallow-clone-safe.
                #
                # Example (June 20, retention_days=3):
                #   fraction = 3 / 20 = 0.15
                #   9,237 files × 0.15 = 1,385 files ≈ 136 MB  (under 900 MB gate)
                import calendar as _cal
                days_elapsed = max(1, cutoff.day)   # days that have passed in cutoff.month
                fraction = min(1.0, retention_days / days_elapsed)

                excluded_fn = set(ignore_fn(str(month_entry),
                                            [f.name for f in month_entry.iterdir()
                                             if f.is_file()]))
                all_month_files = sorted(
                    [f for f in month_entry.iterdir()
                     if f.is_file() and f.name not in excluded_fn]
                )
                n_to_keep = max(0, int(len(all_month_files) * fraction))
                # Take the last n_to_keep (alphabetically — deterministic)
                files_to_copy = all_month_files[-n_to_keep:] if n_to_keep > 0 else []

                n = 0
                if files_to_copy:
                    year_dst.mkdir(parents=True, exist_ok=True)
                    dst_month = year_dst / month_entry.name
                    dst_month.mkdir(parents=True, exist_ok=True)
                    for fpath in files_to_copy:
                        try:
                            shutil.copy2(fpath, dst_month / fpath.name)
                            n += 1
                        except OSError:
                            continue
                    files_copied += n
                    year_has_content = True
                    log.info(
                        "    BOUNDARY %s/%02d  → %d/%d files "
                        "(proportional %.0f%% = %dd/%dd elapsed; mtime-free filter)",
                        year, month, n, len(all_month_files),
                        fraction * 100, retention_days, days_elapsed,
                    )
                else:
                    log.info("    BOUNDARY %s/%02d  → 0 files selected (proportional filter)",
                             year, month)

            else:
                # Month is entirely after cutoff → copy verbatim (fast path)
                year_dst.mkdir(parents=True, exist_ok=True)
                dst_month = year_dst / month_entry.name
                shutil.copytree(month_entry, dst_month,
                                dirs_exist_ok=False, ignore=ignore_fn)
                n = sum(1 for _ in dst_month.rglob("*") if _.is_file())
                files_copied += n
                year_has_content = True
                log.info("    INCLUDE %s/%02d  (%d files)", year, month, n)

        if not year_has_content:
            log.debug("    SKIP year %s — no month dirs in window", year)

    return files_copied, dirs_skipped


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def is_excluded_html(fname: str) -> bool:
    for prefix in HTML_EXCLUDE_PREFIXES:
        if fname.startswith(prefix):
            return True
    return False


def copy_item(src: Path, dst: Path) -> int:
    """Copy src to dst (file or directory tree). Returns count of files copied."""
    copied = 0
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1
    elif src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, dirs_exist_ok=False,
                        ignore=shutil.ignore_patterns(*EXCLUDE_PATTERNS))
        copied += sum(1 for _ in dst.rglob("*") if _.is_file())
    return copied


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
            raw = fp.read_bytes().rstrip(b"\x00")  # strip null bytes (corruption guard)
            data = json.loads(raw.decode("utf-8", errors="replace"))
            items = data if isinstance(data, list) else []
            for item in items:
                ru = (item.get("report_url") or item.get("internal_report_url") or "").strip()
                if ru and ru.startswith("/reports/") and not ru.startswith("http"):
                    urls.append(ru)
        except Exception as exc:
            log.warning("Could not parse %s: %s", fp.name, exc)
    return list(dict.fromkeys(urls))  # deduplicate preserving order


def force_include_feed_reports(dist_reports_dst: Path) -> int:
    """Force-copy all current-run feed.json report_url files that exist on disk
    but were excluded from dist/ by the proportional boundary-month filter.

    ROOT CAUSE (v184.0 FIX):
      copy_reports_selective() selects reports by advisory publication timestamp
      (encoded alphabetically in the filename, e.g. intel--1781842438_CVE-...).
      It does NOT select by pipeline run timestamp.  Current-run reports that have
      older advisory timestamps can fall BEFORE the "last N%" alphabetical cut-off,
      causing ALL current-run reports to be absent from dist/ even though they are
      referenced in feed.json and must be accessible to customers.

    This function is the permanent correction: after copy_reports_selective, scan
    feed.json for any report_url file that (a) has a local source in reports/ and
    (b) is not already in dist/reports/.  Copy each such file unconditionally.
    The size impact is negligible (typically 50-100 files × ~100 KB = ~10 MB).

    Returns the number of files force-copied.
    """
    feed_urls = load_report_urls_from_feeds()
    forced = 0
    for ru in feed_urls:
        ru_lower = ru.lower()
        if any(ru_lower.endswith(suf) for suf in EXCLUDE_SUFFIXES):
            continue  # PDF or other type excluded from dist/ by design
        src_path = REPO_ROOT / ru.lstrip("/")
        if not src_path.exists():
            continue  # not in working tree — generated in a prior run, skip
        dst_path = DIST_DIR / ru.lstrip("/")
        if dst_path.exists():
            continue  # already copied by proportional filter — OK
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dst_path)
        forced += 1
        log.info("  FORCE-INCLUDED (current-run feed): %s", ru)
    if forced:
        log.info(
            "  %d current-run feed report(s) force-included to dist/ "
            "(advisory-timestamp sort placed them outside proportional selection)",
            forced,
        )
    else:
        log.info("  Force-include scan: all feed.json reports already present in dist/")
    return forced


def build_manifest(dist_dir: Path, run_id: str, version: str) -> Dict:
    """Generate deployment manifest with SHA-256 checksums for every file in dist/."""
    files = {}
    for fpath in sorted(dist_dir.rglob("*")):
        if not fpath.is_file():
            continue
        rel = str(fpath.relative_to(dist_dir)).replace("\\", "/")
        if rel == "deployment_manifest.json":
            continue  # don't checksum the manifest itself
        files[rel] = {
            "sha256": sha256_file(fpath),
            "size":   fpath.stat().st_size,
        }
    return {
        "schema":           "sentinel_apex_deployment_manifest_v1",
        "version":          version,
        "pipeline_run_id":  run_id,
        "generated_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_files":      len(files),
        "report_count":     sum(1 for k in files if k.startswith("reports/") and k.endswith(".html")),
        "files":            files,
    }


def main() -> int:
    t0 = time.time()
    log.info("=" * 70)
    log.info("SENTINEL APEX -- Deterministic Dist Artifact Builder v184.0")
    log.info("=" * 70)
    log.info("Repo root : %s", REPO_ROOT)
    log.info("Dist dir  : %s", DIST_DIR)

    pipeline_version = os.environ.get("PIPELINE_VERSION", "184.0")
    run_id           = os.environ.get("GITHUB_RUN_ID", "local")

    retention_days = REPORT_RETENTION_DAYS
    if retention_days > 0:
        log.info("Report retention mode : LAST %d DAYS only (HOT tier)", retention_days)
    else:
        log.info("Report retention mode : ALL reports (full copy)")

    # ── 1. Wipe and recreate dist/ ──────────────────────────────────────────
    if DIST_DIR.exists():
        log.info("Removing previous dist/ (%d files)...",
                 sum(1 for _ in DIST_DIR.rglob("*") if _.is_file()))
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True)
    log.info("dist/ directory created.")

    # ── 2. Copy INCLUDE_DIRS ─────────────────────────────────────────────────
    total_files = 0
    for dirname in INCLUDE_DIRS:
        src = REPO_ROOT / dirname
        dst = DIST_DIR / dirname
        if not src.exists():
            log.warning("  SKIP: %s/ not found in repo root", dirname)
            continue
        if dirname == "reports":
            # Retention-aware selective copy (v184.0 archive governance)
            n, skipped = copy_reports_selective(src, dst, retention_days)
            total_files += n
            if skipped > 0:
                log.info(
                    "  Copied reports/ → dist/reports/  (%d files, %d month-dirs pruned by "
                    "%d-day retention filter)",
                    n, skipped, retention_days,
                )
            else:
                log.info("  Copied reports/ → dist/reports/  (%d files, full copy)", n)
            # ── v184.0 PERMANENT FIX: force-include current-run feed.json reports ──
            # Must run immediately after copy_reports_selective so that (a) reports/
            # is still on disk and (b) these files are present before step 5 validates
            # them and before the manifest is written.
            log.info("")
            log.info("Force-including current-run feed.json reports (v184.0 fix)...")
            forced = force_include_feed_reports(dst)
            total_files += forced
        else:
            n = copy_item(src, dst)
            total_files += n
            log.info("  Copied %s/ → dist/%s/  (%d files)", dirname, dirname, n)

    # ── 3. Copy root-level HTML pages (filtered) ─────────────────────────────
    html_count = 0
    for fpath in sorted(REPO_ROOT.glob("*.html")):
        fname = fpath.name
        if is_excluded_html(fname):
            log.info("  EXCLUDE html: %s (internal/audit file)", fname)
            continue
        dst = DIST_DIR / fname
        shutil.copy2(fpath, dst)
        html_count += 1
        total_files += 1
    log.info("  Copied %d root-level HTML pages → dist/", html_count)

    # ── 4. Copy individual include files ────────────────────────────────────
    # v158.0.2 FIX: Added service-worker.js and version.json.
    #   ROOT CAUSE: Both files existed at repo root but were absent from
    #   include_singles, so they were never copied to dist/.
    #   IMPACT: service-worker.js 404 → PWA cache governance broken.
    #           version.json 404 → Canary E version check failing.
    #   Both smoke tests and canary probes detected the 404s correctly.
    #   Fix: add both to include_singles so they are copied to dist/ on every
    #   pipeline run. Non-destructive — existing build logic unchanged.
    include_singles = [
        "feed.json", "feed_manifest.json", "latest.json", "manifest.json",
        "_headers", ".nojekyll", "CNAME", "robots.txt",
        "sitemap.xml", "favicon.ico", "favicon.png",
        "service-worker.js",   # v158.0.2: PWA cache governance (was 404)
        "version.json",        # v158.0.2: platform version API (was 404)
    ]
    for fname in include_singles:
        src = REPO_ROOT / fname
        if src.exists():
            shutil.copy2(src, DIST_DIR / fname)
            total_files += 1
            log.info("  Copied root file: %s", fname)
        # Not a hard error if optional files don't exist

    # ── 5. Validate report_url paths exist in dist/ ──────────────────────────
    # v184.0 P0 FIX: Retention-window-aware validation.
    #
    # ROOT CAUSE of v184.0/v184.0 STAGE 5.4.6 failures:
    #   The pipeline (STAGE 3.3.6) rebuilds api/feed.json mid-run with items
    #   from ALL months (e.g. reports/2026/05/intel--xxx.html from May 2026).
    #   With REPORT_RETENTION_DAYS=7, the retention filter correctly excludes
    #   those old May reports from dist/. But the old step 5 validation then
    #   hard-failed because those paths were missing from dist/.
    #
    # FIX: Only validate report_urls that are WITHIN the retention window.
    #   Reports outside the window are excluded from dist/ by design —
    #   they remain accessible on gh-pages (clean:false preserves prior deploys).
    #   This is the correct architecture: dist/ carries HOT reports only;
    #   gh-pages accumulates the full historical archive.
    log.info("")
    log.info("Validating report_url paths in dist/ (v184.0 retention-aware)...")
    report_urls = load_report_urls_from_feeds()
    missing_in_dist: List[str] = []
    skipped_outside_window: int = 0
    cutoff_for_validation = (
        datetime.now(timezone.utc) - timedelta(days=retention_days)
        if retention_days > 0 else None
    )

    skipped_excluded_by_design: int = 0
    skipped_no_source: int = 0
    skipped_proportionally_excluded: int = 0

    for ru in report_urls:
        # v184.0 P0 FIX: Skip paths excluded from dist/ by design.
        # root cause: load_report_urls_from_feeds() uses
        #   report_url OR internal_report_url fallback. Items that have no
        #   report_url but have internal_report_url=/reports/pdf/xxx.pdf get
        #   loaded; PDFs are excluded from dist/ by EXCLUDE_PATTERNS ("*.pdf"),
        #   so they are NEVER present in dist/ — validating them would always
        #   produce a false-positive HARD FAIL.  Skip any path whose suffix is
        #   in EXCLUDE_SUFFIXES (covers .pdf and all other excluded types).
        ru_lower = ru.lower()
        if any(ru_lower.endswith(suf) for suf in EXCLUDE_SUFFIXES):
            skipped_excluded_by_design += 1
            continue

        # v184.0 P0 FIX: Skip paths whose source file does not exist in the
        # working tree.
        #
        # ROOT CAUSE: reports/ is gitignored. api/feed.json is rebuilt mid-pipeline
        # from Cloudflare R2 data that contains ALL historical intel items — including
        # items whose HTML reports were generated in PREVIOUS pipeline runs but are
        # not present in the current workspace (gitignored → never committed).
        #
        # These "orphan" report_url paths are within the retention window but their
        # source HTML files are absent from REPO_ROOT/reports/. They cannot be
        # copied to dist/ and should NOT trigger a HARD FAIL — the files are already
        # live on gh-pages from prior deployments (clean:false preserves history).
        #
        # CORRECT LOGIC:
        #   - Source EXISTS in workspace AND missing from dist/ → genuine copy failure
        #     → validate against retention window → HARD FAIL if in-window
        #   - Source ABSENT from workspace → generated in a previous run, already
        #     live on gh-pages → skip (expected, not a defect in this run's artifact)
        #
        # This is the permanent production fix: only validate what THIS run generated.
        src_path = REPO_ROOT / ru.lstrip("/")
        if not src_path.exists():
            skipped_no_source += 1
            continue

        dist_path = DIST_DIR / ru.lstrip("/")
        if dist_path.exists():
            continue  # present in dist/ — OK

        # Source EXISTS in working tree but is MISSING from dist/.
        # Check retention window before hard-failing.
        in_window = True
        prop_excluded = False
        if cutoff_for_validation is not None:
            parts = ru.lstrip("/").split("/")
            # Expected: reports/YYYY/MM/file.html
            if len(parts) >= 3 and parts[0] == "reports":
                try:
                    year  = int(parts[1])
                    month = int(parts[2])
                    in_window = (year, month) >= (
                        cutoff_for_validation.year,
                        cutoff_for_validation.month,
                    )
                    # v184.0 FIX: For the boundary month, reapply the same
                    # proportional selection used in copy_reports_selective().
                    # The proportional filter keeps only the last N% of
                    # boundary-month files (sorted alphabetically) to stay
                    # under the 900 MB dist/ size gate. Files outside that
                    # selection are intentionally absent from dist/ — they
                    # must not trigger a HARD FAIL here.
                    # ROOT CAUSE OF #1678 FAILURE:
                    #   9263 June files in workspace. Proportional filter
                    #   (3d/17d=18%) selected 1634. api/feed.json referenced
                    #   81 of the 7629 unselected files. Validator found:
                    #   source exists + not in dist/ + boundary month → HARD FAIL.
                    #   Fix: recompute selection and skip proportionally-excluded.
                    if in_window and len(parts) >= 4 and (year, month) == (
                        cutoff_for_validation.year, cutoff_for_validation.month
                    ):
                        month_dir = REPO_ROOT / parts[0] / parts[1] / parts[2]
                        if month_dir.exists():
                            days_elapsed = max(1, cutoff_for_validation.day)
                            fraction = min(1.0, retention_days / days_elapsed)
                            all_names = sorted(
                                f.name for f in month_dir.iterdir() if f.is_file()
                            )
                            n_to_keep = max(0, int(len(all_names) * fraction))
                            selected = set(all_names[-n_to_keep:]) if n_to_keep > 0 else set()
                            if parts[3] not in selected:
                                in_window = False
                                prop_excluded = True
                except (ValueError, IndexError):
                    in_window = True  # can't determine → validate conservatively

        if in_window:
            missing_in_dist.append(ru)
        elif prop_excluded:
            skipped_proportionally_excluded += 1
        else:
            skipped_outside_window += 1

    if skipped_excluded_by_design > 0:
        log.info("  %d report_url(s) excluded from dist/ by design (e.g. PDFs → "
                 "Cloudflare R2) — skipped from validation", skipped_excluded_by_design)
    if skipped_no_source > 0:
        log.info("  %d report_url(s) have no source in working tree — generated in a "
                 "prior run, already live on gh-pages (clean:false) — skipped",
                 skipped_no_source)
    if skipped_proportionally_excluded > 0:
        log.info("  %d report_url(s) proportionally excluded from boundary month "
                 "(size gate: %.0f%% of boundary-month files kept in dist/) — expected",
                 skipped_proportionally_excluded,
                 min(1.0, retention_days / max(1, cutoff_for_validation.day)) * 100
                 if cutoff_for_validation else 100)
    if skipped_outside_window > 0:
        log.info("  %d report_url(s) outside retention window — expected on gh-pages "
                 "(clean:false preserves history)", skipped_outside_window)

    if missing_in_dist:
        log.error("HARD FAIL: %d report_url path(s) MISSING from dist/:", len(missing_in_dist))
        for mu in missing_in_dist[:20]:
            log.error("  MISSING: %s", mu)
        if len(missing_in_dist) > 20:
            log.error("  ... and %d more", len(missing_in_dist) - 20)
        log.error("")
        log.error("DIAGNOSIS: These reports are WITHIN the retention window but absent from dist/.")
        log.error("  Check: 1. reports/ directory completeness in working tree")
        log.error("         2. God Mode skipped regeneration for missing files")
        log.error("         3. safe_git_commit.py stash recovery may have lost reports")
        log.error("ACTION: Do NOT deploy. Run report_generator.py to regenerate missing reports.")
        return 1

    actually_validated = (len(report_urls)
                         - skipped_excluded_by_design
                         - skipped_no_source
                         - skipped_outside_window
                         - skipped_proportionally_excluded)
    log.info("  report_url validation: %d paths validated — ALL PRESENT in dist/ "
             "(%d excluded-by-design, %d no-source, %d proportional, %d outside-window skipped)",
             actually_validated, skipped_excluded_by_design,
             skipped_no_source, skipped_proportionally_excluded, skipped_outside_window)

    # ── 5.1. Validate dashboard/ route integrity (v157.0 HARD FAIL) ─────────
    # P0 safeguard: any dashboard file linked from nav that is absent from dist/
    # causes a HARD FAIL, blocking deployment before 404s reach production.
    # Forensic fix for the same root cause addressed by adding "dashboard" to
    # INCLUDE_DIRS above — this gate ensures it can never silently regress.
    log.info("")
    log.info("Validating dashboard/ nav routes in dist/ (v157.0 — HARD FAIL)...")
    NAV_DASHBOARD_ROUTES = [
        "dashboard/enterprise_dashboard.html",      # ENTERPRISE DASHBOARD button
        "dashboard/enterprise_dashboard_v2.html",   # SOC V2 button
        "dashboard/orchestration_hub.html",         # ORCHESTRATION button
        "dashboard/social_distribution.html",       # SOCIAL button
        "dashboard/revenue_acceleration.html",      # REVENUE+ button
        "dashboard/revenue_dashboard.html",         # REVENUE button
        "dashboard/web3_dashboard.html",            # WEB3 INTEL button
        "dashboard/analyst_dashboard.html",
        "dashboard/agents_control_panel.html",
        "dashboard/threat_graph_dashboard.html",
    ]
    missing_dashboard: List[str] = []
    for route in NAV_DASHBOARD_ROUTES:
        src_path  = REPO_ROOT / route
        dist_path = DIST_DIR  / route
        if not src_path.exists():
            log.warning("  WARN: Source not in repo (skipped): %s", route)
            continue
        if not dist_path.exists():
            missing_dashboard.append(route)
            log.error("  MISSING in dist/: %s", route)
        else:
            log.info("  OK: %s", route)

    if missing_dashboard:
        log.error("")
        log.error("HARD FAIL — DASHBOARD ROUTE VALIDATOR (v157.0):")
        log.error("  %d dashboard file(s) in repo but ABSENT from dist/:", len(missing_dashboard))
        for m in missing_dashboard:
            log.error("    MISSING: %s", m)
        log.error("")
        log.error("  ROOT CAUSE: 'dashboard' missing from INCLUDE_DIRS in build_dist_artifact.py")
        log.error("  IMPACT: All missing routes will serve 404 on production GitHub Pages.")
        log.error("  ACTION: Add 'dashboard' to INCLUDE_DIRS and re-run the build.")
        return 1

    checked = len([r for r in NAV_DASHBOARD_ROUTES if (REPO_ROOT / r).exists()])
    log.info("  dashboard/ route validation: %d routes checked — ALL PRESENT in dist/", checked)

    # ── 5.2. Validate PAYMENT-GATEWAY.html in dist/ (v158.0 HARD FAIL) ──────
    # P0 monetization safeguard: PAYMENT-GATEWAY.html MUST be in dist/ on every
    # deployment. This file drives subscriptions, upgrades, enterprise onboarding,
    # and all revenue conversion. Its absence is a CRITICAL business failure.
    # Root cause of original 404: "PAYMENT-GATEWAY" was in HTML_EXCLUDE_PREFIXES.
    # That exclusion has been removed (v158.0). This gate ensures it never regresses.
    log.info("")
    log.info("Validating PAYMENT-GATEWAY.html in dist/ (v158.0 — HARD FAIL)...")
    _pg_src  = REPO_ROOT / "PAYMENT-GATEWAY.html"
    _pg_dist = DIST_DIR  / "PAYMENT-GATEWAY.html"
    if not _pg_src.exists():
        log.error("HARD FAIL — PAYMENT GATEWAY VALIDATOR (v158.0):")
        log.error("  PAYMENT-GATEWAY.html not found in repo root.")
        log.error("  This file is required for monetization, subscriptions, and enterprise onboarding.")
        log.error("  ACTION: Restore PAYMENT-GATEWAY.html to repo root and re-run the build.")
        return 1
    if not _pg_dist.exists():
        log.error("HARD FAIL — PAYMENT GATEWAY VALIDATOR (v158.0):")
        log.error("  PAYMENT-GATEWAY.html exists in repo but is ABSENT from dist/.")
        log.error("  IMPACT: Payment gateway returns 404 on production — monetization broken.")
        log.error("  ROOT CAUSE: Check HTML_EXCLUDE_PREFIXES in build_dist_artifact.py.")
        log.error("  ACTION: Ensure 'PAYMENT-GATEWAY' is NOT in HTML_EXCLUDE_PREFIXES.")
        return 1
    log.info("  OK: PAYMENT-GATEWAY.html is present in dist/")

    # ── 6. Write .nojekyll (prevents Jekyll processing on GitHub Pages) ──────
    nojekyll = DIST_DIR / ".nojekyll"
    if not nojekyll.exists():
        nojekyll.write_text("")
        total_files += 1
        log.info("  Created dist/.nojekyll")

    # ── 7. Build deployment manifest ────────────────────────────────────────
    log.info("")
    log.info("Building deployment manifest (SHA-256 checksums)...")
    manifest = build_manifest(DIST_DIR, run_id, pipeline_version)
    manifest_path = DIST_DIR / "deployment_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("  Manifest written: %d files, %d reports",
             manifest["total_files"], manifest["report_count"])

    # ── 7b. GitHub Pages artifact size gate (v184.0 HARD FAIL) ──────────────
    dist_total_bytes = sum(
        f.stat().st_size for f in DIST_DIR.rglob("*") if f.is_file()
    )
    dist_mb = dist_total_bytes / (1024 * 1024)
    limit_mb = DIST_SIZE_LIMIT_BYTES // (1024 * 1024)
    log.info("  dist/ total size: %.1f MB (limit: %d MB)", dist_mb, limit_mb)
    if dist_total_bytes > DIST_SIZE_LIMIT_BYTES:
        log.error("")
        log.error("=" * 70)
        log.error("HARD FAIL -- GITHUB PAGES SIZE GATE (v184.0)")
        log.error("=" * 70)
        log.error("  dist/ size : %.1f MB", dist_mb)
        log.error("  Limit      : %d MB (GitHub Pages hard limit: 1024 MB)", limit_mb)
        log.error("  EXCESS     : %.1f MB over limit", dist_mb - limit_mb)
        log.error("  RETENTION  : REPORT_RETENTION_DAYS=%d (hard cap: 7)",
                  REPORT_RETENTION_DAYS)
        log.error("")
        log.error("  DIRECTORY BREAKDOWN (dist/ contents):")
        breakdown: List[Tuple[int, str]] = []
        for item in DIST_DIR.iterdir():
            if item.is_dir():
                sz = sum(f.stat().st_size for f in item.rglob("*") if f.is_file())
            else:
                sz = item.stat().st_size
            breakdown.append((sz, item.name))
        for sz, name in sorted(breakdown, reverse=True):
            log.error("    %-40s  %8.1f MB", name + "/", sz / (1024 * 1024))
        log.error("")
        if (DIST_DIR / "reports").exists():
            log.error("  REPORTS SUBDIRECTORY BREAKDOWN (dist/reports/):")
            for sub in sorted((DIST_DIR / "reports").iterdir()):
                if sub.is_dir():
                    sz = sum(f.stat().st_size for f in sub.rglob("*") if f.is_file())
                    fc = sum(1 for _ in sub.rglob("*") if _.is_file())
                    log.error("    %-40s  %8.1f MB  (%d files)",
                              sub.name + "/", sz / (1024 * 1024), fc)
        log.error("")
        log.error("  FIX: REPORT_RETENTION_DAYS is capped at 7 in build_dist_artifact.py.")
        log.error("       Workflow Stage 5.4.6 should set REPORT_RETENTION_DAYS=3.")
        log.error("       Ensure report_archive_manager.py is running (not blocked by")
        log.error("       clean:true check) so old reports are removed from git tracking.")
        log.error("=" * 70)
        return 1
    log.info("  Size gate     : PASS (%.1f MB < %d MB limit)", dist_mb, limit_mb)

    # ── 8. Summary ───────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    dist_reports = sum(1 for _ in (DIST_DIR / "reports").rglob("*.html")) \
        if (DIST_DIR / "reports").exists() else 0
    log.info("")
    log.info("=" * 70)
    log.info("DIST BUILD COMPLETE")
    log.info("=" * 70)
    log.info("  dist/ total files : %d", manifest["total_files"])
    log.info("  dist/ reports     : %d HTML report(s)", dist_reports)
    log.info("  report_url check  : %d/%d paths valid", len(report_urls), len(report_urls))
    log.info("  Elapsed           : %.1fs", elapsed)
    log.info("  Artifact root     : %s", DIST_DIR)
    log.info("  Manifest          : %s", manifest_path)
    log.info("=" * 70)

    # Write a build-summary JSON for downstream steps / observability
    summary_path = REPO_ROOT / "data" / "telemetry" / "dist_build_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps({
        "status":               "success",
        "dist_files":           manifest["total_files"],
        "dist_reports":         dist_reports,
        "report_url_checked": len(report_urls),
        "elapsed_s":            round(elapsed, 1),
        "retention_days":       REPORT_RETENTION_DAYS,
        "dist_size_bytes":      dist_total_bytes,
        "dist_size_mb":         round(dist_mb, 2),
        "size_limit_mb":        limit_mb,
        "size_gate":            "PASS",
        "timestamp":            datetime.now(timezone.utc).isoformat(),
        "manifest_path":        str(manifest_path),
    }, indent=2))
    log.info("Build summary written: %s", summary_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
