#!/usr/bin/env python3
"""
scripts/build_dist_artifact.py
CYBERDUDEBIVASH(R) SENTINEL APEX v155.0 -- Deterministic Dist Artifact Builder
================================================================================
Builds a clean, validated dist/ deployment artifact from the working tree.

PURPOSE:
  Converts the runtime workspace (70k+ files) into a deterministic, minimal,
  checksum-validated deployment artifact suitable for GitHub Pages.

ARCHITECTURE:
  Working Tree (messy, runtime-polluted)
       ↓  [include list filter]
  dist/ (clean, deterministic, governed)
       ↓  [artifact verifier gate]
  GitHub Pages gh-pages branch (customer-facing)

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
from pathlib import Path
from typing import Dict, List, Set

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
}
EXCLUDE_PATTERNS = {
    "__pycache__", ".git", ".env", "*.log", "dist",
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
    "ENTERPRISE-CUSTOMER", "GODMODE", "PAYMENT-GATEWAY",
    "SENTINEL-APEX-SOVEREIGN", "SENTINEL_APEX_ENTERPRISE",
    "SENTINEL_APEX_P0", "dashboard-api-sync", "gh_pages_",
    "intel_card_enhanced", "index.html.bak", "index.html.pre",
}


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
    log.info("SENTINEL APEX -- Deterministic Dist Artifact Builder v155.0")
    log.info("=" * 70)
    log.info("Repo root : %s", REPO_ROOT)
    log.info("Dist dir  : %s", DIST_DIR)

    pipeline_version = os.environ.get("PIPELINE_VERSION", "155.0.0")
    run_id           = os.environ.get("GITHUB_RUN_ID", "local")

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
        if src.exists():
            n = copy_item(src, dst)
            total_files += n
            log.info("  Copied %s/ → dist/%s/  (%d files)", dirname, dirname, n)
        else:
            log.warning("  SKIP: %s/ not found in repo root", dirname)

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
    include_singles = [
        "feed.json", "feed_manifest.json", "latest.json", "manifest.json",
        "_headers", ".nojekyll", "CNAME", "robots.txt",
        "sitemap.xml", "favicon.ico", "favicon.png",
    ]
    for fname in include_singles:
        src = REPO_ROOT / fname
        if src.exists():
            shutil.copy2(src, DIST_DIR / fname)
            total_files += 1
            log.info("  Copied root file: %s", fname)
        # Not a hard error if optional files don't exist

    # ── 5. Validate report_url paths exist in dist/ ──────────────────────────
    log.info("")
    log.info("Validating report_url paths in dist/...")
    report_urls = load_report_urls_from_feeds()
    missing_in_dist: List[str] = []
    for ru in report_urls:
        dist_path = DIST_DIR / ru.lstrip("/")
        if not dist_path.exists():
            missing_in_dist.append(ru)

    if missing_in_dist:
        log.error("HARD FAIL: %d report_url path(s) MISSING from dist/:", len(missing_in_dist))
        for mu in missing_in_dist[:20]:
            log.error("  MISSING: %s", mu)
        if len(missing_in_dist) > 20:
            log.error("  ... and %d more", len(missing_in_dist) - 20)
        log.error("")
        log.error("DIAGNOSIS: These reports exist in manifests but were not copied to dist/.")
        log.error("  Check: 1. reports/ directory completeness in working tree")
        log.error("         2. God Mode skipped regeneration for missing files")
        log.error("         3. safe_git_commit.py stash recovery may have lost reports")
        log.error("ACTION: Do NOT deploy. Run report_generator.py to regenerate missing reports.")
        return 1

    log.info("  report_url validation: %d paths checked — ALL PRESENT in dist/", len(report_urls))

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

    # Write a summary env var for downstream steps
    summary_path = REPO_ROOT / "data" / "telemetry" / "dist_build_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps({
        "status": "success",
        "dist_files": manifest["total_files"],
        "dist_reports": dist_reports,
        "report_url_checked": len(report_urls),
        "report_url_missing": 0,
        "generated_at": manifest["generated_at"],
        "run_id": run_id,
    }, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
