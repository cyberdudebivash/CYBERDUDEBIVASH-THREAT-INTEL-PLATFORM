#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v146.0.0
REPOSITORY SCALE GOVERNANCE
===============================================================================
PURPOSE:
  Monitors repository growth, artifact lifecycle, and clone performance to
  prevent the repository from becoming unmaintainable at scale. Enforces
  artifact retention policies, detects binary blobs, and tracks the ratio
  of tracked data vs code to guide sparse-checkout recommendations.

CHECKS:
  1. Repo size estimate    — warn if tracked files > 500MB aggregate
  2. Binary blob detection — flag non-text files in /api/, /data/ > 5MB
  3. Artifact lifecycle    — flag data/governance/*.json > 180 days old
  4. Cold archive audit    — confirm cold archive path exists and is not empty
  5. Sparse checkout hints — produce .sparse-checkout manifest for heavy paths
  6. Workflow count        — warn if > 50 .github/workflows/*.yml files
  7. Script count          — warn if > 100 scripts/*.py files

OUTPUTS:
  data/governance/repo_scale_governance.json — governance report
  .github/sparse-checkout-hints.txt          — sparse checkout recommendations

EXIT CODES:
  0 — PASS (all scale metrics within bounds)
  3 — WARN (approaching limits — review recommended)
  0 — always (repo scale is non-blocking to production)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [repo_scale] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-REPO-SCALE")

REPO_ROOT    = pathlib.Path(__file__).resolve().parent.parent
GOV_DIR      = REPO_ROOT / "data" / "governance"
REPORT_PATH  = GOV_DIR / "repo_scale_governance.json"
SPARSE_HINTS = REPO_ROOT / ".github" / "sparse-checkout-hints.txt"

VERSION = "146.0.0"

# Thresholds
MAX_TRACKED_MB        = 500
MAX_BLOB_MB           = 5
MAX_ARTIFACT_AGE_DAYS = 180
MAX_WORKFLOWS         = 50
MAX_SCRIPTS           = 100
COLD_ARCHIVE_DIR      = REPO_ROOT / "data" / "archive"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: pathlib.Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".rsg_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def get_dir_size_mb(path: pathlib.Path) -> float:
    """Recursively sum file sizes in MB."""
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    except (PermissionError, OSError):
        pass
    return total / (1024 * 1024)


def check_repo_size() -> Tuple[str, str, Dict[str, float]]:
    """Check aggregate size of key tracked directories."""
    dirs_to_check = {
        "api"       : REPO_ROOT / "api",
        "data"      : REPO_ROOT / "data",
        "scripts"   : REPO_ROOT / "scripts",
        "agent"     : REPO_ROOT / "agent",
        "workers"   : REPO_ROOT / "workers",
    }
    sizes: Dict[str, float] = {}
    total_mb = 0.0

    for label, d in dirs_to_check.items():
        if d.exists():
            mb = get_dir_size_mb(d)
            sizes[label] = round(mb, 2)
            total_mb += mb

    sizes["total"] = round(total_mb, 2)

    if total_mb > MAX_TRACKED_MB:
        return "WARN", (
            f"Tracked data total {total_mb:.1f}MB exceeds {MAX_TRACKED_MB}MB threshold. "
            "Consider sparse checkout or cold archive for historical data."
        ), sizes
    return "PASS", f"Total tracked data: {total_mb:.1f}MB (within {MAX_TRACKED_MB}MB limit)", sizes


def check_binary_blobs() -> Tuple[str, str, List[Dict]]:
    """Detect large non-text files in api/ and data/."""
    large_blobs: List[Dict] = []
    threshold = MAX_BLOB_MB * 1024 * 1024

    for search_dir in [REPO_ROOT / "api", REPO_ROOT / "data"]:
        if not search_dir.exists():
            continue
        for p in search_dir.rglob("*"):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
                if size <= threshold:
                    continue
                # Heuristic: non-text if not .json/.csv/.txt/.md/.yml/.yaml
                text_exts = {".json", ".csv", ".txt", ".md", ".yml", ".yaml", ".html", ".js", ".py"}
                if p.suffix.lower() not in text_exts:
                    large_blobs.append({
                        "path": str(p.relative_to(REPO_ROOT)),
                        "size_mb": round(size / (1024 * 1024), 2),
                    })
            except OSError:
                pass

    if large_blobs:
        return "WARN", (
            f"{len(large_blobs)} large binary blob(s) detected in api/ or data/ "
            f"(>{MAX_BLOB_MB}MB). These inflate clone size for all clients."
        ), large_blobs
    return "PASS", f"No binary blobs >{MAX_BLOB_MB}MB detected in api/ or data/", large_blobs


def check_artifact_lifecycle() -> Tuple[str, str, List[str]]:
    """Flag governance artifacts older than retention policy."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_ARTIFACT_AGE_DAYS)
    stale: List[str] = []

    for gov_json in GOV_DIR.glob("*.json"):
        try:
            mtime = datetime.fromtimestamp(gov_json.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                age_days = (datetime.now(timezone.utc) - mtime).days
                stale.append(f"{gov_json.name} ({age_days}d old)")
        except OSError:
            pass

    if stale:
        return "WARN", (
            f"{len(stale)} governance artifact(s) exceed {MAX_ARTIFACT_AGE_DAYS}-day retention: "
            + ", ".join(stale[:5])
        ), stale
    return "PASS", f"All governance artifacts within {MAX_ARTIFACT_AGE_DAYS}-day retention policy", stale


def check_cold_archive() -> Tuple[str, str]:
    """Verify cold archive directory exists and is populated."""
    if not COLD_ARCHIVE_DIR.exists():
        return "INFO", f"Cold archive directory not present: {COLD_ARCHIVE_DIR.name} (create when needed)"

    archive_files = list(COLD_ARCHIVE_DIR.rglob("*.json"))
    if not archive_files:
        return "WARN", "Cold archive directory exists but contains no archived files"

    total_mb = sum(
        f.stat().st_size for f in archive_files if f.is_file()
    ) / (1024 * 1024)
    return "PASS", f"Cold archive active: {len(archive_files)} files, {total_mb:.1f}MB"


def check_workflow_count() -> Tuple[str, str, int]:
    """Warn if workflow file count exceeds manageable threshold."""
    workflows_dir = REPO_ROOT / ".github" / "workflows"
    count = len(list(workflows_dir.glob("*.yml"))) if workflows_dir.exists() else 0

    if count > MAX_WORKFLOWS:
        return "WARN", (
            f"{count} workflow files found (>{MAX_WORKFLOWS}). "
            "Consider consolidating low-frequency workflows."
        ), count
    return "PASS", f"Workflow count: {count} (within {MAX_WORKFLOWS} limit)", count


def check_script_count() -> Tuple[str, str, int]:
    """Warn if scripts directory is overcrowded."""
    scripts_dir = REPO_ROOT / "scripts"
    count = len(list(scripts_dir.glob("*.py"))) if scripts_dir.exists() else 0

    if count > MAX_SCRIPTS:
        return "WARN", (
            f"{count} Python scripts found (>{MAX_SCRIPTS}). "
            "Consider grouping into packages."
        ), count
    return "PASS", f"Script count: {count} (within {MAX_SCRIPTS} limit)", count


def write_sparse_hints(sizes: Dict[str, float], workflow_count: int) -> None:
    """Write sparse-checkout hints for heavy-data consumers."""
    lines = [
        "# SENTINEL APEX — Sparse Checkout Hints",
        "# Generated by repo_scale_governance.py",
        "# Use: git sparse-checkout set <paths>",
        "#",
        "# Minimal (code only — no data):",
        "  scripts/",
        "  agent/",
        "  workers/",
        "  .github/workflows/",
        "#",
        "# + API feed (lightweight consumers):",
        "  api/v1/intel/manifest.json",
        "  api/v1/intel/top10.json",
        "#",
        "# Full data (governance/SRE use only):",
        "  api/",
        "  data/governance/",
        "  data/health/",
        "#",
        f"# Note: data/ is {sizes.get('data', 0):.1f}MB — exclude for read-only API consumers",
        f"# Note: {workflow_count} active workflows",
    ]
    try:
        SPARSE_HINTS.parent.mkdir(parents=True, exist_ok=True)
        SPARSE_HINTS.write_text("\n".join(lines) + "\n", encoding="utf-8")
        log.info("[WRITE] Sparse checkout hints: %s", SPARSE_HINTS)
    except OSError as e:
        log.warning("Could not write sparse hints: %s", e)


def main() -> int:
    t0 = time.monotonic()
    log.info("=" * 66)
    log.info("SENTINEL APEX %s — Repository Scale Governance", VERSION)
    log.info("Repo: %s", REPO_ROOT)
    log.info("=" * 66)

    checks: List[Dict[str, Any]] = []
    soft_warn = False

    def record(name: str, status: str, detail: str, **extra: Any) -> None:
        nonlocal soft_warn
        icon = {"PASS": "[PASS]", "WARN": "[WARN]", "INFO": "[INFO]"}.get(status, "[????]")
        log.info("%s %s: %s", icon, name, detail[:120])
        entry: Dict[str, Any] = {"check": name, "status": status, "detail": detail}
        entry.update(extra)
        checks.append(entry)
        if status == "WARN":
            soft_warn = True

    # Run checks
    status, detail, sizes = check_repo_size()
    record("repo_size", status, detail, sizes_mb=sizes)

    status, detail, blobs = check_binary_blobs()
    record("binary_blobs", status, detail, blobs=blobs)

    status, detail, stale = check_artifact_lifecycle()
    record("artifact_lifecycle", status, detail, stale_files=stale)

    status, detail = check_cold_archive()
    record("cold_archive", status, detail)

    status, detail, wf_count = check_workflow_count()
    record("workflow_count", status, detail, count=wf_count)

    status, detail, sc_count = check_script_count()
    record("script_count", status, detail, count=sc_count)

    # Write sparse hints
    write_sparse_hints(sizes, wf_count)

    verdict = "WARN" if soft_warn else "PASS"
    runtime = round(time.monotonic() - t0, 3)
    pass_count = sum(1 for c in checks if c["status"] in ("PASS", "INFO"))
    warn_count = sum(1 for c in checks if c["status"] == "WARN")

    report = {
        "schema_version"  : "1.0",
        "generated_at"    : now_iso(),
        "generator"       : "repo_scale_governance.py",
        "version"         : VERSION,
        "overall_verdict" : verdict,
        "pass_count"      : pass_count,
        "warn_count"      : warn_count,
        "checks"          : checks,
        "thresholds"      : {
            "max_tracked_mb"       : MAX_TRACKED_MB,
            "max_blob_mb"          : MAX_BLOB_MB,
            "max_artifact_age_days": MAX_ARTIFACT_AGE_DAYS,
            "max_workflows"        : MAX_WORKFLOWS,
            "max_scripts"          : MAX_SCRIPTS,
        },
        "runtime_seconds" : runtime,
    }

    GOV_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(REPORT_PATH, json.dumps(report, ensure_ascii=False, indent=2))

    log.info("=" * 66)
    log.info("REPO SCALE: %s | pass=%d warn=%d", verdict, pass_count, warn_count)
    log.info("[WRITE] %s", REPORT_PATH)
    log.info("=" * 66)

    return 3 if soft_warn else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log.error("[FATAL] Unexpected error: %s", e)
        sys.exit(0)
