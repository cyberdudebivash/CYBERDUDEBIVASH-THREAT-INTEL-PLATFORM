#!/usr/bin/env python3
"""
scripts/run_pipeline.py
CYBERDUDEBIVASH(R) SENTINEL APEX v131.2.0 -- Master Pipeline Orchestrator
==========================================================================
P0 ARCHITECTURAL FIX: Replaces ALL inline PYEOF/PYEOF heredoc blocks from
sentinel-blogger.yml.  The YAML now calls ONLY this script (plus dedicated
utility scripts).  Zero inline Python in YAML ever again.

Stages orchestrated by this script:
  Stage 0.5  -- Purge Blogger publish queue (queue-bomb neutraliser)
  Stage 1    -- Bootstrap: ensure critical files exist
  Stage 1.1  -- Validate bootstrap output
  Stage 1.2  -- Inject sovereign key if available
  Stage 1.3  -- Validate JWT secret (HARD FAIL if absent)
  Stage 2    -- Run Sentinel Intelligence Engine
  Stage 1.5  -- Pre-v70 Manifest Sync (feed fresh data to v70)
  Stage 2.1  -- v70 Apex Intelligence Orchestrator (enrichment)
  Stage 2.2  -- Manifest Stabilisation (preserve/normalise engine output)
  Stage 2.5  -- Intel Freshness Gate (hard fail if < MIN entries)
  Stage 3    -- Schema Validation
  Stage 3.1  -- Manifest Cleanup (dedup, brand strip)
  Stage 3.6  -- HTML Report Generation
  Stage 3.6a -- Manifest Integrity Check (report_url + validation_status)
  Stage 3.6b -- Refresh EMBEDDED_INTEL + version sync in dashboard
  Stage 3.6c -- Prune STIX bundles (cap at 500 newest)

Rules enforced:
  - Every stage wrapped in try/except -- pipeline NEVER crashes
  - Hard fails (JWT, Freshness Gate, Integrity Check) call sys.exit(1)
  - All other failures are logged and pipeline continues
  - Zero inline heredocs, zero echo with quotes, zero PYEOF

Environment variables consumed (set at job level in workflow):
  CDB_JWT_SECRET     -- REQUIRED: JWT auth secret for engine
  CDB_SOVEREIGN_KEY  -- optional: PEM key content
  NVD_API_KEY        -- optional: NVD intel source
  GUMROAD_ACCESS_TOKEN -- optional: revenue data
  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID -- optional: alerts
  SKIP_AI            -- "true" to skip AI enrichment
  FORCE_FULL_SYNC    -- "true" to force full sync
  PIPELINE_VERSION   -- version string (default: 131.2.0)
  PYTHONPATH         -- set to github.workspace by workflow

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [pipeline] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.pipeline")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "131.2.0")
MIN_FRESHNESS_ENTRIES = 10   # absolute hard-fail threshold
MIN_ENGINE_ENTRIES = 50      # engine manifest minimum before --force-rebuild
MAX_STIX_BUNDLES = 500       # cap on persisted STIX bundle files

GITHUB_ENV = os.environ.get("GITHUB_ENV", "/dev/null")

VALID_THREAT_TYPES = {
    "vulnerability", "malware", "campaign", "intrusion-set",
    "tool", "attack-pattern", "indicator", "threat-report",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_github_env(key: str, value: str) -> None:
    """Append KEY=VALUE to GITHUB_ENV file so downstream steps can read it."""
    try:
        with open(GITHUB_ENV, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")
    except Exception as e:
        log.warning("GITHUB_ENV write failed (%s): %s", key, e)


def run_script(
    args: list[str],
    *,
    stage: str,
    capture: bool = False,
    timeout: int = 300,
    allow_fail: bool = True,
) -> subprocess.CompletedProcess:
    """Run a subprocess, log outcome, return CompletedProcess."""
    log.info("[%s] Running: %s", stage, " ".join(str(a) for a in args))
    try:
        result = subprocess.run(
            args,
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            log.info("[%s] OK (exit 0)", stage)
        else:
            msg = f"[{stage}] Exited {result.returncode}"
            if allow_fail:
                log.warning("%s (non-fatal, pipeline continues)", msg)
            else:
                log.error("%s (HARD FAIL)", msg)
        return result
    except subprocess.TimeoutExpired:
        log.warning("[%s] Timeout after %ds (non-fatal)", stage, timeout)
        return subprocess.CompletedProcess(args, returncode=-1, stdout="", stderr="timeout")
    except Exception as e:
        if allow_fail:
            log.warning("[%s] Failed to run: %s (non-fatal)", stage, e)
        else:
            log.error("[%s] Failed to run: %s (HARD FAIL)", stage, e)
        return subprocess.CompletedProcess(args, returncode=-1, stdout="", stderr=str(e))


def load_manifest(path: str) -> tuple[list, str]:
    """
    Load feed manifest, handle both LIST and DICT formats.
    Returns (items_list, format_string).
    """
    p = Path(path)
    if not p.exists():
        return [], "absent"
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return raw, "list"
        if isinstance(raw, dict):
            for key in ("advisories", "reports", "items"):
                if key in raw and isinstance(raw[key], list):
                    return raw[key], "dict"
            return [], "dict-empty"
    except Exception as e:
        log.warning("Cannot parse %s: %s", path, e)
    return [], "error"


def count_manifest(path: str) -> int:
    items, _ = load_manifest(path)
    return len(items)


# ---------------------------------------------------------------------------
# Stage 0.0 -- Python Syntax Guard (runs FIRST, before anything else)
# ---------------------------------------------------------------------------

def stage_syntax_guard() -> None:
    """
    Run python_syntax_guard.py to catch SyntaxErrors in any .py file
    BEFORE the pipeline executes.  On failure: log the error and skip
    the faulty module — do NOT crash the entire pipeline.
    """
    log.info("=" * 60)
    log.info("STAGE 0.0 -- Python Syntax Guard pre-flight check")
    log.info("=" * 60)
    guard_script = REPO_ROOT / "scripts" / "python_syntax_guard.py"
    if not guard_script.exists():
        log.warning("[0.0] python_syntax_guard.py not found — skipping pre-flight.")
        return
    try:
        result = subprocess.run(
            [sys.executable, str(guard_script)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        for line in result.stdout.splitlines():
            log.info("[0.0] %s", line)
        for line in result.stderr.splitlines():
            log.warning("[0.0] %s", line)
        if result.returncode == 0:
            log.info("[0.0] Syntax Guard PASSED — all Python files are syntax-clean.")
        else:
            log.error(
                "[0.0] Syntax Guard reported errors (see above). "
                "Faulty modules will be skipped. Pipeline continues."
            )
    except subprocess.TimeoutExpired:
        log.warning("[0.0] Syntax Guard timed out (non-fatal, pipeline continues).")
    except Exception as e:
        log.warning("[0.0] Syntax Guard could not run: %s (non-fatal)", e)


# ---------------------------------------------------------------------------
# Stage 0.5 -- Purge Blogger Publish Queue
# ---------------------------------------------------------------------------

def stage_purge_publish_queue() -> None:
    log.info("=" * 60)
    log.info("STAGE 0.5 -- Purge Blogger publish queue")
    log.info("=" * 60)
    try:
        queue_path = REPO_ROOT / "data" / "publish_queue.json"
        count = 0
        if queue_path.exists():
            try:
                raw = json.loads(queue_path.read_text(encoding="utf-8"))
                queue = raw.get("queue", raw) if isinstance(raw, dict) else raw
                count = len(queue) if isinstance(queue, list) else 0
                if count > 0:
                    log.info("[0.5] Clearing %d stale Blogger queue entries (queue bomb neutralised)", count)
            except Exception as e:
                log.warning("[0.5] Could not read existing queue: %s", e)
        empty = {
            "queue": [],
            "version": "111.0",
            "cleared_at": utc_now(),
            "_cleared_by": "run_pipeline.py",
        }
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        queue_path.write_text(json.dumps(empty, indent=2), encoding="utf-8")
        log.info("[0.5] publish_queue.json cleared (was %d entries).", count)
    except Exception as e:
        log.warning("[0.5] Queue purge failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 1 -- Bootstrap
# ---------------------------------------------------------------------------

def stage_bootstrap() -> None:
    log.info("=" * 60)
    log.info("STAGE 1 -- Bootstrap critical files")
    log.info("=" * 60)
    run_script(
        [sys.executable, "scripts/bootstrap_critical_files.py"],
        stage="1.bootstrap",
        allow_fail=True,
        timeout=120,
    )


def stage_validate_bootstrap() -> None:
    log.info("STAGE 1.1 -- Validate bootstrap output")
    try:
        manifest = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
        if not manifest.exists():
            log.warning("[1.1] %s missing after bootstrap -- will be created by engine", manifest)
        else:
            items, fmt = load_manifest(str(manifest))
            log.info("[1.1] Bootstrap manifest: %d items (fmt=%s)", len(items), fmt)
        log.info("[1.1] Bootstrap validation COMPLETE")
    except Exception as e:
        log.warning("[1.1] Validation failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 1.2 -- Inject Sovereign Key
# ---------------------------------------------------------------------------

def stage_inject_sovereign_key() -> None:
    log.info("STAGE 1.2 -- Inject sovereign key (optional)")
    try:
        key_content = os.environ.get("CDB_SOVEREIGN_KEY", "").strip()
        if not key_content:
            log.info("[1.2] CDB_SOVEREIGN_KEY not set -- skipping.")
            return
        secrets_dir = REPO_ROOT / "secrets"
        secrets_dir.mkdir(parents=True, exist_ok=True)
        key_path = secrets_dir / "cdb_sovereign.pem"
        key_path.write_text(key_content + "\n", encoding="utf-8")
        key_path.chmod(0o600)
        log.info("[1.2] Sovereign key written to secrets/cdb_sovereign.pem")
    except Exception as e:
        log.warning("[1.2] Sovereign key inject failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 1.3 -- Validate JWT Secret (HARD FAIL)
# ---------------------------------------------------------------------------

def stage_validate_jwt_secret() -> None:
    log.info("STAGE 1.3 -- Validate JWT secret (hard fail if absent)")
    jwt_secret = os.environ.get("CDB_JWT_SECRET", "").strip()
    if not jwt_secret:
        log.error("[1.3] FATAL: CDB_JWT_SECRET is not set.")
        log.error("[1.3] Fix: Repository Settings -> Secrets -> Actions -> New secret")
        log.error("[1.3] Name: CDB_JWT_SECRET")
        log.error("[1.3] Value: generate with: openssl rand -hex 32")
        sys.exit(1)
    log.info("[1.3] CDB_JWT_SECRET is configured. [OK]")


# ---------------------------------------------------------------------------
# Stage 2 -- Run Sentinel Intelligence Engine
# ---------------------------------------------------------------------------

def stage_run_intel_engine() -> None:
    log.info("=" * 60)
    log.info("STAGE 2 -- Sentinel Intelligence Engine v111.0 (R2-only)")
    log.info("=" * 60)

    stix_dir = REPO_ROOT / "data" / "stix"
    stix_before = len(list(stix_dir.glob("CDB-APEX-*.json"))) if stix_dir.exists() else 0
    log.info("[2] STIX bundles before run: %d", stix_before)

    result = run_script(
        [sys.executable, "-m", "agent.sentinel_blogger"],
        stage="2.intel_engine",
        allow_fail=True,
        timeout=1200,
    )
    log.info("[2] Engine exited: %d", result.returncode)

    stix_after = len(list(stix_dir.glob("CDB-APEX-*.json"))) if stix_dir.exists() else 0
    new_bundles = stix_after - stix_before
    log.info("[2] STIX bundles after run: %d (NEW: %d)", stix_after, new_bundles)
    write_github_env("STIX_NEW_BUNDLES", str(new_bundles))


# ---------------------------------------------------------------------------
# Stage 1.5 -- Pre-v70 Manifest Sync
# ---------------------------------------------------------------------------

def stage_pre_v70_manifest_sync() -> None:
    log.info("=" * 60)
    log.info("STAGE 1.5 -- Pre-v70 Manifest Sync")
    log.info("=" * 60)
    try:
        src = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
        dst = REPO_ROOT / "data" / "feed_manifest.json"
        bkup = REPO_ROOT / "data" / ".manifest_backups"

        if not src.exists():
            log.warning("[1.5] %s does not exist -- skipping sync.", src)
            return

        try:
            raw = json.loads(src.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning("[1.5] Cannot read %s: %s -- skipping.", src, e)
            return

        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get("advisories", raw.get("reports", raw.get("items", [])))
        else:
            items = []

        if len(items) < 10:
            log.warning("[1.5] Only %d items in %s -- skipping (too small).", len(items), src)
            return

        # Sanitise invalid threat_type values for v70 schema compliance
        sanitised = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            tt = item.get("threat_type", "")
            if tt and isinstance(tt, str) and tt.lower() not in VALID_THREAT_TYPES:
                item["threat_type"] = ""
                sanitised += 1
        if sanitised:
            log.info("[1.5] Sanitised %d invalid threat_type values -> '' (v70 will reclassify)", sanitised)

        # Write v70-schema-compliant manifest
        gen_at = raw.get("generated_at", utc_now()) if isinstance(raw, dict) else utc_now()
        payload = {
            "version":        raw.get("version", "v114.0") if isinstance(raw, dict) else "v114.0",
            "schema_version": "v70.0",
            "platform":       "SENTINEL-APEX",
            "generated_at":   gen_at,
            "synced_at":      utc_now(),
            "total_reports":  len(items),
            "entry_count":    len(items),
            "sort_order":     "timestamp DESC, risk_score DESC",
            "source":         "pre_v70_sync_from_stix_manifest",
            "advisories":     items,
        }
        tmp = dst.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
        os.replace(tmp, dst)
        log.info("[1.5] Synced %d items from stix/feed_manifest.json -> feed_manifest.json", len(items))

        # Prune stale backups older than 7 days
        if bkup.is_dir():
            cutoff = time.time() - 7 * 86400
            deleted = 0
            for f in bkup.iterdir():
                if f.suffix == ".json":
                    try:
                        if time.time() - f.stat().st_mtime > cutoff:
                            f.unlink()
                            deleted += 1
                    except Exception:
                        pass
            if deleted:
                log.info("[1.5] Deleted %d stale backup(s) older than 7 days.", deleted)

    except Exception as e:
        log.warning("[1.5] Pre-v70 manifest sync failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 2.1 -- v70 Apex Intelligence Orchestrator
# ---------------------------------------------------------------------------

def stage_v70_orchestrator() -> None:
    log.info("=" * 60)
    log.info("STAGE 2.1 -- v70 Apex Intelligence Orchestrator")
    log.info("=" * 60)

    v70_dir = REPO_ROOT / "agent" / "v70_apex_upgrade"
    if not v70_dir.is_dir():
        log.info("[2.1] agent/v70_apex_upgrade not found -- skipping.")
        return

    # Check freshness of candidate manifests (skip if all > 48h old)
    max_age_seconds = 48 * 3600
    now = time.time()
    candidates = [
        "data/stix/feed_manifest.json",
        "data/feed_manifest.json",
        "data/apex_enriched_manifest.json",
    ]
    newest_age: float | None = None
    for path in candidates:
        full = REPO_ROOT / path
        if full.exists():
            age = now - full.stat().st_mtime
            if newest_age is None or age < newest_age:
                newest_age = age

    if newest_age is None:
        log.warning("[2.1] No manifest files found -- skipping v70.")
        return

    if newest_age > max_age_seconds:
        log.warning("[2.1] Newest manifest is %.1fh old (stale). Skipping v70.", newest_age / 3600)
        log.warning("[2.1] v70 will run on the next successful intel engine run.")
        return

    log.info("[2.1] Input data is fresh (%.1fh old). Proceeding with v70 enrichment.", newest_age / 3600)

    skip_ai = os.environ.get("SKIP_AI", "false").lower() == "true"
    cmd = [sys.executable, "-m", "agent.v70_apex_upgrade.orchestrator",
           "--data-dir", "data", "--dashboard", "index.html", "--json"]
    if skip_ai:
        cmd.append("--no-ai")

    result = run_script(cmd, stage="2.1.v70", allow_fail=True, timeout=240)

    if result.returncode != 0:
        log.warning("[2.1] v70 exited %d -- writing fallback result.", result.returncode)
        fallback = {
            "success": False,
            "total_advisories": 0,
            "error": f"v70 non-zero exit {result.returncode} (guard fired)",
            "phases": [],
            "guard_fired": True,
        }
        try:
            Path("/tmp/v70_result.json").write_text(
                json.dumps(fallback, indent=2), encoding="utf-8"
            )
        except Exception as e:
            log.warning("[2.1] Could not write fallback v70 result: %s", e)
    else:
        log.info("[2.1] v70 enrichment complete.")


# ---------------------------------------------------------------------------
# Stage 2.2 -- Manifest Stabilisation
# ---------------------------------------------------------------------------

def stage_manifest_stabilisation() -> None:
    log.info("=" * 60)
    log.info("STAGE 2.2 -- Manifest Stabilisation")
    log.info("=" * 60)
    try:
        manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

        engine_count = 0
        engine_items: list = []
        manifest_fmt = "absent"

        if manifest_path.exists():
            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    engine_items = raw
                    engine_count = len(raw)
                    manifest_fmt = "list"
                    log.info("[2.2] Manifest is LIST format (%d items).", engine_count)
                elif isinstance(raw, dict):
                    for key in ("advisories", "reports", "items"):
                        if key in raw and isinstance(raw[key], list):
                            engine_items = raw[key]
                            break
                    engine_count = len(engine_items)
                    manifest_fmt = "dict"
                    log.info("[2.2] Manifest is DICT format (%d items).", engine_count)
            except Exception as e:
                log.warning("[2.2] Cannot parse manifest: %s", e)

        stix_dir = REPO_ROOT / "data" / "stix"
        stix_bundles = len(list(stix_dir.glob("CDB-APEX-*.json"))) if stix_dir.exists() else 0
        log.info("[2.2] Engine manifest: %d entries (fmt=%s) | STIX bundles: %d",
                 engine_count, manifest_fmt, stix_bundles)

        if engine_count >= MIN_ENGINE_ENTRIES:
            log.info("[2.2] Engine manifest valid (%d >= %d). --force-rebuild SKIPPED.",
                     engine_count, MIN_ENGINE_ENTRIES)

            # Normalise LIST -> DICT if needed
            if manifest_fmt == "list":
                log.info("[2.2] Normalising LIST -> DICT envelope (%d entries)...", engine_count)
                payload = {
                    "version":           "v114.0",
                    "platform":          "SENTINEL-APEX",
                    "generated_at":      utc_now(),
                    "normalised_at":     utc_now(),
                    "total_reports":     engine_count,
                    "entry_count":       engine_count,
                    "schema_version":    "v114.0",
                    "sort_order":        "timestamp DESC, risk_score DESC",
                    "source_of_truth":   "agent.sentinel_blogger (normalised by pipeline)",
                    "advisories":        engine_items,
                }
                tmp = str(manifest_path) + ".norm.tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
                os.replace(tmp, str(manifest_path))
                log.info("[2.2] Normalised: %d entries in DICT format written. [OK]", engine_count)

            # Run cleaner (non-blocking)
            r = run_script(
                [sys.executable, "scripts/clean_feed_manifest.py"],
                stage="2.2.cleaner",
                allow_fail=True,
                timeout=120,
            )
            if r.returncode != 0:
                log.warning("[2.2] clean_feed_manifest exited %d -- engine manifest retained.", r.returncode)
        else:
            log.warning("[2.2] Engine manifest too small (%d < %d). Running --force-rebuild.",
                        engine_count, MIN_ENGINE_ENTRIES)
            run_script(
                [sys.executable, "scripts/bootstrap_critical_files.py", "--force-rebuild"],
                stage="2.2.force_rebuild",
                allow_fail=True,
                timeout=300,
            )

        # Report final state
        final_count = 0
        for ppath in ("data/stix/feed_manifest.json", "data/feed_manifest.json"):
            full = REPO_ROOT / ppath
            if full.exists():
                try:
                    d = json.loads(full.read_text(encoding="utf-8"))
                    if isinstance(d, list):
                        cnt = len(d)
                        log.info("[2.2] %s: %d entries (LIST format)", ppath, cnt)
                    elif isinstance(d, dict):
                        items = d.get("advisories", d.get("reports", []))
                        cnt = len(items)
                        gen = d.get("generated_at", d.get("normalised_at", "?"))
                        log.info("[2.2] %s: %d entries  generated_at=%s", ppath, cnt, gen)
                    else:
                        cnt = 0
                    if ppath == "data/stix/feed_manifest.json":
                        final_count = cnt
                except Exception as e:
                    log.warning("[2.2] %s: ERROR reading -- %s", ppath, e)

        log.info("[2.2] MANIFEST_FINAL_COUNT=%d", final_count)
        write_github_env("MANIFEST_FINAL_COUNT", str(final_count))

    except Exception as e:
        log.warning("[2.2] Manifest stabilisation failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 2.5 -- Intel Freshness Gate (HARD FAIL)
# ---------------------------------------------------------------------------

def stage_freshness_gate() -> None:
    log.info("=" * 60)
    log.info("STAGE 2.5 -- Intel Freshness Gate")
    log.info("=" * 60)

    manifest = str(REPO_ROOT / "data" / "stix" / "feed_manifest.json")

    if not Path(manifest).exists():
        log.error("[2.5] FATAL: %s missing after stabilisation.", manifest)
        sys.exit(1)

    try:
        d = json.loads(Path(manifest).read_text(encoding="utf-8"))
        if isinstance(d, list):
            count = len(d)
            log.warning("[2.5] Manifest still in LIST format at gate (count=%d).", count)
        elif isinstance(d, dict):
            items = d.get("advisories", d.get("reports", d.get("items", [])))
            count = len(items) if isinstance(items, list) else 0
        else:
            log.error("[2.5] FATAL: Unexpected manifest root type: %s", type(d).__name__)
            sys.exit(1)
    except Exception as e:
        log.error("[2.5] FATAL: Cannot parse manifest: %s", e)
        sys.exit(1)

    if count < MIN_FRESHNESS_ENTRIES:
        log.error("[2.5] FATAL: Manifest has only %d entries (minimum: %d)", count, MIN_FRESHNESS_ENTRIES)
        log.error("[2.5] Root causes to check:")
        log.error("[2.5]   1. Engine manifest format (list vs dict)")
        log.error("[2.5]   2. Manifest Stabilisation normalisation output")
        log.error("[2.5]   3. clean_feed_manifest.py exit code")
        sys.exit(1)

    log.info("[2.5] FRESHNESS GATE PASSED: %d entries. [OK]", count)


# ---------------------------------------------------------------------------
# Stage 3 -- Schema Validation
# ---------------------------------------------------------------------------

def stage_schema_validation() -> None:
    log.info("=" * 60)
    log.info("STAGE 3 -- Schema Validation (hard gate)")
    log.info("=" * 60)
    result = run_script(
        [sys.executable, "scripts/validate_intel_schema.py"],
        stage="3.schema",
        allow_fail=False,
        timeout=120,
    )
    if result.returncode != 0:
        log.error("[3] Schema validation FAILED. Malformed data must not reach R2.")
        sys.exit(1)
    log.info("[3] SCHEMA VALIDATION PASSED. [OK]")


# ---------------------------------------------------------------------------
# Stage 3.1 -- Manifest Cleanup
# ---------------------------------------------------------------------------

def stage_manifest_cleanup() -> None:
    log.info("STAGE 3.1 -- Manifest Cleanup")
    run_script(
        [sys.executable, "scripts/clean_feed_manifest.py"],
        stage="3.1.cleanup",
        allow_fail=True,
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Stage 3.6 -- HTML Report Generation
# ---------------------------------------------------------------------------

def stage_html_reports() -> None:
    log.info("=" * 60)
    log.info("STAGE 3.6 -- HTML Report Generation")
    log.info("=" * 60)
    t_start = time.monotonic()

    # v117.0.0: Zero-skip policy -- every intel entry generates a 16-section report.
    r = run_script(
        [
            sys.executable, "scripts/generate_intel_reports.py",
            "--manifest", "data/stix/feed_manifest.json",
            "--public-prefix", "https://intel.cyberdudebivash.com",
            "--fail-on-zero",
            "--limit", "0",
        ],
        stage="3.6.reports",
        allow_fail=False,
        timeout=900,
    )
    if r.returncode != 0:
        log.error("[3.6] HTML report generation FAILED (exit %d).", r.returncode)
        sys.exit(1)

    # v131 upgrades: IOC enforcement, dedup, synthetic fallback, PDF, revenue
    run_script(
        [sys.executable, "scripts/apply_v131_upgrades.py"],
        stage="3.6.v131_upgrades",
        allow_fail=True,
        timeout=300,
    )

    report_count = 0
    try:
        reports_dir = REPO_ROOT / "reports"
        if reports_dir.is_dir():
            report_count = sum(
                1 for f in reports_dir.rglob("*.html")
                if f.name != "index.html"
            )
    except Exception:
        pass

    elapsed = time.monotonic() - t_start
    log.info("[3.6] Reports written: %d | Elapsed: %.1fs", report_count, elapsed)
    write_github_env("REPORT_COUNT", str(report_count))
    write_github_env("REPORT_ELAPSED", f"{elapsed:.0f}")


# ---------------------------------------------------------------------------
# Stage 3.6a -- Manifest Integrity Check (HARD FAIL on write_error/file_missing)
# ---------------------------------------------------------------------------

def stage_manifest_integrity_check() -> None:
    log.info("=" * 60)
    log.info("STAGE 3.6a -- Manifest Integrity Check")
    log.info("=" * 60)
    try:
        manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
        d = json.loads(manifest_path.read_text(encoding="utf-8"))
        items = d.get("advisories", d.get("reports", []))

        HARD_FAIL_STATUSES = {"write_error", "file_missing"}
        missing_url: list[str] = []
        hard_fail: list[str] = []
        stale_domain: list[str] = []

        for item in items:
            sid = item.get("id", "?")
            vs  = item.get("validation_status", "")
            ru  = item.get("report_url", "")
            if vs == "brand_skip":
                continue
            if vs in HARD_FAIL_STATUSES:
                hard_fail.append(f"  HARD_FAIL [{vs}] {sid}")
                continue
            if not ru:
                missing_url.append(f"  MISSING_URL {sid}")
                continue
            if "reports.cyberdudebivash.com" in ru:
                stale_domain.append(f"  STALE_DOMAIN {sid}")

        total = len(items)
        ok    = total - len(missing_url) - len(hard_fail) - len(stale_domain)
        log.info("[3.6a] Manifest entries : %d", total)
        log.info("[3.6a] report_url OK    : %d", ok)
        log.info("[3.6a] Missing URL      : %d", len(missing_url))
        log.info("[3.6a] Hard failures    : %d", len(hard_fail))
        log.info("[3.6a] Stale domain     : %d", len(stale_domain))

        if stale_domain:
            log.warning("[3.6a] Stale domains (will be rewritten by Worker at serve time):")
            for s in stale_domain[:10]:
                log.warning("[3.6a] %s", s)

        if hard_fail:
            log.error("[3.6a] MANIFEST INTEGRITY FAIL -- write_error/file_missing entries:")
            for h in hard_fail:
                log.error("[3.6a] %s", h)
            sys.exit(1)

        log.info("[3.6a] MANIFEST INTEGRITY CHECK PASSED. [OK]")

    except SystemExit:
        raise
    except Exception as e:
        log.warning("[3.6a] Integrity check failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 3.6b -- Refresh EMBEDDED_INTEL + Version Sync
# ---------------------------------------------------------------------------

def stage_refresh_embedded_intel() -> None:
    log.info("=" * 60)
    log.info("STAGE 3.6b -- Refresh EMBEDDED_INTEL + version sync")
    log.info("=" * 60)

    # Count items for informational logging
    item_count = count_manifest(str(REPO_ROOT / "data" / "stix" / "feed_manifest.json"))
    log.info("[3.6b] Manifest has %d items -- injecting into index.html...", item_count)

    run_script(
        [sys.executable, "scripts/update_embedded_intel.py"],
        stage="3.6b.embedded_intel",
        allow_fail=True,
        timeout=120,
    )

    # AI Brain panels + CDB_NEWS engine injection (idempotent)
    run_script(
        [sys.executable, "scripts/patch_ai_brain_news.py"],
        stage="3.6b.ai_brain_patch",
        allow_fail=True,
        timeout=60,
    )

    # Version sync: keep dashboard title aligned with pipeline version
    _version_sync()


def _version_sync() -> None:
    """Replace SENTINEL APEX vX.Y.Z in index.html with current PIPELINE_VERSION."""
    try:
        new_tag = f"SENTINEL APEX v{PIPELINE_VERSION}"
        html_path = REPO_ROOT / "index.html"
        if not html_path.exists():
            log.warning("[3.6b] index.html not found -- version sync skipped.")
            return
        content = html_path.read_text(encoding="utf-8", errors="replace")
        updated = re.sub(
            r"SENTINEL APEX [Vv]\d+\.\d+(?:\.\d+)?(?:\.\d+)?",
            new_tag,
            content,
        )
        if content != updated:
            html_path.write_text(updated, encoding="utf-8")
            count = updated.count(new_tag)
            log.info("[3.6b] Version-sync: dashboard updated to %s (%d occurrences)", new_tag, count)
        else:
            log.info("[3.6b] Version-sync: dashboard already at %s", new_tag)
    except Exception as e:
        log.warning("[3.6b] Version sync failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Stage 3.6c -- Prune STIX Bundles
# ---------------------------------------------------------------------------

def stage_prune_stix_bundles() -> None:
    log.info("STAGE 3.6c -- Prune STIX bundles (cap %d newest)", MAX_STIX_BUNDLES)
    try:
        stix_dir = REPO_ROOT / "data" / "stix"
        if not stix_dir.is_dir():
            log.info("[3.6c] data/stix not found -- nothing to prune.")
            return
        bundles = sorted(
            stix_dir.glob("CDB-APEX-*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if len(bundles) > MAX_STIX_BUNDLES:
            to_remove = bundles[MAX_STIX_BUNDLES:]
            for old in to_remove:
                try:
                    old.unlink()
                except Exception:
                    pass
            log.info("[3.6c] Pruned STIX bundles to %d newest (removed %d oldest).",
                     MAX_STIX_BUNDLES, len(to_remove))
        else:
            log.info("[3.6c] STIX bundle count: %d (under %d cap, no pruning).",
                     len(bundles), MAX_STIX_BUNDLES)
    except Exception as e:
        log.warning("[3.6c] STIX prune failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=" * 70)
    log.info("SENTINEL APEX v%s -- Master Pipeline Orchestrator", PIPELINE_VERSION)
    log.info("Run at: %s", utc_now())
    log.info("=" * 70)

    # Change to repo root so all relative paths work correctly
    os.chdir(REPO_ROOT)

    t_total = time.monotonic()

    # ---- Pre-flight -------------------------------------------------------
    stage_syntax_guard()                 # FIRST: catch SyntaxErrors before execution
    stage_purge_publish_queue()
    stage_bootstrap()
    stage_validate_bootstrap()
    stage_inject_sovereign_key()
    stage_validate_jwt_secret()          # HARD FAIL if JWT missing

    # ---- Intel Generation -------------------------------------------------
    stage_run_intel_engine()
    stage_pre_v70_manifest_sync()
    stage_v70_orchestrator()

    # ---- Manifest Processing ----------------------------------------------
    stage_manifest_stabilisation()
    stage_freshness_gate()               # HARD FAIL if < MIN entries
    stage_schema_validation()            # HARD FAIL if schema invalid
    stage_manifest_cleanup()

    # ---- Output Generation ------------------------------------------------
    stage_html_reports()                 # HARD FAIL if 0 reports
    stage_manifest_integrity_check()     # HARD FAIL on write_error entries
    stage_refresh_embedded_intel()

    # ---- Housekeeping -----------------------------------------------------
    stage_prune_stix_bundles()

    elapsed = time.monotonic() - t_total
    log.info("=" * 70)
    log.info("PIPELINE COMPLETE in %.1fs | Version: %s | %s",
             elapsed, PIPELINE_VERSION, utc_now())
    log.info("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise   # Allow hard-fail exits to propagate
    except Exception as e:
        import traceback
        log.critical(
            "UNHANDLED EXCEPTION in run_pipeline.py -- exiting 1:\n%s\n%s",
            e, traceback.format_exc()
        )
        sys.exit(1)
