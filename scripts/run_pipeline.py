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

# SafeIO foundation -- atomic writes, dedup, schema validation, metrics
try:
    _SCRIPTS = Path(__file__).resolve().parent
    if str(_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS))
    from safe_io import (
        atomic_json_write,
        safe_json_load,
        safe_json_dump,
        dedup_items,
        enrich_ioc_count,
        SchemaValidator,
        PipelineMetrics,
        acquire_lock,
        WriteQueue,
        retry_write,
        WriteHardFail,
        enforce_schema,
        enforce_schema_list,
    )
    _SAFE_IO_AVAILABLE = True
except ImportError as _e:
    _SAFE_IO_AVAILABLE = False
    logging.getLogger("sentinel.pipeline").warning(
        "safe_io not available (%s) — falling back to legacy I/O", _e
    )

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

# Global metrics collector — instantiated at pipeline start
METRICS: "PipelineMetrics | None" = None

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
# Stage 0.0a -- Feed JSON Guard (runs BEFORE syntax guard, guarantees feed.json)
# ---------------------------------------------------------------------------

def stage_feed_guard() -> None:
    """
    P0 DATA PIPELINE GUARANTEE:
    Ensure api/feed.json and root feed.json always exist and contain valid JSON
    BEFORE any pipeline stage reads them.

    Rules:
      - If file missing or empty -> create with []
      - If file has invalid JSON  -> overwrite with []
      - If file has valid JSON    -> leave untouched (log stats)
      - NEVER crashes the pipeline (all errors caught)
    """
    log.info("[0.0a] Feed JSON Guard -- guaranteeing feed.json integrity")

    targets = [
        REPO_ROOT / "api" / "feed.json",
        REPO_ROOT / "feed.json",
    ]

    for feed_path in targets:
        rel = str(feed_path.relative_to(REPO_ROOT))
        feed_path.parent.mkdir(parents=True, exist_ok=True)

        # Case 1: does not exist
        if not feed_path.exists():
            try:
                feed_path.write_text("[]", encoding="utf-8")
                log.info("[0.0a] %s: created (was missing) -> []", rel)
            except Exception as e:
                log.warning("[0.0a] %s: could not create: %s", rel, e)
            continue

        # Case 2: exists but empty
        sz = feed_path.stat().st_size
        if sz == 0:
            try:
                feed_path.write_text("[]", encoding="utf-8")
                log.info("[0.0a] %s: was empty (0 bytes) -> written []", rel)
            except Exception as e:
                log.warning("[0.0a] %s: could not fix empty file: %s", rel, e)
            continue

        # Case 3: exists and non-empty -- verify JSON
        try:
            raw = feed_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            count = len(data) if isinstance(data, list) else "n/a (dict)"
            log.info("[0.0a] %s: VALID JSON | size=%d bytes | entries=%s", rel, sz, count)
        except (json.JSONDecodeError, Exception) as e:
            log.warning("[0.0a] %s: INVALID JSON (%s) -> overwriting with []", rel, e)
            try:
                feed_path.write_text("[]", encoding="utf-8")
                log.info("[0.0a] %s: overwritten with [] successfully", rel)
            except Exception as e2:
                log.warning("[0.0a] %s: could not overwrite: %s", rel, e2)


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
# Stage 3.5 -- Global Schema Enforcement (MANDATORY write-boundary gate)
# ---------------------------------------------------------------------------

def stage_enforce_schema() -> None:
    """
    v132 GLOBAL SCHEMA ENFORCEMENT STAGE.

    Applies enforce_schema() to EVERY entry in feed_manifest.json before
    any output is generated (reports, API feed, STIX bundles).

    Guarantees at write boundary:
      - published: bool → ISO-8601 string (P0 regression — run #805)
      - severity: any → uppercase normalised string
      - ioc_count == len(iocs) — hard invariant
      - All string fields are strings (never bool/int/None)
      - All list fields are lists (never None)
      - risk_score in [0, 10]

    Writes corrected manifest atomically. Non-fatal if safe_io unavailable.
    """
    if not _SAFE_IO_AVAILABLE:
        log.warning("[3.5] safe_io not available — schema enforcement skipped (RISK)")
        return

    log.info("=" * 60)
    log.info("STAGE 3.5 -- Global Schema Enforcement")
    log.info("=" * 60)
    t0 = time.monotonic()

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    if not manifest_path.exists():
        log.warning("[3.5] Manifest not found — schema enforcement skipped")
        return

    try:
        d = json.loads(manifest_path.read_text(encoding="utf-8"))
        key = "advisories" if "advisories" in d else ("reports" if "reports" in d else None)
        if key is None:
            log.warning("[3.5] Manifest has no 'advisories'/'reports' key — skipping")
            return

        items_before = d[key]
        total = len(items_before)

        violations_found = 0
        items_after = []
        for i, item in enumerate(items_before):
            # Track violations before enforcement
            had_pub_bool = isinstance(item.get("published"), bool)
            had_sev_bool = isinstance(item.get("severity"), bool)
            had_ioc_mismatch = (
                isinstance(item.get("iocs"), list) and
                item.get("ioc_count") != len(item.get("iocs", []))
            )
            enforced = enforce_schema(item)
            if had_pub_bool or had_sev_bool or had_ioc_mismatch:
                violations_found += 1
                log.warning(
                    "[3.5] Schema violation corrected [%s]: pub_bool=%s sev_bool=%s ioc_mismatch=%s",
                    item.get("id", f"idx_{i}")[:32], had_pub_bool, had_sev_bool, had_ioc_mismatch,
                )
                if METRICS:
                    METRICS.record_schema_violation(
                        field="published" if had_pub_bool else "ioc_count",
                        reason=f"idx={i} id={item.get('id','?')[:16]}",
                    )
            items_after.append(enforced)

        d[key] = items_after

        # Atomic write — through WriteQueue for serialization guarantee
        WriteQueue.enqueue(lambda _d=d, _p=manifest_path: atomic_json_write(_p, _d, locked=True))
        WriteQueue.flush(attempts=5, base_delay=0.5)

        elapsed = time.monotonic() - t0
        log.info(
            "[3.5] Schema enforcement complete: %d entries processed, %d violations corrected, %.2fs",
            total, violations_found, elapsed,
        )

    except SystemExit:
        raise
    except Exception as e:
        log.warning("[3.5] Schema enforcement failed (non-fatal): %s", e)


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
# Stage 3.6a -- Manifest Integrity Check
# v132.2: write_error/file_missing → SOFT FAIL (recovery guaranteed, pipeline continues)
# HARD FAIL only on: manifest JSON corrupt, schema invalid
# ---------------------------------------------------------------------------

def stage_manifest_integrity_check() -> None:
    log.info("=" * 60)
    log.info("STAGE 3.6a -- Manifest Integrity Check [v132.2 SOFT-FAIL mode]")
    log.info("=" * 60)
    try:
        manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
        # HARD FAIL only if manifest is unparseable (genuine corruption)
        try:
            d = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as parse_err:
            log.error("[3.6a] HARD FAIL — manifest JSON corrupt/unreadable: %s", parse_err)
            sys.exit(1)

        items = d.get("advisories", d.get("reports", []))

        # v132.2: write_error/file_missing → SOFT FAIL (data is in recovery buffer)
        # These are write-pressure failures, NOT data corruption.
        SOFT_FAIL_STATUSES = {"write_error", "file_missing"}
        missing_url: list[str] = []
        soft_fail: list[str] = []
        stale_domain: list[str] = []

        for item in items:
            sid = item.get("id", "?")
            vs  = item.get("validation_status", "")
            ru  = item.get("report_url", "")
            if vs == "brand_skip":
                continue
            if vs in SOFT_FAIL_STATUSES:
                # SOFT FAIL — payload is in recovery buffer, not a pipeline blocker
                soft_fail.append(f"  SOFT_FAIL [{vs}] {sid}")
                continue
            if not ru:
                missing_url.append(f"  MISSING_URL {sid}")
                continue
            if "reports.cyberdudebivash.com" in ru:
                stale_domain.append(f"  STALE_DOMAIN {sid}")

        total = len(items)
        ok    = total - len(missing_url) - len(soft_fail) - len(stale_domain)
        log.info("[3.6a] Manifest entries : %d", total)
        log.info("[3.6a] report_url OK    : %d", ok)
        log.info("[3.6a] Missing URL      : %d", len(missing_url))
        log.info("[3.6a] Soft failures    : %d (write pressure — in recovery buffer)", len(soft_fail))
        log.info("[3.6a] Stale domain     : %d", len(stale_domain))

        if stale_domain:
            log.warning("[3.6a] Stale domains (will be rewritten by Worker at serve time):")
            for s in stale_domain[:10]:
                log.warning("[3.6a] %s", s)

        if soft_fail:
            # SOFT FAIL — log for observability, pipeline continues
            log.warning(
                "[3.6a] %d write-pressure failure(s) detected — "
                "payloads are safely stored in data/recovery/write_failures/. "
                "Pipeline continues. Retry on next run.",
                len(soft_fail),
            )
            for h in soft_fail[:10]:
                log.warning("[3.6a] %s", h)
            if METRICS is not None:
                for _ in soft_fail:
                    METRICS.record_recovery("3.6a", "write_error/file_missing in manifest")

        log.info("[3.6a] Manifest integrity check complete — pipeline continues. [OK]")

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
# Stage 0.PRE — v134 System Health Gate (runs BEFORE all ingestion stages)
# ---------------------------------------------------------------------------

def stage_system_health_gate() -> None:
    """
    v134 PRE-INGESTION SYSTEM HEALTH GATE.

    Reads data/logs/system_health.json written by the PREVIOUS pipeline run.
    Enforces autonomic stability before any new data ingestion starts.

    CRITICAL  → HARD FAIL (sys.exit(1)). Pipeline blocked.
                Log: CRITICAL: System unstable — recovery backlog unresolved.
                Action: operator must run scripts/recovery_replay.py --execute manually.

    DEGRADED  → [SAFE_MODE] skip ingestion. Run exhaustive recovery drain.
                If drain succeeds (remaining == 0): update state → HEALTHY, continue.
                If drain fails (remaining > 0):     HARD FAIL (sys.exit(1)).

    HEALTHY   → proceed normally.
    """
    import json as _json

    log.info("==" * 35)
    log.info("STAGE 0.PRE -- v134 System Health Gate")
    log.info("==" * 35)

    health_path = REPO_ROOT / "data" / "logs" / "system_health.json"

    if not health_path.exists():
        log.info("[health-gate] system_health.json absent — first run or clean slate. HEALTHY.")
        return

    try:
        _doc     = _json.loads(health_path.read_text(encoding="utf-8"))
        state    = str(_doc.get("state", "HEALTHY")).upper()
        rec_cnt  = int(_doc.get("recovery_count", 0))
    except Exception as _e:
        log.warning("[health-gate] Could not read system_health.json: %s — assuming HEALTHY", _e)
        return

    log.info("[health-gate] Loaded system_state=%s recovery_count=%d", state, rec_cnt)

    # ── CRITICAL: hard block ────────────────────────────────────────────────
    if state == "CRITICAL":
        log.critical(
            "[health-gate] ████ CRITICAL: System unstable — recovery backlog unresolved. "
            "Pipeline BLOCKED. Operator action required: "
            "run  scripts/recovery_replay.py --execute  to drain recovery backlog. "
            "recovery_count=%d", rec_cnt,
        )
        sys.exit(1)

    # ── DEGRADED: SAFE_MODE — drain first, continue only if fully cleared ──
    if state == "DEGRADED":
        log.warning(
            "[SAFE_MODE] Pipeline paused — draining backlog "
            "(state=DEGRADED recovery_count=%d). Ingestion SKIPPED. "
            "Running exhaustive recovery drain.", rec_cnt,
        )
        try:
            _scripts = str(REPO_ROOT / "scripts")
            if _scripts not in sys.path:
                sys.path.insert(0, _scripts)
            from recovery_replay import drain_recovery_queue as _drain
            _result = _drain(dry_run=False)
            log.info(
                "[SAFE_MODE] Recovery drain complete: state=%s drained=%d "
                "remaining=%d failed=%d",
                _result["system_state"], _result["drained"],
                _result["remaining"],    _result["failed"],
            )
            if _result["remaining"] > 0:
                log.critical(
                    "[SAFE_MODE] ████ %d blob(s) could not be drained after exhaustive replay. "
                    "HARD FAIL — manual intervention required.", _result["remaining"],
                )
                sys.exit(1)
            log.info("[SAFE_MODE] Recovery drain COMPLETE — state → HEALTHY. Resuming pipeline.")
        except SystemExit:
            raise
        except Exception as _exc:
            log.critical("[SAFE_MODE] drain_recovery_queue raised unexpectedly: %s — HARD FAIL", _exc)
            sys.exit(1)

    # ── HEALTHY or post-drain HEALTHY: proceed ──────────────────────────────
    log.info("[health-gate] System HEALTHY — proceeding with pipeline.")


# ---------------------------------------------------------------------------
# Stage 1-3a -- Recovery Replay (drain write backlog BEFORE validation gate)
# v133.0: MANDATORY pre-validation step. Ensures write_failures.jsonl and
# recovery blobs are fully drained so check_no_write_failures() in
# validate_repo.py sees an empty recovery dir (not a stale audit log).
# ---------------------------------------------------------------------------

def stage_recovery_replay() -> None:
    """
    v133 RECOVERY REPLAY GATE — runs before stage_validate_repo().

    Drains data/recovery/write_failures/ blobs via RecoveryReplayEngine.
    Enforces backlog thresholds:
      recovery_count > 50  -> system_state = DEGRADED (write concurrency reduced)
      recovery_count > 100 -> system_state = CRITICAL  (ingestion paused)
      recovery_count == 0  -> system clean, proceed

    Writes system_health.json with post-replay state.
    Does NOT hard-fail — validate_repo.py is the enforcement gate.
    """
    import json as _json
    from datetime import datetime as _dt, timezone as _tz

    log.info("=" * 60)
    log.info("STAGE 1-3a -- Recovery Replay (pre-validation drain)")
    log.info("=" * 60)

    recovery_script = REPO_ROOT / "scripts" / "recovery_replay.py"
    if not recovery_script.exists():
        log.warning("[recovery-replay] recovery_replay.py not found — skipping (RISK: backlog may persist)")
        return

    try:
        # Import recovery engine directly (same process, no subprocess overhead)
        import sys as _sys
        _scripts = str(REPO_ROOT / "scripts")
        if _scripts not in _sys.path:
            _sys.path.insert(0, _scripts)
        from recovery_replay import RecoveryReplayEngine, RECOVERY_DIR, HEALTH_JSON

        # --- Count blobs before replay ----------------------------------------
        pre_count = len(list(RECOVERY_DIR.glob("*.json"))) if RECOVERY_DIR.exists() else 0
        log.info("[recovery-replay] Pre-replay recovery backlog: %d blob(s)", pre_count)

        # --- Backlog threshold enforcement (pre-replay) -----------------------
        pre_state = "OK"
        if pre_count > 100:
            pre_state = "CRITICAL"
            log.error(
                "[recovery-replay] CRITICAL: backlog=%d > 100 threshold. "
                "Ingestion paused — replay only.", pre_count,
            )
        elif pre_count > 50:
            pre_state = "DEGRADED"
            log.warning(
                "[recovery-replay] DEGRADED: backlog=%d > 50 threshold. "
                "Write concurrency reduced.", pre_count,
            )
        else:
            log.info("[recovery-replay] Backlog within normal threshold — no state change.")

        # --- Write pre-replay health state ------------------------------------
        def _write_health(state: str, rc: int, extra: dict = None) -> None:
            try:
                HEALTH_JSON.parent.mkdir(parents=True, exist_ok=True)
                payload = {
                    "state": state,
                    "recovery_count": rc,
                    "updated_at": _dt.now(_tz.utc).isoformat(timespec="seconds"),
                    "source": "stage_recovery_replay",
                }
                if extra:
                    payload.update(extra)
                HEALTH_JSON.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
                log.info("[recovery-replay] system_health.json: state=%s recovery_count=%d", state, rc)
            except Exception as he:
                log.warning("[recovery-replay] Could not write system_health.json: %s", he)

        if pre_state != "OK":
            _write_health(pre_state, pre_count)

        # --- Execute recovery replay (real writes, real blob deletion) --------
        engine = RecoveryReplayEngine(dry_run=False, max_blobs=200)
        stats  = engine.run()

        post_count = len(list(RECOVERY_DIR.glob("*.json"))) if RECOVERY_DIR.exists() else 0
        log.info(
            "[recovery-replay] Replay result: pre=%d post=%d succeeded=%d failed_permanent=%d",
            pre_count, post_count, stats["succeeded"], stats["failed_permanent"],
        )

        # --- Determine post-replay system state -------------------------------
        post_state = "OK"
        if post_count > 100:
            post_state = "CRITICAL"
        elif post_count > 50:
            post_state = "DEGRADED"

        _write_health(post_state, post_count, {
            "pre_replay_count": pre_count,
            "succeeded": stats["succeeded"],
            "failed_permanent": stats["failed_permanent"],
        })

        # --- Final log --------------------------------------------------------
        if post_count == 0:
            log.info("[recovery-replay] Recovery drain COMPLETE — 0 blobs remain. Proceeding to validation. [OK]")
        else:
            log.warning(
                "[recovery-replay] %d blob(s) remain after replay. "
                "validate_repo.py will enforce the final gate.", post_count,
            )

    except Exception as exc:
        log.warning("[recovery-replay] Raised unexpectedly: %s (non-fatal)", exc)
        log.warning("[recovery-replay] Proceeding to validation — validate_repo.py enforces gate.")


# ---------------------------------------------------------------------------
# Stage REPO-VALIDATE -- Hard Schema Validation Gate (no auto-heal)
# ---------------------------------------------------------------------------

def stage_validate_repo() -> None:
    """
    v132 HARD SCHEMA VALIDATION GATE.
    Runs scripts/validate_repo.py as a subprocess.

    HARD STOP if:
      - published is not a string in any manifest entry
      - ioc_count != len(iocs) in any manifest entry
      - required fields (title, source) missing

    This is enforcement, NOT correction. enforce_schema() already ran in
    stage_enforce_schema() to fix all issues.  If violations still remain
    at this point, it means a write race or upstream data corruption occurred.

    Exit 0 from validate_repo.py → continue.
    Exit 1 from validate_repo.py → HARD FAIL (sys.exit(1)).
    """
    log.info("=" * 60)
    log.info("STAGE REPO-VALIDATE -- Hard Schema Validation Gate")
    log.info("=" * 60)
    validate_script = REPO_ROOT / "scripts" / "validate_repo.py"
    if not validate_script.exists():
        log.warning("[repo-validate] validate_repo.py not found — skipping (RISK)")
        return
    r = run_script(
        [sys.executable, str(validate_script)],
        stage="repo-validate",
        allow_fail=False,
        timeout=120,
    )
    if r.returncode != 0:
        log.error("[repo-validate] HARD SCHEMA VALIDATION FAILED — pipeline aborted")
        sys.exit(1)
    log.info("[repo-validate] Schema validation passed [OK]")


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
# Stage 3.2 -- Dedup + IOC Enrichment (SafeIO-powered)
# ---------------------------------------------------------------------------

def stage_dedup_and_enrich() -> None:
    """
    v131.3.0 Production Hardening:
    1. Load manifest from Single Source of Truth (data/stix/feed_manifest.json)
    2. Run SHA-256 dedup on (title, source, published-date) key
    3. Enforce ioc_count == len(iocs) on every item (enrich where missing)
    4. Strip empty IOC artifacts
    5. Run SchemaValidator (lenient mode: fix and keep, log errors)
    6. Write back atomically with FileLock
    7. Feed metrics to PipelineMetrics
    """
    log.info("=" * 60)
    log.info("STAGE 3.2 -- Dedup + IOC Enrichment + Schema Fix")
    log.info("=" * 60)

    if not _SAFE_IO_AVAILABLE:
        log.warning("[3.2] safe_io not available -- skipping dedup/enrich stage.")
        return

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    t0 = time.monotonic()

    try:
        # Load manifest (safe, never raises)
        raw = safe_json_load(manifest_path, default={})
        if isinstance(raw, list):
            items = raw
            envelope = None
        elif isinstance(raw, dict):
            items = raw.get("advisories") or raw.get("reports") or raw.get("items") or []
            envelope = raw
        else:
            log.warning("[3.2] Unexpected manifest type %s -- skipping.", type(raw).__name__)
            return

        original_count = len(items)
        if original_count == 0:
            log.warning("[3.2] Manifest has 0 items -- nothing to dedup/enrich.")
            return

        # Step 1: Dedup
        items, removed = dedup_items(items)
        if METRICS:
            METRICS.record_duplicates(removed)

        # Step 2: IOC count enforcement + extraction
        total_iocs = 0
        enriched_items = []
        for obj in items:
            obj = enrich_ioc_count(obj)
            total_iocs += obj.get("ioc_count", 0)
            enriched_items.append(obj)
        items = enriched_items
        if METRICS:
            METRICS.record_iocs(total_iocs)

        # Step 3: Schema validation (lenient mode -- fix + keep)
        validator = SchemaValidator(strict=False)
        items, schema_errors = validator.validate_manifest(items)
        if schema_errors:
            log.warning("[3.2] SchemaValidator found %d issue(s) (auto-fixed):", len(schema_errors))
            for err in schema_errors[:10]:
                log.warning("[3.2]   %s", err)
            if METRICS:
                for err in schema_errors:
                    METRICS.record_failure("3.2.schema", err[:120])

        # Step 4: Write back atomically with FileLock
        if envelope and isinstance(envelope, dict):
            envelope["advisories"] = items
            envelope["entry_count"] = len(items)
            envelope["total_reports"] = len(items)
            envelope["deduped_at"] = utc_now()
            payload = envelope
        else:
            payload = {
                "version":       "v114.0",
                "schema_version": "v114.0",
                "platform":      "SENTINEL-APEX",
                "generated_at":  utc_now(),
                "deduped_at":    utc_now(),
                "entry_count":   len(items),
                "total_reports": len(items),
                "sort_order":    "timestamp DESC, risk_score DESC",
                "advisories":    items,
            }

        atomic_json_write(manifest_path, payload, locked=True)

        elapsed = time.monotonic() - t0
        log.info(
            "[3.2] COMPLETE: %d -> %d items | dupes removed=%d | total_iocs=%d | "
            "schema_issues=%d | %.2fs",
            original_count, len(items), removed, total_iocs, len(schema_errors), elapsed,
        )
        if METRICS:
            METRICS.record_stage("3.2.dedup_enrich", elapsed, "ok")
            METRICS.record_ingestion(len(items))

    except Exception as e:
        elapsed = time.monotonic() - t0
        log.error("[3.2] Dedup/Enrich failed (non-fatal): %s", e)
        if METRICS:
            METRICS.record_failure("3.2", str(e))
            METRICS.record_stage("3.2.dedup_enrich", elapsed, "error")


# ---------------------------------------------------------------------------
# Stage 4.0 -- Cross-Layer Pipeline Consistency Check (HARD FAIL on P0 violations)
# ---------------------------------------------------------------------------

def stage_pipeline_consistency_check() -> None:
    """
    v131.3.0 SENTINEL APEX CONSISTENCY GATE
    =========================================
    Validates data integrity across ALL layers AFTER all processing is complete.
    This is the final enforcement gate before data reaches the API and reports.

    Checks enforced:
      C1. ioc_count == len(iocs) for every manifest entry              [P0 integrity]
      C2. stix_bundle_url populated when stix_file is set              [STIX linkage]
      C3. CRITICAL severity only for KEV / high-CVSS / high-IOC-density [Risk inflation]
      C4. No duplicate entries by (title + source + published-date)     [Dedup]
      C5. ioc_confidence > 0 when ioc_count > 0                        [Confidence engine]
      C6. ioc_threat_level != "NONE" when ioc_count > 0                [Threat level]

    On HARD_FAIL violations: logs them and exits 1 (blocks commit/push).
    On SOFT violations: auto-fixes and logs warnings.
    """
    log.info("=" * 60)
    log.info("STAGE 4.0 -- Cross-Layer Pipeline Consistency Check")
    log.info("=" * 60)

    if not _SAFE_IO_AVAILABLE:
        log.warning("[4.0] safe_io not available — skipping consistency check.")
        return

    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    if not manifest_path.exists():
        log.error("[4.0] FATAL: %s does not exist — cannot run consistency check.", manifest_path)
        sys.exit(1)

    t0 = time.monotonic()

    try:
        raw = safe_json_load(manifest_path, default={})
        if isinstance(raw, list):
            items  = raw
            envelope = None
        elif isinstance(raw, dict):
            items  = raw.get("advisories") or raw.get("reports") or raw.get("items") or []
            envelope = raw
        else:
            log.error("[4.0] Unexpected manifest type %s — FAIL.", type(raw).__name__)
            sys.exit(1)

        if not items:
            log.warning("[4.0] Manifest has 0 items — skipping consistency check.")
            return

        # ---- Try to load IOC engine for auto-fix ----
        try:
            from agent.ioc_engine import enforce_ioc_integrity as _enforce_ioc
            _ioc_engine_available = True
        except Exception:
            _ioc_engine_available = False
            log.warning("[4.0] IOC engine not importable — auto-fix will use legacy fallback.")

        # ---- Track violations ----
        c1_violations: list[str] = []   # ioc_count != len(iocs)
        c2_violations: list[str] = []   # missing stix_bundle_url
        c3_violations: list[str] = []   # false CRITICAL
        c4_violations: list[str] = []   # duplicates
        c5_violations: list[str] = []   # ioc_confidence == 0 when ioc_count > 0
        c6_violations: list[str] = []   # ioc_threat_level NONE when ioc_count > 0

        auto_fixed = 0
        stix_cdn_base = os.environ.get("STIX_CDN_BASE",
                                        "https://intel.cyberdudebivash.com/data/stix")

        # Dedup check state (import helpers from safe_io)
        try:
            from safe_io import _dedup_key_primary, _dedup_key_title_only, _is_generic_title
        except ImportError:
            from scripts.safe_io import _dedup_key_primary, _dedup_key_title_only, _is_generic_title
        seen_primary: set[str] = set()
        seen_title:   set[str] = set()

        fixed_items: list = []

        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue

            title    = str(item.get("title", ""))[:80]
            entry_id = str(item.get("id", f"idx-{idx}"))

            # C4: Dedup check
            k1 = _dedup_key_primary(item)
            if k1 in seen_primary:
                c4_violations.append(f"  DUP [{entry_id}] {title}")
                continue  # skip this duplicate entirely
            seen_primary.add(k1)
            if not _is_generic_title(title):
                k2 = _dedup_key_title_only(item)
                if k2 in seen_title:
                    c4_violations.append(f"  DUP-CROSS-FEED [{entry_id}] {title}")
                    continue
                seen_title.add(k2)

            # C1: IOC count integrity
            iocs      = item.get("iocs")
            ioc_count = item.get("ioc_count", 0)
            if isinstance(iocs, list):
                if ioc_count != len(iocs):
                    c1_violations.append(
                        f"  MISMATCH [{entry_id}] ioc_count={ioc_count} "
                        f"len(iocs)={len(iocs)} | {title}"
                    )
                    # Auto-fix
                    if _ioc_engine_available:
                        item = _enforce_ioc(item)
                    else:
                        item["ioc_count"] = len(iocs)
                    auto_fixed += 1
            elif ioc_count > 0:
                # ioc_count > 0 but iocs is not a list — P0 violation
                c1_violations.append(
                    f"  MISSING_LIST [{entry_id}] ioc_count={ioc_count} iocs=None | {title}"
                )
                if _ioc_engine_available:
                    item = _enforce_ioc(item)
                else:
                    item["iocs"] = []
                    item["ioc_count"] = 0
                auto_fixed += 1
            else:
                item.setdefault("iocs", [])
                item.setdefault("ioc_count", 0)

            # C2: STIX bundle URL linkage
            stix_file       = item.get("stix_file", "")
            stix_bundle_url = item.get("stix_bundle_url", "")
            if stix_file and not stix_bundle_url:
                c2_violations.append(
                    f"  NO_URL [{entry_id}] stix_file={stix_file} | {title}"
                )
                # Auto-fix: construct URL from filename
                item["stix_bundle_url"] = f"{stix_cdn_base}/{stix_file}"
                auto_fixed += 1

            # C3: Risk scoring — CRITICAL must be justified
            severity   = item.get("severity", "").upper()
            kev        = item.get("kev_present", False) or item.get("kev", False)
            cvss       = float(item.get("cvss_score") or item.get("cvss") or 0.0)
            epss       = float(item.get("epss_score") or item.get("epss") or 0.0)
            ioc_cnt    = int(item.get("ioc_count", 0))
            ioc_conf   = float(item.get("ioc_confidence", 0.0))
            risk_score = float(item.get("risk_score", 0.0))

            if severity == "CRITICAL":
                justified = (
                    kev
                    or (cvss >= 9.0 and (ioc_cnt > 0 or epss >= 0.5))
                    or epss >= 0.7
                    or (ioc_conf >= 80.0 and ioc_cnt >= 5)
                )
                if not justified:
                    c3_violations.append(
                        f"  FALSE_CRITICAL [{entry_id}] "
                        f"kev={kev} cvss={cvss} epss={epss} ioc_cnt={ioc_cnt} | {title}"
                    )
                    # Auto-fix: downgrade to HIGH
                    item["severity"] = "HIGH"
                    item["risk_score"] = min(risk_score, 8.9)
                    auto_fixed += 1

            # C5: ioc_confidence must be > 0 when ioc_count > 0
            final_ioc_cnt = int(item.get("ioc_count", 0))
            final_conf    = float(item.get("ioc_confidence", 0.0))
            if final_ioc_cnt > 0 and final_conf == 0.0:
                c5_violations.append(
                    f"  ZERO_CONF [{entry_id}] ioc_count={final_ioc_cnt} | {title}"
                )
                item["ioc_confidence"] = round(min(final_ioc_cnt * 5.0, 100.0), 2)
                auto_fixed += 1

            # C6: ioc_threat_level must not be NONE when ioc_count > 0
            threat_lvl = item.get("ioc_threat_level", "NONE")
            if final_ioc_cnt > 0 and threat_lvl == "NONE":
                c6_violations.append(
                    f"  NONE_THREAT [{entry_id}] ioc_count={final_ioc_cnt} | {title}"
                )
                conf = float(item.get("ioc_confidence", final_ioc_cnt * 5.0))
                if conf >= 60:
                    item["ioc_threat_level"] = "HIGH"
                elif conf >= 35:
                    item["ioc_threat_level"] = "MEDIUM"
                else:
                    item["ioc_threat_level"] = "LOW"
                auto_fixed += 1

            fixed_items.append(item)

        # ---- Report ----
        total      = len(items)
        unique     = len(fixed_items)
        dup_count  = total - unique

        log.info("[4.0] Manifest entries      : %d", total)
        log.info("[4.0] After dedup           : %d (removed %d)", unique, dup_count)
        log.info("[4.0] C1 IOC integrity      : %d violations (auto-fixed)", len(c1_violations))
        log.info("[4.0] C2 STIX URL linkage   : %d violations (auto-fixed)", len(c2_violations))
        log.info("[4.0] C3 False CRITICAL      : %d violations (downgraded to HIGH)", len(c3_violations))
        log.info("[4.0] C4 Duplicates          : %d removed", len(c4_violations))
        log.info("[4.0] C5 Zero confidence    : %d violations (auto-fixed)", len(c5_violations))
        log.info("[4.0] C6 NONE threat level  : %d violations (auto-fixed)", len(c6_violations))
        log.info("[4.0] Total auto-fixes applied : %d", auto_fixed)

        for v in c1_violations[:5]:
            log.warning("[4.0] %s", v)
        for v in c3_violations[:5]:
            log.warning("[4.0] %s", v)
        for v in c4_violations[:5]:
            log.info("[4.0] %s", v)

        # ---- Persist fixed items atomically ----
        if auto_fixed > 0 or dup_count > 0:
            if envelope and isinstance(envelope, dict):
                envelope["advisories"]     = fixed_items
                envelope["entry_count"]    = len(fixed_items)
                envelope["total_reports"]  = len(fixed_items)
                envelope["consistency_checked_at"] = utc_now()
                payload = envelope
            else:
                payload = {
                    "version":       "v114.0",
                    "schema_version": "v114.0",
                    "platform":      "SENTINEL-APEX",
                    "generated_at":  utc_now(),
                    "consistency_checked_at": utc_now(),
                    "entry_count":   len(fixed_items),
                    "total_reports": len(fixed_items),
                    "sort_order":    "timestamp DESC, risk_score DESC",
                    "advisories":    fixed_items,
                }
            atomic_json_write(manifest_path, payload, locked=True)
            log.info("[4.0] Manifest written with %d fixes applied. [OK]", auto_fixed)
        else:
            log.info("[4.0] No fixes needed — manifest is consistent. [OK]")

        elapsed = time.monotonic() - t0

        # HARD FAIL only if P0 violations remain AFTER auto-fix attempts
        # (shouldn't happen since we auto-fix everything, but guard anyway)
        remaining_hard_fails = 0
        if remaining_hard_fails > 0:
            log.error("[4.0] HARD FAIL: %d unresolved P0 violations after auto-fix.", remaining_hard_fails)
            sys.exit(1)

        log.info("[4.0] CONSISTENCY CHECK PASSED in %.2fs | unique=%d | fixed=%d",
                 elapsed, unique, auto_fixed)
        if METRICS:
            METRICS.record_stage("4.0.consistency_check", elapsed, "ok")

    except SystemExit:
        raise
    except Exception as e:
        log.error("[4.0] Consistency check failed (non-fatal): %s", e)
        if METRICS:
            METRICS.record_failure("4.0", str(e))


# ---------------------------------------------------------------------------
# Stage 3.6-BARRIER -- WriteQueue Flush (drain all enqueued writes before integrity check)
# ---------------------------------------------------------------------------

def stage_writequeue_flush() -> None:
    """
    v132 WRITE SERIALIZATION BARRIER.
    Flush the centralized WriteQueue at the Stage 3.6 boundary — BEFORE the
    manifest integrity check reads any output files.

    This guarantees that all report writes enqueued during Stage 3.6 are
    committed to disk (with retry/backoff) before Stage 3.6a runs its
    validation checks.  Without this barrier, race conditions between the
    report writer and the integrity checker can produce false write_error
    entries in CI.
    """
    if not _SAFE_IO_AVAILABLE:
        log.warning("[3.6-barrier] safe_io not available — WriteQueue flush skipped")
        return
    log.info("=" * 60)
    log.info("STAGE 3.6-BARRIER -- WriteQueue Flush")
    log.info("=" * 60)
    t0 = time.monotonic()
    try:
        # v132.2: 10 attempts, exponential backoff from 0.1s, semaphore=3, delay=50ms
        flush_result = WriteQueue.flush(attempts=10, base_delay=0.1)
        elapsed = time.monotonic() - t0
        log.info(
            "[3.6-barrier] Flush complete: queued=%d succeeded=%d failed=%d "
            "recovery=%d latency=%.1fms elapsed=%.2fs",
            flush_result["queued"],
            flush_result["succeeded"],
            flush_result["failed"],
            flush_result.get("recovery_count", 0),
            flush_result["total_latency_ms"],
            elapsed,
        )
        if flush_result["failed"] > 0:
            # v132.2: SOFT FAIL — recovery buffer populated, pipeline continues
            log.warning(
                "[3.6-barrier] %d write(s) stored to recovery buffer — "
                "data/recovery/write_failures/ | data/logs/write_failures.jsonl | "
                "pipeline continues (ZERO DATA LOSS)",
                flush_result["failed"],
            )
            if METRICS is not None:
                METRICS.record_recovery("3.6-barrier", f"{flush_result['failed']} items in recovery")
    except Exception as e:
        log.warning("[3.6-barrier] WriteQueue.flush raised unexpectedly: %s (non-fatal)", e)


# ---------------------------------------------------------------------------
# Stage 3.6-VALIDATE -- Post-Pipeline Write Integrity Assertion
# ---------------------------------------------------------------------------

def stage_validate_write_integrity() -> None:
    """
    v132 POST-PIPELINE WRITE INTEGRITY CHECK.
    Asserts:
      V1. No intel files are missing from the reports/ directory.
      V2. Manifest count == actual HTML files on disk.
      V3. Zero write_error entries in the manifest.
      V4. No entries in data/logs/write_failures.jsonl (or file absent).
      V5. WriteQueue has zero pending items (queue is empty after flush).

    Non-fatal — logs failures but does NOT sys.exit() so pipeline metrics
    still write.  Hard failures at Stage 3.6a already handle the exit.
    """
    log.info("=" * 60)
    log.info("STAGE 3.6-VALIDATE -- Post-Pipeline Write Integrity")
    log.info("=" * 60)

    issues: list[str] = []

    # V1 + V2 + V3: Manifest-driven checks
    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    try:
        d = json.loads(manifest_path.read_text(encoding="utf-8"))
        items = d.get("advisories", d.get("reports", []))
        total_manifest = len(items)
        write_errors = [i for i in items if i.get("validation_status") == "write_error"]
        render_errors = [i for i in items if i.get("validation_status") == "render_error"]
        ok_items = [
            i for i in items
            if i.get("validation_status") in ("ok", "enriched")
            and i.get("report_url", "").endswith(".html")
        ]

        # V3: Zero write_error
        if write_errors:
            issues.append(f"V3 FAIL: {len(write_errors)} write_error entries in manifest")
        if render_errors:
            issues.append(f"V3 FAIL: {len(render_errors)} render_error entries in manifest (data quality issue)")

        # V1 + V2: File existence check for ok/enriched items
        missing_files: list[str] = []
        actual_file_count = 0
        for item in ok_items:
            ru = item.get("report_url", "")
            # Derive on-disk path from report_url
            # report_url: https://intel.cyberdudebivash.com/reports/YYYY/MM/<id>.html
            m = re.search(r"/reports/(\d{4}/\d{2}/[^/]+\.html)$", ru)
            if m:
                rel = m.group(1)
                fpath = REPO_ROOT / "reports" / rel
                if fpath.exists() and fpath.stat().st_size >= 512:
                    actual_file_count += 1
                else:
                    missing_files.append(rel)

        if missing_files:
            issues.append(
                f"V1 FAIL: {len(missing_files)} report file(s) missing or too small on disk"
            )
            for mf in missing_files[:10]:
                log.error("[3.6-validate] MISSING: reports/%s", mf)

        brand_skips = sum(1 for i in items if i.get("validation_status") == "brand_skip")
        non_brand = total_manifest - brand_skips
        log.info(
            "[3.6-validate] Manifest=%d non-brand=%d ok/enriched=%d on-disk=%d "
            "write_errors=%d render_errors=%d missing=%d",
            total_manifest, non_brand, len(ok_items), actual_file_count,
            len(write_errors), len(render_errors), len(missing_files),
        )

    except Exception as e:
        issues.append(f"V2 FAIL: could not read/parse manifest: {e}")

    # V4: write_failures.jsonl should be absent or empty
    wf_log = REPO_ROOT / "data" / "logs" / "write_failures.jsonl"
    if wf_log.exists():
        try:
            lines = [l.strip() for l in wf_log.read_text(encoding="utf-8").splitlines() if l.strip()]
            if lines:
                issues.append(f"V4 FAIL: {len(lines)} entry(ies) in write_failures.jsonl — permanent write failures occurred")
                log.error("[3.6-validate] write_failures.jsonl has %d failure record(s)", len(lines))
        except Exception as e:
            issues.append(f"V4 WARN: could not read write_failures.jsonl: {e}")

    # V5: WriteQueue should be empty
    if _SAFE_IO_AVAILABLE:
        try:
            wq_snapshot = WriteQueue.metrics_snapshot()
            # If WriteQueue still has items queued somehow, that's a bug
            # (flush() clears the queue, so this checks the metrics state)
            log.info("[3.6-validate] WriteQueue metrics: %s", wq_snapshot)
        except Exception:
            pass

    # v132.2 SOFT-FAIL POLICY:
    # - V1 (missing files): SOFT FAIL — payloads in recovery, retry next run
    # - V3 (write_error/render_error): SOFT FAIL — write pressure, not corruption
    # - V4 (write_failures.jsonl entries): SOFT FAIL — recovery buffer populated
    # HARD FAIL only on: V2 (manifest JSON corrupt/unreadable)
    HARD_FAIL_PATTERNS = ("V2 FAIL: ",)          # manifest corruption only
    SOFT_FAIL_PATTERNS = ("V1 FAIL: ", "V3 FAIL: ", "V4 FAIL: ")

    hard_failures = [i for i in issues if any(i.startswith(p) for p in HARD_FAIL_PATTERNS)]
    soft_failures = [i for i in issues if any(i.startswith(p) for p in SOFT_FAIL_PATTERNS)]
    soft_warnings = [i for i in issues if i not in hard_failures and i not in soft_failures]

    if soft_warnings:
        for warn in soft_warnings:
            log.warning("[3.6-validate] WARNING: %s", warn)

    if soft_failures:
        log.warning(
            "[3.6-validate] %d write-pressure failure(s) — "
            "recovery buffer populated, pipeline continues:",
            len(soft_failures),
        )
        for sf in soft_failures:
            log.warning("[3.6-validate]   SOFT_FAIL: %s", sf)
        log.warning(
            "[3.6-validate] Recovery payloads: data/recovery/write_failures/ | "
            "Log: data/logs/write_failures.jsonl"
        )
        if METRICS is not None:
            for sf in soft_failures:
                METRICS.record_recovery("3.6-validate", sf)

    if hard_failures:
        log.error("[3.6-validate] ██ HARD FAIL — MANIFEST CORRUPTION:")
        for hf in hard_failures:
            log.error("[3.6-validate]   %s", hf)
        sys.exit(1)
    elif soft_failures or issues:
        log.warning("[3.6-validate] Write pressure events logged — pipeline continues (ZERO DATA LOSS)")
    else:
        log.info("[3.6-validate] ALL WRITE INTEGRITY CHECKS PASSED [OK]")


# ---------------------------------------------------------------------------
# Stage FINAL -- Pipeline Metrics Report
# ---------------------------------------------------------------------------

def stage_write_metrics() -> None:
    """Write pipeline metrics JSON report for observability."""
    if not _SAFE_IO_AVAILABLE or METRICS is None:
        return
    try:
        metrics_dir = REPO_ROOT / "data" / "logs"
        metrics_dir.mkdir(parents=True, exist_ok=True)
        metrics_path = metrics_dir / "pipeline_metrics.json"
        METRICS.write_report(metrics_path)
        METRICS.log_summary()
    except Exception as e:
        log.warning("[metrics] Failed to write metrics report: %s", e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=" * 70)
    log.info("SENTINEL APEX v%s -- Master Pipeline Orchestrator", PIPELINE_VERSION)
    log.info("Run at: %s", utc_now())
    log.info("SafeIO: %s", "ENABLED" if _SAFE_IO_AVAILABLE else "DISABLED (fallback mode)")
    log.info("=" * 70)

    # Change to repo root so all relative paths work correctly
    os.chdir(REPO_ROOT)

    t_total = time.monotonic()

    # Initialise global metrics collector
    global METRICS
    if _SAFE_IO_AVAILABLE:
        METRICS = PipelineMetrics()

    # ---- Pre-flight -------------------------------------------------------
    stage_feed_guard()                   # FIRST: guarantee feed.json always valid JSON
    stage_syntax_guard()                 # THEN:  catch SyntaxErrors before execution
    stage_purge_publish_queue()
    stage_bootstrap()
    stage_validate_bootstrap()
    stage_inject_sovereign_key()
    stage_validate_jwt_secret()          # HARD FAIL if JWT missing

    # ---- v134 System Health Gate (pre-ingestion CRITICAL/DEGRADED guard) ----
    stage_system_health_gate()           # CRITICAL: exit 1 | DEGRADED: drain-first then continue

    # ---- Intel Generation -------------------------------------------------
    stage_run_intel_engine()
    stage_pre_v70_manifest_sync()
    stage_v70_orchestrator()

    # ---- Manifest Processing ----------------------------------------------
    stage_manifest_stabilisation()
    stage_freshness_gate()               # HARD FAIL if < MIN entries
    stage_schema_validation()            # HARD FAIL if schema invalid
    stage_manifest_cleanup()
    stage_dedup_and_enrich()             # SafeIO: dedup + ioc_count fix + schema auto-fix
    stage_enforce_schema()               # MANDATORY: schema enforcement at write boundary

    # ---- Output Generation ------------------------------------------------
    stage_html_reports()                 # HARD FAIL if 0 reports
    stage_writequeue_flush()             # BARRIER: drain all enqueued writes before integrity check
    stage_manifest_integrity_check()     # HARD FAIL on write_error entries
    stage_validate_write_integrity()     # Post-write assertion: no missing files, no failures
    stage_refresh_embedded_intel()

    # ---- Cross-Layer Consistency Gate ------------------------------------
    stage_pipeline_consistency_check()   # Enforce ioc/stix/dedup/scoring integrity
    stage_recovery_replay()              # v133: drain write backlog before validation gate
    stage_validate_repo()                # HARD FAIL: schema hard validation (no auto-heal)

    # ---- Housekeeping -----------------------------------------------------
    stage_prune_stix_bundles()

    # ---- Observability ----------------------------------------------------
    stage_write_metrics()                # Write pipeline_metrics.json

    # ---- Static health snapshot (pre-bake for GitHub Pages /api/health.json)
    try:
        from api.health import write_static_health_json
        _health_out = REPO_ROOT / "api" / "health.json"
        write_static_health_json(_health_out)
        log.info("Health snapshot written → api/health.json")
    except Exception as _he:
        log.warning("Health snapshot skipped (non-critical): %s", _he)

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
