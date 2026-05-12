#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v148.0.0
EMIT AI TELEMETRY — Pipeline Observability Artifact Writer
===============================================================================
PURPOSE:
  Writes data/ai-telemetry/last-run.json after every generate-and-sync run.
  Reads all values from environment variables — zero inline Python in YAML.
  Called by generate-and-sync.yml STAGE 7 (Phase 6 Scale Governance).

OUTPUT:
  data/ai-telemetry/last-run.json  -- structured pipeline run telemetry

SCHEMA: sentinel-apex-ai-telemetry-v1
  {
    "schema":           "sentinel-apex-ai-telemetry-v1",
    "run_id":           str,    -- GITHUB_RUN_ID
    "run_number":       int,    -- GITHUB_RUN_NUMBER
    "pipeline_version": str,    -- PIPELINE_VERSION
    "generated_at":     str,    -- ISO-8601 UTC timestamp
    "duration_seconds": int,    -- total wall-clock pipeline time
    "dry_run":          bool,   -- DRY_RUN env flag
    "step_timing_ms":   dict,   -- per-step timing breakdown
    "output_sizes_kb":  dict,   -- output file sizes in KB
    "feed_summary":     dict,   -- feed item count + GRI score
    "health":           str     -- "ok" | "warn" | "error"
  }

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
import datetime
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [emit_ai_telemetry] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-AI-TELEMETRY")

REPO_ROOT = Path(__file__).resolve().parent.parent
TELEMETRY_DIR = REPO_ROOT / "data" / "ai-telemetry"
TELEMETRY_FILE = TELEMETRY_DIR / "last-run.json"

AI_OUTPUTS = [
    "api/ai/tracker.json",
    "api/ai/health.json",
    "api/ai/executive-brief.json",
    "api/ai/monetization.json",
]


def safe_int(val, default=0):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def get_file_size_kb(rel_path):
    p = REPO_ROOT / rel_path
    if p.exists():
        return round(p.stat().st_size / 1024, 1)
    return 0


def get_tracker_summary():
    tracker_path = REPO_ROOT / "api" / "ai" / "tracker.json"
    if not tracker_path.exists():
        return {"feed_items": 0, "gri_score": "N/A", "generated_at": "N/A"}
    try:
        data = json.loads(tracker_path.read_text(encoding="utf-8"))
        gri = data.get("global_risk_index", {})
        return {
            "feed_items": data.get("feed_item_count", 0),
            "gri_score": gri.get("gri_score", "N/A"),
            "gri_label": gri.get("gri_label", "N/A"),
            "generated_at": data.get("generated_at", "N/A"),
            "schema": data.get("schema", "N/A"),
            "version": data.get("version", "N/A"),
        }
    except Exception as exc:
        log.warning("Could not parse tracker.json: %s", exc)
        return {"feed_items": 0, "gri_score": "N/A"}


def main():
    TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)

    # Read all values from environment — zero coupling to YAML internals
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    run_number = safe_int(os.environ.get("GITHUB_RUN_NUMBER"), 0)
    pipeline_version = os.environ.get("PIPELINE_VERSION", "148.0.0")
    duration_seconds = safe_int(os.environ.get("PIPELINE_DURATION_SECONDS"), 0)
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    step_deps_ms = safe_int(os.environ.get("STEP_TIMING_DEPS_MS"), 0)
    step_gen_ms = safe_int(os.environ.get("STEP_TIMING_GENERATE_MS"), 0)
    schema_valid = os.environ.get("SCHEMA_VALID", "unknown")

    tracker_summary = get_tracker_summary()

    output_sizes = {rel: get_file_size_kb(rel) for rel in AI_OUTPUTS}

    # Determine health status
    health = "ok"
    if not (REPO_ROOT / "api" / "ai" / "tracker.json").exists():
        health = "error"
    elif schema_valid not in ("true", "1", "ok", "unknown"):
        health = "warn"

    telemetry = {
        "schema": "sentinel-apex-ai-telemetry-v1",
        "run_id": run_id,
        "run_number": run_number,
        "pipeline_version": pipeline_version,
        "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_seconds": duration_seconds,
        "dry_run": dry_run,
        "step_timing_ms": {
            "deps_install": step_deps_ms,
            "ai_generation": step_gen_ms,
        },
        "output_sizes_kb": output_sizes,
        "feed_summary": tracker_summary,
        "health": health,
    }

    try:
        tmp = TELEMETRY_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(telemetry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        tmp.replace(TELEMETRY_FILE)
        log.info("[OK] Telemetry artifact written: %s", TELEMETRY_FILE.relative_to(REPO_ROOT))
        log.info("     Run #%d | Duration: %ds | Health: %s | GRI: %s | Items: %s",
                 run_number, duration_seconds, health,
                 tracker_summary.get("gri_score", "N/A"),
                 tracker_summary.get("feed_items", 0))
    except Exception as exc:
        log.error("Failed to write telemetry artifact: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
