#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/stage_3_1_11_detection_engineering_core.py — Pipeline Stage 3.1.11
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PIPELINE POSITION: After STAGE 3.1.10 (MITRE ATT&CK Actor Attribution)
CALLED BY        : .github/workflows/generate-and-sync.yml
PURPOSE          : Run the full Detection Engineering Core pipeline on
                   all advisories in the current feed manifest.

OUTPUT FILES:
  api/detections/detection-index.json        — Detection index API endpoint
  api/detections/{advisory_id}.json          — Per-advisory detection payload
  api/detections/{advisory_id}_full.json     — Enterprise full payload
  api/detections/apex-sentinel-arm-template.json
  api/detections/apex-splunk-content-bundle.json
  api/detections/apex-sigma-rules.zip
  api/detections/apex-yara-rules.yar
  api/detections/apex-suricata.rules
  api/detections/apex-package-manifest.json
  data/audit/detection_drift_report.json
  data/audit/detection_drift_state.json
================================================================================
"""
import sys, os, json, time, logging
from pathlib import Path
from datetime import datetime, timezone

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("apex.stage_3_1_11")

MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
API_FEED_PATH = REPO_ROOT / "api" / "feed.json"
OUTPUT_DIR    = REPO_ROOT / "api" / "detections"
STAGE_VERSION = "162.0.0"


def ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_advisories() -> list:
    """Load advisories from feed.json or feed_manifest.json."""
    # Try api/feed.json first (most current)
    for path in [API_FEED_PATH, MANIFEST_PATH]:
        if path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                items = data if isinstance(data, list) else data.get("items", [])
                if items:
                    log.info(f"[S3.1.11] Loaded {len(items)} advisories from {path.name}")
                    return items
            except Exception as e:
                log.warning(f"[S3.1.11] Could not load {path}: {e}")
    return []


def run_stage():
    """Execute Stage 3.1.11 — Detection Engineering Core."""
    print("=" * 70)
    print(f"  STAGE 3.1.11 — Detection Engineering Core v{STAGE_VERSION}")
    print(f"  CYBERDUDEBIVASH® SENTINEL APEX")
    print(f"  Started: {ts()}")
    print("=" * 70)

    start_ts = time.time()
    stage_result = {
        "stage": "3.1.11",
        "version": STAGE_VERSION,
        "started_at": ts(),
        "status": "PENDING",
        "advisories_processed": 0,
        "detections_generated": 0,
        "production_ready_count": 0,
        "average_quality_score": 0.0,
        "platforms_covered": [],
        "output_files": [],
        "errors": []
    }

    # Pre-flight
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (REPO_ROOT / "data" / "audit").mkdir(parents=True, exist_ok=True)

    advisories = load_advisories()
    if not advisories:
        print("  [SKIP] No advisories found — detection engineering skipped")
        stage_result["status"] = "SKIP"
        stage_result["reason"] = "No advisories in manifest"
        _write_stage_result(stage_result)
        sys.exit(0)

    # Import orchestrator
    try:
        from scripts.detection_engineering_orchestrator import DetectionEngineeringOrchestrator
        orchestrator = DetectionEngineeringOrchestrator(
            repo_root=str(REPO_ROOT),
            output_dir=str(OUTPUT_DIR)
        )
    except ImportError as e:
        print(f"  [FAIL] Cannot import DetectionEngineeringOrchestrator: {e}")
        stage_result["status"] = "FAIL"
        stage_result["errors"].append(str(e))
        _write_stage_result(stage_result)
        sys.exit(0)  # Non-fatal — pipeline continues

    # Process in batches of 20 to manage memory
    BATCH_SIZE = 20
    all_batch_results = []
    total_ready = 0
    all_scores = []
    all_platforms = set()

    for i in range(0, len(advisories), BATCH_SIZE):
        batch = advisories[i:i+BATCH_SIZE]
        batch_num = i//BATCH_SIZE + 1
        print(f"\n  [BATCH {batch_num}] Processing {len(batch)} advisories...")

        try:
            batch_result = orchestrator.process_batch(
                batch,
                run_id=f"s3-1-11-batch-{batch_num}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
            )
            all_batch_results.append(batch_result)

            # Aggregate stats
            stats = batch_result.get("stats",{})
            total_ready += stats.get("pass",0)

            # From detection index
            det_index = batch_result.get("detection_index",{})
            if det_index.get("average_quality_score",0) > 0:
                all_scores.append(det_index["average_quality_score"])
            all_platforms.update(det_index.get("platforms_available",[]))

            print(f"  [BATCH {batch_num}] PASS={stats.get('pass',0)} "
                  f"WARN={stats.get('warn',0)} FAIL={stats.get('fail',0)}")

        except Exception as e:
            log.error(f"[S3.1.11] Batch {batch_num} failed: {e}")
            stage_result["errors"].append(f"Batch {batch_num}: {e}")

    # Final stats
    avg_score = round(sum(all_scores)/len(all_scores) if all_scores else 0, 2)
    elapsed   = round(time.time()-start_ts, 2)

    # List output files
    output_files = []
    for f in OUTPUT_DIR.glob("*.json"):
        output_files.append(str(f.relative_to(REPO_ROOT)))
    for f in OUTPUT_DIR.glob("*.zip"):
        output_files.append(str(f.relative_to(REPO_ROOT)))
    for f in OUTPUT_DIR.glob("*.yar"):
        output_files.append(str(f.relative_to(REPO_ROOT)))
    for f in OUTPUT_DIR.glob("*.rules"):
        output_files.append(str(f.relative_to(REPO_ROOT)))

    stage_result.update({
        "status": "PASS" if not stage_result["errors"] else "WARN",
        "finished_at": ts(),
        "elapsed_seconds": elapsed,
        "advisories_processed": len(advisories),
        "production_ready_count": total_ready,
        "average_quality_score": avg_score,
        "platforms_covered": list(all_platforms),
        "output_files": output_files[:20],
    })

    print(f"\n{'='*70}")
    print(f"  STAGE 3.1.11 COMPLETE")
    print(f"  Status         : {stage_result['status']}")
    print(f"  Advisories     : {len(advisories)}")
    print(f"  Prod-Ready     : {total_ready}")
    print(f"  Avg Quality    : {avg_score}/100")
    print(f"  Platforms      : {len(all_platforms)} SIEM targets")
    print(f"  Output Files   : {len(output_files)}")
    print(f"  Elapsed        : {elapsed}s")
    print(f"  Output Dir     : {OUTPUT_DIR}")
    print(f"{'='*70}")

    _write_stage_result(stage_result)
    # Always exit 0 — non-fatal stage
    sys.exit(0)


def _write_stage_result(result:dict):
    """Write stage audit result."""
    path = REPO_ROOT / "data" / "audit" / "stage_3_1_11_detection_engineering.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\n  Stage result written: {path}")


if __name__ == "__main__":
    run_stage()
