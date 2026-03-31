#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  CYBERDUDEBIVASH SENTINEL APEX — AI + DETECTION WRAPPER v1.0               ║
# ║  Orchestrates: AI Decision Engine + Detection Rule Forge                   ║
# ║  Called by: .github/workflows/sentinel-blogger.yml (Stage 6c)             ║
# ║  Zero-failure design: all errors caught, pipeline never blocked            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

import sys
import os
import time
import json
import traceback
import subprocess
import importlib.util
from pathlib import Path
from datetime import datetime, timezone

# ── Ensure workspace root is in sys.path ────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
AI_OUTPUT_DIR = REPO_ROOT / "data" / "ai_intelligence"
DETECTION_DIR = REPO_ROOT / "data" / "intelligence" / "detection_rules"
WRAPPER_LOG   = REPO_ROOT / "data" / "ai_intelligence" / "wrapper_run_log.json"

# ────────────────────────────────────────────────────────────────────────────
# UTILITY
# ────────────────────────────────────────────────────────────────────────────

def ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def banner(text: str):
    bar = "═" * 60
    print(f"\n╔{bar}╗")
    print(f"║  {text:<58}║")
    print(f"╚{bar}╝")

def section(text: str):
    print(f"\n── {text} {'─' * max(0, 55 - len(text))}")

def check_manifest() -> bool:
    """Verify manifest exists and has entries."""
    if not MANIFEST_PATH.exists():
        print(f"  ✗ Manifest not found: {MANIFEST_PATH}")
        return False
    try:
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            data = json.load(f)
        items = data if isinstance(data, list) else data.get("items", [])
        count = len(items)
        if count == 0:
            print("  ✗ Manifest is empty — no entries to process")
            return False
        print(f"  ✓ Manifest OK: {count} entries")
        return True
    except Exception as e:
        print(f"  ✗ Manifest parse error: {e}")
        return False

def ensure_dirs():
    """Create all required output directories."""
    dirs = [
        AI_OUTPUT_DIR,
        DETECTION_DIR / "sigma",
        DETECTION_DIR / "yara",
        DETECTION_DIR / "suricata",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    print(f"  ✓ Output directories ready")

# ────────────────────────────────────────────────────────────────────────────
# ENGINE RUNNERS
# ────────────────────────────────────────────────────────────────────────────

def run_ai_engine() -> dict:
    """
    Run SentinelAIEngine from agent/sentinel_ai_engine.py.
    Returns telemetry dict regardless of success/failure.
    """
    section("AI DECISION ENGINE")
    result = {
        "engine": "SentinelAIEngine",
        "status": "not_run",
        "started_at": ts(),
        "finished_at": None,
        "duration_s": None,
        "advisories_processed": 0,
        "errors": [],
    }
    t0 = time.time()

    try:
        ai_module_path = REPO_ROOT / "agent" / "sentinel_ai_engine.py"
        if not ai_module_path.exists():
            raise FileNotFoundError(f"sentinel_ai_engine.py not found at {ai_module_path}")

        spec = importlib.util.spec_from_file_location("sentinel_ai_engine", ai_module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        engine = module.SentinelAIEngine()
        run_result = engine.run()

        result["status"] = "success"
        result["advisories_processed"] = run_result.get("processed", 0)
        result["summary"] = {
            "critical": run_result.get("critical", 0),
            "high": run_result.get("high", 0),
            "imminent_exploits": run_result.get("imminent", 0),
            "actors_attributed": run_result.get("actors_attributed", 0),
            "campaigns_detected": run_result.get("campaigns_detected", 0),
        }
        print(f"  ✓ AI Engine complete: {result['advisories_processed']} advisories processed")
        if result.get("summary"):
            s = result["summary"]
            print(f"    Critical: {s['critical']} | High: {s['high']} | "
                  f"Imminent Exploits: {s['imminent_exploits']}")
            print(f"    Actors Attributed: {s['actors_attributed']} | "
                  f"Campaigns Detected: {s['campaigns_detected']}")

    except FileNotFoundError as e:
        result["status"] = "skipped"
        result["errors"].append(str(e))
        print(f"  ⚠ AI Engine skipped: {e}")

    except Exception as e:
        result["status"] = "failed"
        result["errors"].append(str(e))
        result["traceback"] = traceback.format_exc()
        print(f"  ✗ AI Engine failed (non-fatal): {e}")
        print(f"    (Pipeline continues — zero failure architecture)")

    finally:
        elapsed = time.time() - t0
        result["finished_at"] = ts()
        result["duration_s"] = round(elapsed, 2)
        print(f"  ⏱ AI Engine duration: {elapsed:.2f}s")

    return result


def run_detection_forge() -> dict:
    """
    Run DetectionForge from agent/detection_forge.py.
    Returns telemetry dict regardless of success/failure.
    """
    section("DETECTION RULE FORGE")
    result = {
        "engine": "DetectionForge",
        "status": "not_run",
        "started_at": ts(),
        "finished_at": None,
        "duration_s": None,
        "rules_generated": 0,
        "errors": [],
    }
    t0 = time.time()

    try:
        forge_module_path = REPO_ROOT / "agent" / "detection_forge.py"
        if not forge_module_path.exists():
            raise FileNotFoundError(f"detection_forge.py not found at {forge_module_path}")

        spec = importlib.util.spec_from_file_location("detection_forge", forge_module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        forge = module.DetectionForge()
        forge_result = forge.run()

        result["status"] = "success"
        result["rules_generated"] = forge_result.get("total_rules", 0)
        result["breakdown"] = {
            "sigma": forge_result.get("sigma_rules", 0),
            "yara":  forge_result.get("yara_rules", 0),
            "suricata": forge_result.get("suricata_rules", 0),
        }
        print(f"  ✓ Detection Forge complete: {result['rules_generated']} rules generated")
        if result.get("breakdown"):
            b = result["breakdown"]
            print(f"    Sigma: {b['sigma']} | YARA: {b['yara']} | Suricata: {b['suricata']}")

    except FileNotFoundError as e:
        result["status"] = "skipped"
        result["errors"].append(str(e))
        print(f"  ⚠ Detection Forge skipped: {e}")

    except Exception as e:
        result["status"] = "failed"
        result["errors"].append(str(e))
        result["traceback"] = traceback.format_exc()
        print(f"  ✗ Detection Forge failed (non-fatal): {e}")
        print(f"    (Pipeline continues — zero failure architecture)")

    finally:
        elapsed = time.time() - t0
        result["finished_at"] = ts()
        result["duration_s"] = round(elapsed, 2)
        print(f"  ⏱ Detection Forge duration: {elapsed:.2f}s")

    return result


# ────────────────────────────────────────────────────────────────────────────
# POST-RUN: Stitch AI data into enriched manifest (for frontend consumption)
# ────────────────────────────────────────────────────────────────────────────

def stitch_ai_into_manifest() -> dict:
    """
    After AI engine runs, merge ai_index.json entries back into the main
    feed_manifest.json so the dashboard can render live AI data.
    Zero-failure: if anything goes wrong, manifest is left intact.
    """
    section("MANIFEST STITCH (AI → feed_manifest.json)")
    result = {"status": "skipped", "stitched": 0, "errors": []}

    ai_index_path = AI_OUTPUT_DIR / "ai_index.json"
    if not ai_index_path.exists():
        print(f"  ⚠ ai_index.json not found — skipping stitch")
        return result

    try:
        with open(ai_index_path, encoding="utf-8") as f:
            ai_index = json.load(f)

        # Build lookup: advisory_id → ai summary record
        ai_lookup = {}
        for rec in ai_index:
            aid = rec.get("advisory_id", "")
            if aid:
                ai_lookup[aid] = rec

        with open(MANIFEST_PATH, encoding="utf-8") as f:
            manifest = json.load(f)

        items = manifest if isinstance(manifest, list) else manifest.get("items", [])
        stitched = 0
        for item in items:
            aid = item.get("advisory_id", item.get("id", ""))
            if aid and aid in ai_lookup:
                ai_rec = ai_lookup[aid]
                # Embed key AI fields directly into manifest entry
                item["ai_risk_score"]   = ai_rec.get("ai_risk_score", item.get("risk_score", 0))
                item["ai_priority"]     = ai_rec.get("priority", "MEDIUM")
                item["ai_confidence"]   = ai_rec.get("ai_confidence", 0.5)
                item["primary_actor"]   = ai_rec.get("primary_actor")
                item["exploit_tier"]    = ai_rec.get("exploit_tier")
                item["tte_days"]        = ai_rec.get("tte_days")
                item["campaign_id"]     = ai_rec.get("campaign_id")
                item["attack_chain"]    = ai_rec.get("kill_chain_narrative")
                item["exec_summary"]    = ai_rec.get("executive_summary")
                item["nist_functions"]  = ai_rec.get("nist_functions", [])
                item["ai_enriched"]     = True
                stitched += 1

        with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump(manifest, f, separators=(",", ":"))

        result["status"] = "success"
        result["stitched"] = stitched
        print(f"  ✓ Stitched AI data into {stitched} manifest entries")

    except Exception as e:
        result["status"] = "failed"
        result["errors"].append(str(e))
        print(f"  ✗ Manifest stitch failed (non-fatal): {e}")

    return result


# ────────────────────────────────────────────────────────────────────────────
# MAIN
# ────────────────────────────────────────────────────────────────────────────

def main():
    banner("SENTINEL APEX — AI + DETECTION WRAPPER v1.0")
    print(f"  Started : {ts()}")
    print(f"  Repo    : {REPO_ROOT}")

    run_log = {
        "wrapper_version": "1.0",
        "started_at": ts(),
        "finished_at": None,
        "manifest_ok": False,
        "ai_engine": {},
        "detection_forge": {},
        "manifest_stitch": {},
        "overall_status": "pending",
    }

    # ── Pre-flight ────────────────────────────────────────────────────────
    section("PRE-FLIGHT CHECKS")
    ensure_dirs()
    manifest_ok = check_manifest()
    run_log["manifest_ok"] = manifest_ok

    if not manifest_ok:
        print("\n  ⚠ No manifest available — AI+Detection engines require feed_manifest.json")
        print("  ⚠ Ensure Stage 1 (sentinel_blogger.py) ran successfully before this stage")
        # Non-fatal: we write the log and exit 0 to not block the pipeline
        run_log["overall_status"] = "skipped_no_manifest"
        run_log["finished_at"] = ts()
        AI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with open(WRAPPER_LOG, "w") as f:
            json.dump(run_log, f, indent=2)
        print("\n  Pipeline continues (zero failure architecture)")
        sys.exit(0)

    # ── Run engines ───────────────────────────────────────────────────────
    ai_result       = run_ai_engine()
    detection_result = run_detection_forge()

    # ── Stitch AI into manifest (only if AI succeeded) ────────────────────
    stitch_result = {}
    if ai_result["status"] == "success":
        stitch_result = stitch_ai_into_manifest()
    else:
        section("MANIFEST STITCH")
        print("  ⚠ Skipped — AI engine did not produce output")

    run_log["ai_engine"]        = ai_result
    run_log["detection_forge"]  = detection_result
    run_log["manifest_stitch"]  = stitch_result

    # ── Summary ───────────────────────────────────────────────────────────
    banner("WRAPPER RUN SUMMARY")
    statuses = [ai_result["status"], detection_result["status"]]
    if all(s == "success" for s in statuses):
        run_log["overall_status"] = "success"
        status_icon = "✓"
    elif all(s in ("skipped", "not_run") for s in statuses):
        run_log["overall_status"] = "skipped"
        status_icon = "⚠"
    else:
        # Partial success or failures — still non-fatal
        run_log["overall_status"] = "partial"
        status_icon = "⚠"

    run_log["finished_at"] = ts()

    print(f"  {status_icon} Overall status    : {run_log['overall_status'].upper()}")
    print(f"  AI Engine          : {ai_result['status'].upper()} "
          f"({ai_result.get('advisories_processed', 0)} advisories, "
          f"{ai_result.get('duration_s', 0)}s)")
    print(f"  Detection Forge    : {detection_result['status'].upper()} "
          f"({detection_result.get('rules_generated', 0)} rules, "
          f"{detection_result.get('duration_s', 0)}s)")
    if stitch_result:
        print(f"  Manifest Stitch    : {stitch_result.get('status', 'skipped').upper()} "
              f"({stitch_result.get('stitched', 0)} entries)")

    # ── Write run log ─────────────────────────────────────────────────────
    try:
        with open(WRAPPER_LOG, "w") as f:
            json.dump(run_log, f, indent=2, default=str)
        print(f"\n  ✓ Run log saved: {WRAPPER_LOG}")
    except Exception as e:
        print(f"  ⚠ Could not write run log: {e}")

    print(f"\n  Finished: {ts()}")
    print("  Pipeline continues →\n")

    # ── Always exit 0 — zero failure architecture ─────────────────────────
    sys.exit(0)


if __name__ == "__main__":
    main()
