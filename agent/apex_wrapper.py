"""
CYBERDUDEBIVASH® SENTINEL APEX
APEX SAFE WRAPPER v1.0 — Production Merge Layer
================================================
MANDATORY RULES:
  - NEVER called directly; always invoked via feature flag
  - ALL failures are silently swallowed — pipeline MUST continue
  - sentinel_blogger.py is NEVER modified
  - CDB_APEX_ENABLED=false disables this entirely
  - Reads manifest data written by primary pipeline
  - Writes APEX enrichments to data/apex_enrichments/

EXECUTION FLOW:
  sentinel_blogger.py (primary, unchanged)
      └── apex_wrapper.py (optional, post-processing only)
              └── try: run all 12 engines on new advisories
              └── except: log + skip, pipeline unaffected
"""
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [APEX-WRAPPER] %(levelname)s — %(message)s",
)
logger = logging.getLogger("CDB-APEX-WRAPPER")

# ── Feature flag (hard gate) ──────────────────────────────────────────────────
APEX_ENABLED = os.environ.get("CDB_APEX_ENABLED", "false").lower() in ("true", "1", "yes")

# ── Paths (env-overridable, relative for portability) ─────────────────────────
MANIFEST_PATH  = os.environ.get("CDB_MANIFEST_PATH",  "data/stix/feed_manifest.json")
ENRICHMENT_DIR = os.environ.get("CDB_ENRICHMENT_DIR", "data/apex_enrichments")
APEX_LOG_PATH  = os.environ.get("CDB_APEX_LOG_PATH",  "data/apex_enrichments/apex_run_log.json")

# ── Limits (performance safety) ───────────────────────────────────────────────
MAX_ADVISORIES_PER_RUN = int(os.environ.get("CDB_APEX_BATCH_SIZE", "50"))
MAX_ENGINE_TIMEOUT_SEC = int(os.environ.get("CDB_APEX_TIMEOUT", "120"))


def _load_manifest() -> List[Dict]:
    """Load advisory manifest written by sentinel_blogger.py. Read-only."""
    try:
        if not os.path.exists(MANIFEST_PATH):
            logger.warning(f"[APEX-WRAPPER] Manifest not found: {MANIFEST_PATH}")
            return []
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            logger.warning("[APEX-WRAPPER] Manifest is not a list — skipping")
            return []
        logger.info(f"[APEX-WRAPPER] Loaded {len(data)} advisories from manifest")
        return data
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Manifest load failed: {e}")
        return []


def _init_engine():
    """Lazy-import and initialise ApexIntelligenceEngine. Returns None on failure."""
    try:
        from agent.apex_engine import ApexIntelligenceEngine
        engine = ApexIntelligenceEngine()
        engine._lazy_init()
        status = engine.get_engine_status()
        logger.info(f"[APEX-WRAPPER] Engine initialised — {status['engines_online']}/12 online")
        return engine
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Engine init failed: {e}")
        return None


def _save_enrichments(results: List[Dict], manifest: List[Dict]) -> None:
    """Persist APEX enrichment results. Failures here NEVER block the pipeline."""
    try:
        os.makedirs(ENRICHMENT_DIR, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(ENRICHMENT_DIR, f"enrichments_{ts}.json")
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "advisories_processed": len(results),
            "manifest_total": len(manifest),
            "results": results,
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"[APEX-WRAPPER] Enrichments saved → {out_path}")
    except Exception as e:
        logger.warning(f"[APEX-WRAPPER] Enrichment save failed (non-critical): {e}")


def _save_run_log(run_record: Dict) -> None:
    """Append this run's summary to the rolling run log."""
    try:
        os.makedirs(ENRICHMENT_DIR, exist_ok=True)
        log_data = []
        if os.path.exists(APEX_LOG_PATH):
            with open(APEX_LOG_PATH, encoding="utf-8") as f:
                log_data = json.load(f)
        log_data.append(run_record)
        # Keep last 100 runs
        log_data = log_data[-100:]
        with open(APEX_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"[APEX-WRAPPER] Run log save failed (non-critical): {e}")


def run_apex_enrichment() -> Dict:
    """
    Main entry point — called AFTER sentinel_blogger.py completes.
    Returns a summary dict. NEVER raises — all errors are caught internally.

    PHASE 1: Feature flag check
    PHASE 2: Load manifest (read-only)
    PHASE 3: Init engines
    PHASE 4: Run each engine with individual try/except
    PHASE 5: Save enrichments
    PHASE 6: Log run summary
    """
    run_start = time.time()
    run_record: Dict[str, Any] = {
        "run_at":     datetime.now(timezone.utc).isoformat(),
        "enabled":    APEX_ENABLED,
        "status":     "SKIPPED",
        "duration_s": 0,
        "engines":    {},
        "errors":     [],
    }

    # ── PHASE 1: Feature flag ────────────────────────────────────────────────
    if not APEX_ENABLED:
        logger.info("[APEX-WRAPPER] CDB_APEX_ENABLED=false — skipping enrichment (safe)")
        run_record["status"] = "DISABLED"
        _save_run_log(run_record)
        return run_record

    logger.info("[APEX-WRAPPER] ====== APEX ENRICHMENT LAYER STARTING ======")
    logger.info(f"[APEX-WRAPPER] Feature flag: CDB_APEX_ENABLED=true")

    # ── PHASE 2: Load manifest ───────────────────────────────────────────────
    manifest = _load_manifest()
    if not manifest:
        run_record["status"] = "NO_DATA"
        run_record["errors"].append("Empty manifest")
        _save_run_log(run_record)
        return run_record

    # Limit batch size for performance safety
    advisories = manifest[:MAX_ADVISORIES_PER_RUN]
    logger.info(f"[APEX-WRAPPER] Processing {len(advisories)}/{len(manifest)} advisories "
                f"(limit={MAX_ADVISORIES_PER_RUN})")

    # ── PHASE 3: Init engine ─────────────────────────────────────────────────
    engine = _init_engine()
    if engine is None:
        run_record["status"] = "ENGINE_INIT_FAILED"
        run_record["errors"].append("Engine initialisation failed")
        _save_run_log(run_record)
        return run_record

    # Pre-seed engines with historical data
    try:
        engine._predictive.ingest_advisories(advisories)
        for adv in advisories[:30]:
            engine._behavioral.feed(adv)
            engine._copilot.index_advisories([adv])
        logger.info("[APEX-WRAPPER] Engines pre-seeded with historical data")
    except Exception as e:
        logger.warning(f"[APEX-WRAPPER] Pre-seed warning (non-critical): {e}")

    results = []
    engine_statuses: Dict[str, str] = {}

    # ── PHASE 4: Per-engine execution (individual isolation) ─────────────────
    # Each engine is wrapped independently — one failure CANNOT affect others

    # ENGINE 1: SOC Triage
    try:
        soc_results = []
        p1_count = 0
        for adv in advisories[:20]:
            tr = engine._soc.tier1.triage(adv)
            if tr.get("priority") == "P1":
                p1_count += 1
                soc_results.append({"advisory": adv.get("title","")[:60],
                                    "priority": tr.get("priority"),
                                    "score": tr.get("priority_score")})
        logger.info(f"[APEX-WRAPPER] SOC Engine Executed — {p1_count} P1 alerts from {len(advisories[:20])} advisories")
        engine_statuses["SOC"] = f"OK — {p1_count} P1 alerts"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] SOC Engine failed (isolated): {e}")
        engine_statuses["SOC"] = f"FAILED: {e}"
        run_record["errors"].append(f"SOC: {e}")

    # ENGINE 2: Threat Graph
    try:
        nodes_added = 0
        for adv in advisories[:50]:
            r = engine._graph.ingest_advisory(adv)
            nodes_added += r.get("nodes_added", 0)
        summary = engine._graph.get_graph_summary()
        logger.info(f"[APEX-WRAPPER] Threat Graph Executed — {nodes_added} nodes added, "
                    f"total={summary.get('total_nodes',0)}, high_risk={summary.get('high_risk_nodes',0)}")
        engine_statuses["ThreatGraph"] = f"OK — {summary.get('total_nodes',0)} total nodes"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Threat Graph failed (isolated): {e}")
        engine_statuses["ThreatGraph"] = f"FAILED: {e}"
        run_record["errors"].append(f"ThreatGraph: {e}")

    # ENGINE 3: Predictive
    try:
        pred = engine._predictive.get_attack_predictions()
        threat_level = pred.get("overall_threat_level", "UNKNOWN")
        forecast = engine._predictive.predict_next_period(7)
        trend = forecast.get("trend_direction", "UNKNOWN")
        logger.info(f"[APEX-WRAPPER] Predictive Engine Output Generated — "
                    f"threat_level={threat_level} trend={trend}")
        engine_statuses["Predictive"] = f"OK — {threat_level} / {trend}"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Predictive Engine failed (isolated): {e}")
        engine_statuses["Predictive"] = f"FAILED: {e}"
        run_record["errors"].append(f"Predictive: {e}")

    # ENGINE 4: Orchestration
    try:
        orch_result = engine._orchestrator.run(advisories[0]) if advisories else {}
        hunt_priority = orch_result.get("hunt_package", {}).get("priority", "?")
        malware_family = orch_result.get("malware_report", {}).get(
            "malware_classification", {}).get("primary_family", "?")
        logger.info(f"[APEX-WRAPPER] Orchestration Completed — "
                    f"hunt={hunt_priority} malware={malware_family}")
        engine_statuses["Orchestration"] = f"OK — hunt={hunt_priority} malware={malware_family}"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Orchestration failed (isolated): {e}")
        engine_statuses["Orchestration"] = f"FAILED: {e}"
        run_record["errors"].append(f"Orchestration: {e}")

    # ENGINE 5: Red Team
    try:
        rt = engine._redteam.generate_exercise(advisories[0]) if advisories else {}
        logger.info(f"[APEX-WRAPPER] Red Team Exercise Generated — id={rt.get('exercise_id','?')}")
        engine_statuses["RedTeam"] = f"OK — {rt.get('exercise_id','?')}"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Red Team failed (isolated): {e}")
        engine_statuses["RedTeam"] = f"FAILED: {e}"
        run_record["errors"].append(f"RedTeam: {e}")

    # ENGINE 6: Scoring
    try:
        top_risks = engine._scoring.get_top_risks(advisories, 10)
        top_score = top_risks[0]["composite_score"] if top_risks else 0
        logger.info(f"[APEX-WRAPPER] Risk Scoring Executed — "
                    f"top_score={top_score} across {len(advisories)} advisories")
        engine_statuses["Scoring"] = f"OK — top_score={top_score}"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Scoring failed (isolated): {e}")
        engine_statuses["Scoring"] = f"FAILED: {e}"
        run_record["errors"].append(f"Scoring: {e}")

    # ENGINE 7: Zero Trust
    try:
        zt_result = engine._zerotrust.get_engine_status()
        logger.info(f"[APEX-WRAPPER] Zero Trust Engine Active — "
                    f"monitored_users={zt_result.get('monitored_users', 0)}")
        engine_statuses["ZeroTrust"] = f"OK — users={zt_result.get('monitored_users',0)}"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Zero Trust failed (isolated): {e}")
        engine_statuses["ZeroTrust"] = f"FAILED: {e}"
        run_record["errors"].append(f"ZeroTrust: {e}")

    # ENGINE 8: Copilot
    try:
        cop_r = engine._copilot.query("What are the current top threats?")
        logger.info(f"[APEX-WRAPPER] Security Copilot Active — "
                    f"intent={cop_r.get('intent','?')} queries_answered={engine._copilot.query_count}")
        engine_statuses["Copilot"] = f"OK — {engine._copilot.query_count} queries answered"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Copilot failed (isolated): {e}")
        engine_statuses["Copilot"] = f"FAILED: {e}"
        run_record["errors"].append(f"Copilot: {e}")

    # ENGINE 9: Supply Chain
    try:
        sc_threats = 0
        for adv in advisories[:30]:
            r = engine._supply_chain.scan_advisory_for_supply_chain(adv)
            if r.get("is_supply_chain_threat"):
                sc_threats += 1
        logger.info(f"[APEX-WRAPPER] Supply Chain Engine Executed — "
                    f"{sc_threats} threats found in {min(30, len(advisories))} advisories")
        engine_statuses["SupplyChain"] = f"OK — {sc_threats} threats"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Supply Chain failed (isolated): {e}")
        engine_statuses["SupplyChain"] = f"FAILED: {e}"
        run_record["errors"].append(f"SupplyChain: {e}")

    # ENGINE 10: Social Engineering
    try:
        se_detections = 0
        for adv in advisories[:30]:
            r = engine._social_eng.analyze_advisory(adv)
            if r.get("is_social_eng"):
                se_detections += 1
        logger.info(f"[APEX-WRAPPER] Social Eng Detection Executed — "
                    f"{se_detections} detections in {min(30, len(advisories))} advisories")
        engine_statuses["SocialEng"] = f"OK — {se_detections} detections"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Social Eng failed (isolated): {e}")
        engine_statuses["SocialEng"] = f"FAILED: {e}"
        run_record["errors"].append(f"SocialEng: {e}")

    # ENGINE 11: Quantum
    try:
        roadmap = engine._quantum.generate_pqc_roadmap()
        phase_count = len(roadmap.get("migration_phases", []))
        logger.info(f"[APEX-WRAPPER] Quantum Readiness Engine Active — {phase_count} migration phases")
        engine_statuses["Quantum"] = f"OK — {phase_count} phases"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Quantum failed (isolated): {e}")
        engine_statuses["Quantum"] = f"FAILED: {e}"
        run_record["errors"].append(f"Quantum: {e}")

    # ENGINE 12: Marketplace
    try:
        rev = engine._marketplace.get_revenue_summary()
        mrr = rev.get("mrr", 0)
        subs = rev.get("active_subscriptions", 0)
        logger.info(f"[APEX-WRAPPER] Marketplace Revenue Updated — MRR=${mrr} subs={subs}")
        engine_statuses["Marketplace"] = f"OK — MRR=${mrr} subs={subs}"
    except Exception as e:
        logger.error(f"[APEX-WRAPPER] Marketplace failed (isolated): {e}")
        engine_statuses["Marketplace"] = f"FAILED: {e}"
        run_record["errors"].append(f"Marketplace: {e}")

    # ── PHASE 5: Save enrichments + per-advisory index ──────────────────────
    _save_enrichments(results, manifest)

    # Build and save per-advisory APEX index for injector consumption
    try:
        from agent.apex_injector import _build_enrichment_index
        apex_index = _build_enrichment_index(advisories)
        if apex_index:
            index_path = os.path.join(ENRICHMENT_DIR, "apex_index.json")
            with open(index_path, "w", encoding="utf-8") as _f:
                json.dump(apex_index, _f, indent=2, default=str)
            logger.info(f"[APEX-WRAPPER] Advisory index saved: {len(apex_index)} entries → {index_path}")
    except Exception as _e:
        logger.warning(f"[APEX-WRAPPER] Index save failed (non-critical): {_e}")

    # ── PHASE 6: Log run summary ─────────────────────────────────────────────
    elapsed = round(time.time() - run_start, 2)
    ok_engines  = sum(1 for v in engine_statuses.values() if v.startswith("OK"))
    fail_engines = len(engine_statuses) - ok_engines

    run_record.update({
        "status":      "COMPLETED" if fail_engines == 0 else "PARTIAL",
        "duration_s":  elapsed,
        "engines":     engine_statuses,
        "ok_count":    ok_engines,
        "fail_count":  fail_engines,
        "advisories":  len(advisories),
    })
    _save_run_log(run_record)

    logger.info(f"[APEX-WRAPPER] ====== APEX ENRICHMENT COMPLETE ======")
    logger.info(f"[APEX-WRAPPER] Engines: {ok_engines}/12 OK | {fail_engines} failed | "
                f"duration={elapsed}s | advisories={len(advisories)}")
    return run_record


# ── CLI entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    result = run_apex_enrichment()
    print(json.dumps(result, indent=2, default=str))
    sys.exit(0 if result.get("status") in ("COMPLETED", "DISABLED", "SKIPPED", "NO_DATA") else 1)
