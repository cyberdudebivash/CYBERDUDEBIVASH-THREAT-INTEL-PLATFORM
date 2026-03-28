"""
CYBERDUDEBIVASH® SENTINEL APEX
APEX OUTPUT INJECTOR v1.0 — Safe Non-Destructive Enrichment Layer
==================================================================
MANDATE:
  - NEVER overwrite existing fields
  - ONLY add new "apex": {...} sub-object
  - All errors return original data UNCHANGED
  - Reads enrichment cache — NEVER writes to manifest
  - Zero-import cost when APEX disabled

ENRICHMENT FIELDS ADDED (under "apex" key):
  {
    "apex": {
      "priority":           "P1" | "P2" | "P3" | "P4",
      "priority_score":     9.2,
      "sla":                "15 minutes",
      "threat_level":       "CRITICAL_SURGE",
      "prediction":         "Ransomware Campaign (78%)",
      "malware_family":     "RANSOMWARE",
      "patch_priority":     "P1_IMMEDIATE",
      "supply_chain_risk":  true | false,
      "social_eng_risk":    true | false,
      "quantum_risk":       true | false,
      "recommended_action": "PATCH NOW — P1 KEV-confirmed exploit",
      "agent_analysis":     "...",
      "hunt_queries":       [...],
      "mitre_techniques":   [...],
      "enriched_at":        "ISO timestamp",
      "engine_version":     "1.0"
    }
  }
"""
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-APEX-INJECTOR")

# ── Config ────────────────────────────────────────────────────────────────────
APEX_ENABLED      = os.environ.get("CDB_APEX_ENABLED", "false").lower() in ("true","1","yes")
ENRICHMENT_DIR    = os.environ.get("CDB_ENRICHMENT_DIR", "data/apex_enrichments")
RUN_LOG_PATH      = os.path.join(ENRICHMENT_DIR, "apex_run_log.json")
CACHE_TTL_SECONDS = int(os.environ.get("CDB_APEX_CACHE_TTL", "3600"))  # 1 hour default

# ── In-memory cache ────────────────────────────────────────────────────────────
_enrichment_cache: Dict[str, Dict] = {}     # stix_id → apex enrichment dict
_cache_loaded_at: float = 0.0
_last_run_summary: Dict = {}


def _load_run_log() -> Dict:
    """Load last APEX run summary from disk. Returns empty dict on failure."""
    try:
        if not os.path.exists(RUN_LOG_PATH):
            return {}
        with open(RUN_LOG_PATH, encoding="utf-8") as f:
            runs = json.load(f)
        return runs[-1] if runs else {}
    except Exception:
        return {}


def _build_enrichment_index(advisories: List[Dict]) -> Dict[str, Dict]:
    """
    Build per-advisory APEX enrichment by running engines on demand.
    Called once per cache TTL. Returns stix_id → apex_data mapping.
    """
    index: Dict[str, Dict] = {}
    try:
        from agent.apex_engine import ApexIntelligenceEngine
        engine = ApexIntelligenceEngine()
        engine._lazy_init()

        # Pre-seed predictive + behavioral
        engine._predictive.ingest_advisories(advisories[:100])
        for adv in advisories[:50]:
            engine._behavioral.feed(adv)

        # Get platform-level predictions once
        predictions = {}
        try:
            predictions = engine._predictive.get_attack_predictions()
        except Exception:
            pass

        threat_level = predictions.get("overall_threat_level", "UNKNOWN")

        # Score all advisories
        scored = []
        try:
            scored = engine._scoring.score_batch(advisories[:200])
            scored_index = {s.get("advisory_id",""): s for s in scored}
        except Exception:
            scored_index = {}

        # Per-advisory enrichment (lightweight — triage + scoring only)
        for adv in advisories[:200]:
            stix_id = adv.get("stix_id", "")
            if not stix_id:
                continue
            try:
                apex = _enrich_single(adv, engine, scored_index.get(stix_id, {}),
                                      threat_level, predictions)
                index[stix_id] = apex
            except Exception as e:
                logger.debug(f"[INJECTOR] Enrich skip {stix_id[:20]}: {e}")
                continue

        logger.info(f"[INJECTOR] Enrichment index built: {len(index)} advisories")
    except Exception as e:
        logger.warning(f"[INJECTOR] Index build failed (non-critical): {e}")
    return index


def _enrich_single(adv: Dict, engine, scored: Dict,
                   threat_level: str, predictions: Dict) -> Dict:
    """Build the apex enrichment dict for one advisory. Never raises."""
    title   = str(adv.get("title") or "")
    stix_id = str(adv.get("stix_id") or "")

    # SOC triage
    priority      = "P4"
    priority_score = 0.0
    sla           = "24 hours"
    try:
        triage = engine._soc.tier1.triage(adv)
        priority       = triage.get("priority", "P4")
        priority_score = triage.get("priority_score", 0.0)
        sla            = triage.get("sla", "24 hours")
    except Exception:
        pass

    # Composite risk score
    composite_score = float(scored.get("composite_score", 0.0))

    # Malware family
    malware_family = "UNKNOWN"
    try:
        text = f"{title} {str(adv.get('summary',''))}"
        ml = engine._orchestrator.malware_analyst.classify_malware(text)
        malware_family = ml.get("primary_family", "UNKNOWN")
    except Exception:
        pass

    # Patch priority
    patch_priority = "P5_LOW"
    try:
        pg = engine._orchestrator.vuln_analyst.compute_exploitability_score(adv)
        pp = engine._orchestrator.vuln_analyst.determine_patch_priority(
            pg.get("exploitability_score", 0))
        patch_priority = pp.get("priority", "P5_LOW")
    except Exception:
        pass

    # Supply chain risk
    supply_chain_risk = False
    try:
        sc = engine._supply_chain.scan_advisory_for_supply_chain(adv)
        supply_chain_risk = sc.get("is_supply_chain_threat", False)
    except Exception:
        pass

    # Social eng risk
    social_eng_risk = False
    try:
        se = engine._social_eng.analyze_advisory(adv)
        social_eng_risk = se.get("is_social_eng", False)
    except Exception:
        pass

    # Quantum risk
    quantum_risk = False
    try:
        qr = engine._quantum.assess_advisory(adv)
        quantum_risk = qr.get("is_crypto_relevant", False)
    except Exception:
        pass

    # Build recommended action
    recommended_action = _build_recommended_action(priority, patch_priority,
                                                    composite_score, supply_chain_risk)

    # Build agent analysis summary
    agent_analysis = _build_agent_analysis(priority, malware_family, composite_score,
                                            supply_chain_risk, social_eng_risk, quantum_risk)

    # Top attack prediction
    top_prediction = "NORMAL"
    try:
        preds = predictions.get("attack_predictions", [])
        if preds:
            top = preds[0]
            prob_pct = int(top.get("probability", 0) * 100)
            top_prediction = f"{top.get('attack_type','?')} ({prob_pct}%)"
    except Exception:
        pass

    return {
        "priority":           priority,
        "priority_score":     round(priority_score, 2),
        "sla":                sla,
        "composite_score":    round(composite_score, 2),
        "threat_level":       threat_level,
        "prediction":         top_prediction,
        "malware_family":     malware_family,
        "patch_priority":     patch_priority,
        "supply_chain_risk":  supply_chain_risk,
        "social_eng_risk":    social_eng_risk,
        "quantum_risk":       quantum_risk,
        "recommended_action": recommended_action,
        "agent_analysis":     agent_analysis,
        "enriched_at":        datetime.now(timezone.utc).isoformat(),
        "engine_version":     "1.0",
    }


def _build_recommended_action(priority: str, patch_priority: str,
                               score: float, supply_chain: bool) -> str:
    """Generate a human-readable recommended action string."""
    if priority == "P1" or patch_priority == "P1_IMMEDIATE":
        return "PATCH NOW — P1 critical, SLA 15 minutes, KEV-confirmed or active exploit"
    if priority == "P2" or patch_priority == "P2_URGENT":
        return "PATCH URGENT — P2 high severity, apply within 72 hours"
    if supply_chain:
        return "SUPPLY CHAIN ALERT — Audit dependencies, update lockfiles immediately"
    if patch_priority in ("P3_HIGH",):
        return "PATCH REQUIRED — Apply within 7 days, monitor for exploitation"
    if score >= 5.0:
        return "MONITOR & SCHEDULE — Add to patch cycle, review within 30 days"
    return "LOG & TRACK — Low risk, schedule for next maintenance window"


def _build_agent_analysis(priority: str, malware_family: str, score: float,
                           supply_chain: bool, social_eng: bool, quantum: bool) -> str:
    """Build a concise agent analysis narrative."""
    parts = []
    if priority in ("P1", "P2"):
        parts.append(f"APEX SOC classified as {priority} — immediate response required")
    if malware_family not in ("UNKNOWN", ""):
        parts.append(f"Malware family: {malware_family}")
    if supply_chain:
        parts.append("Supply chain threat detected — dependency audit required")
    if social_eng:
        parts.append("Social engineering indicators present — user awareness alert recommended")
    if quantum:
        parts.append("Quantum-vulnerable cryptography referenced — PQC review advised")
    if not parts:
        parts.append(f"Risk score {score:.1f}/10 — standard monitoring recommended")
    return ". ".join(parts) + "."


# ── Public API ─────────────────────────────────────────────────────────────────

def get_enrichment_cache(advisories: Optional[List[Dict]] = None) -> Dict[str, Dict]:
    """
    Return the enrichment cache, loading from disk or rebuilding if stale.
    Priority: 1) In-memory cache  2) apex_index.json on disk  3) Recompute
    """
    global _enrichment_cache, _cache_loaded_at, _last_run_summary

    if not APEX_ENABLED:
        return {}

    now = time.time()
    if (now - _cache_loaded_at) < CACHE_TTL_SECONDS and _enrichment_cache:
        return _enrichment_cache

    # Try loading from disk cache written by apex_wrapper
    index_path = os.path.join(ENRICHMENT_DIR, "apex_index.json")
    if os.path.exists(index_path):
        try:
            mtime = os.path.getmtime(index_path)
            if (now - mtime) < CACHE_TTL_SECONDS:
                with open(index_path, encoding="utf-8") as f:
                    _enrichment_cache = json.load(f)
                _cache_loaded_at = now
                _last_run_summary = _load_run_log()
                logger.info(f"[INJECTOR] Loaded disk cache: {len(_enrichment_cache)} entries")
                return _enrichment_cache
        except Exception as e:
            logger.debug(f"[INJECTOR] Disk cache load failed: {e}")

    # Recompute if no valid disk cache and advisories provided
    if advisories:
        _enrichment_cache = _build_enrichment_index(advisories)
    _cache_loaded_at = now
    _last_run_summary = _load_run_log()
    return _enrichment_cache


def inject_apex(item: Dict, cache: Optional[Dict] = None) -> Dict:
    """
    SAFE INJECTION: Returns a copy of item with "apex" field added.
    NEVER modifies item in-place. NEVER overwrites existing fields.
    Returns original item unchanged on any error.
    """
    if not APEX_ENABLED:
        return item

    try:
        stix_id = item.get("stix_id", "")
        if not stix_id or "apex" in item:
            # Already has apex OR no stix_id to look up → return unchanged
            return item

        apex_data = (cache or {}).get(stix_id)
        if not apex_data:
            return item

        # Return a new dict — NEVER mutate original
        return {**item, "apex": apex_data}

    except Exception as e:
        logger.debug(f"[INJECTOR] inject_apex failed (non-critical): {e}")
        return item  # Always return original on failure


def inject_apex_batch(items: List[Dict], cache: Optional[Dict] = None) -> List[Dict]:
    """Inject apex enrichment into a list of advisories."""
    if not APEX_ENABLED or not cache:
        return items
    return [inject_apex(item, cache) for item in items]


def get_apex_summary() -> Dict:
    """Return APEX enrichment summary for /health and /stats endpoints."""
    if not APEX_ENABLED:
        return {"apex_enabled": False}
    run_log = _load_run_log()
    return {
        "apex_enabled":     True,
        "last_run_status":  run_log.get("status", "UNKNOWN"),
        "last_run_at":      run_log.get("run_at", ""),
        "engines_ok":       run_log.get("ok_count", 0),
        "engines_total":    12,
        "enriched_count":   len(_enrichment_cache),
        "cache_age_s":      round(time.time() - _cache_loaded_at, 0),
        "engine_version":   "1.0",
    }
