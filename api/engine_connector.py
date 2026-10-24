"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — ENGINE CONNECTOR v1.0                   ║
║  Safe reader for all 9 engine output directories                          ║
║  TTL caching · Atomic reads · Graceful fallback on missing data           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import json
import time
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-ENGINE-CONNECTOR")

# ── Base paths ────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"

# ── Engine output file registry ───────────────────────────────────────────────
ENGINE_FILES = {
    # Agentic AI
    "agentic_predictions":    DATA_DIR / "agentic_intel" / "predictions.json",
    "agentic_signals":        DATA_DIR / "agentic_intel" / "agent_signals.json",
    "agentic_supply_chain":   DATA_DIR / "agentic_intel" / "supply_chain_risks.json",
    "agentic_meta":           DATA_DIR / "agentic_intel" / "engine_meta.json",
    # Identity Intel
    "identity_index":         DATA_DIR / "identity_intel" / "identity_risk_index.json",
    "identity_signals":       DATA_DIR / "identity_intel" / "leaked_credential_signals.json",
    "identity_remediation":   DATA_DIR / "identity_intel" / "remediation_actions.json",
    "identity_meta":          DATA_DIR / "identity_intel" / "engine_meta.json",
    # Dark Web
    "darkweb_actors":         DATA_DIR / "darkweb_intel" / "actor_profiles.json",
    "darkweb_entities":       DATA_DIR / "darkweb_intel" / "entity_monitor.json",
    "darkweb_campaigns":      DATA_DIR / "darkweb_intel" / "campaign_map.json",
    "darkweb_forums":         DATA_DIR / "darkweb_intel" / "forum_signals.json",
    "darkweb_meta":           DATA_DIR / "darkweb_intel" / "engine_meta.json",
    # Risk Quantification
    "risk_financial":         DATA_DIR / "risk_quantification" / "financial_impact.json",
    "risk_brand":             DATA_DIR / "risk_quantification" / "brand_protection.json",
    "risk_tiers":             DATA_DIR / "risk_quantification" / "risk_tiers.json",
    "risk_portfolio":         DATA_DIR / "risk_quantification" / "portfolio_risk_summary.json",
    "risk_meta":              DATA_DIR / "risk_quantification" / "engine_meta.json",
    # TTP Engine
    "ttp_matrix":             DATA_DIR / "ttp_engine" / "ttp_coverage_matrix.json",
    "ttp_correlations":       DATA_DIR / "ttp_engine" / "ttp_correlations.json",
    "ttp_siem_rules":         DATA_DIR / "ttp_engine" / "siem_rules.json",
    "ttp_meta":               DATA_DIR / "ttp_engine" / "engine_meta.json",
    # SOAR Engine
    "soar_iocs":              DATA_DIR / "soar_engine" / "ioc_enrichment.json",
    "soar_dispatch":          DATA_DIR / "soar_engine" / "siem_dispatch_queue.json",
    "soar_responses":         DATA_DIR / "soar_engine" / "response_actions.json",
    "soar_meta":              DATA_DIR / "soar_engine" / "engine_meta.json",
    # Detection Engine (from Mandate 4)
    "detection_matrix":       DATA_DIR / "detection_engine" / "detection_matrix.json",
    "detection_meta":         DATA_DIR / "detection_engine" / "engine_meta.json",
    # Threat Graph (from Mandate 4)
    "graph_nodes":            DATA_DIR / "threat_graph" / "graph_nodes.json",
    "graph_meta":             DATA_DIR / "threat_graph" / "graph_meta.json",
    # Exploit Intel (from Mandate 4)
    "exploit_index":          DATA_DIR / "exploit_intel" / "exploit_index.json",
    "exploit_meta":           DATA_DIR / "exploit_intel" / "engine_meta.json",
    # Main threat feed
    "manifest":               DATA_DIR / "enriched_manifest.json",
    "feed_manifest":          DATA_DIR / "stix" / "feed_manifest.json",
}

# ── TTL cache: {key: (data, expires_at)} ─────────────────────────────────────
_cache: Dict[str, tuple] = {}
_cache_lock = threading.Lock()
DEFAULT_TTL_SECONDS = 300  # 5 minutes


def _load_json_safe(path: Path, default: Any = None) -> Any:
    """Safe JSON load — never raises. Returns default on any error."""
    try:
        if not path.exists():
            return default
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.debug(f"load_json_safe({path}): {e}")
        return default


def load(key: str, ttl: int = DEFAULT_TTL_SECONDS,
         default: Any = None) -> Any:
    """
    Load engine output by key with TTL caching.
    Thread-safe, never raises.
    """
    now = time.monotonic()

    # Check cache
    with _cache_lock:
        if key in _cache:
            data, expires = _cache[key]
            if now < expires:
                return data

    # Load from disk
    path = ENGINE_FILES.get(key)
    if path is None:
        logger.warning(f"Unknown engine key: {key}")
        return default

    data = _load_json_safe(path, default)

    # Cache the result
    with _cache_lock:
        _cache[key] = (data, now + ttl)

    return data


def invalidate(key: str) -> None:
    """Invalidate a cache entry."""
    with _cache_lock:
        _cache.pop(key, None)


def invalidate_all() -> None:
    """Clear all cached data."""
    with _cache_lock:
        _cache.clear()


def is_available(key: str) -> bool:
    """Check if engine output file exists."""
    path = ENGINE_FILES.get(key)
    return path is not None and path.exists()


def get_engine_status() -> List[Dict]:
    """Return health status for all engines."""
    engines = [
        ("Agentic AI", "agentic_meta"),
        ("Identity Intel", "identity_meta"),
        ("Dark Web Intel", "darkweb_meta"),
        ("Risk Quantification", "risk_meta"),
        ("TTP Engine", "ttp_meta"),
        ("SOAR Engine", "soar_meta"),
        ("Detection Engine", "detection_meta"),
        ("Threat Graph", "graph_meta"),
        ("Exploit Intel", "exploit_meta"),
    ]
    status = []
    for name, meta_key in engines:
        meta = load(meta_key, ttl=60, default={})
        available = is_available(meta_key)
        status.append({
            "name": name,
            "status": "OPERATIONAL" if available else "PENDING_FIRST_RUN",
            "last_run": meta.get("run_timestamp") if meta else None,
            "outputs_available": available,
            "version": meta.get("version", "1.0.0") if meta else "1.0.0",
        })
    return status


def get_threats(page: int = 1, per_page: int = 20,
                severity: Optional[str] = None,
                cve_filter: Optional[str] = None) -> Dict:
    """Load and paginate threat advisories."""
    # Try enriched manifest first, then STIX feed_manifest
    advisories = load("manifest", ttl=120, default=[])
    if not advisories:
        advisories = load("feed_manifest", ttl=120, default=[])
        if isinstance(advisories, dict):
            advisories = advisories.get("advisories", [])

    if not isinstance(advisories, list):
        advisories = []

    # Filter
    if severity:
        advisories = [a for a in advisories
                      if str(a.get("severity", "")).upper() == severity.upper()]
    if cve_filter:
        cve_up = cve_filter.upper()
        advisories = [a for a in advisories
                      if cve_up in str(a.get("cve_id", "")).upper() or
                         cve_up in str(a.get("title", "")).upper()]

    total = len(advisories)
    start = (page - 1) * per_page
    end = start + per_page
    page_data = advisories[start:end]

    return {
        "threats": page_data,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


def get_threat_by_id(threat_id: str) -> Optional[Dict]:
    """Find a specific advisory by ID or CVE ID."""
    advisories = load("manifest", ttl=120, default=[])
    if not advisories:
        advisories = load("feed_manifest", ttl=120, default=[])
        if isinstance(advisories, dict):
            advisories = advisories.get("advisories", [])
    if not isinstance(advisories, list):
        return None
    tid_upper = threat_id.upper()
    for adv in advisories:
        if (str(adv.get("id", "")).upper() == tid_upper or
                str(adv.get("cve_id", "")).upper() == tid_upper):
            return adv
    return None


def get_iocs(page: int = 1, per_page: int = 50,
             ioc_type: Optional[str] = None,
             min_confidence: float = 0.0) -> Dict:
    """Load and filter IOCs from SOAR engine output."""
    soar_data = load("soar_iocs", ttl=300, default={})
    iocs = soar_data.get("ioc_sample", []) if soar_data else []
    if not isinstance(iocs, list):
        iocs = []

    # Filter by type and confidence
    if ioc_type:
        iocs = [i for i in iocs if i.get("ioc_type", "") == ioc_type]
    if min_confidence > 0:
        iocs = [i for i in iocs if float(i.get("confidence", 0)) >= min_confidence]

    total = len(iocs)
    start = (page - 1) * per_page
    return {
        "iocs": iocs[start:start + per_page],
        "total": total,
        "page": page,
        "per_page": per_page,
        "iocs_by_type": soar_data.get("iocs_by_type", {}) if soar_data else {},
    }


def get_predictions(context: Optional[str] = None) -> Dict:
    """Load predictions from Agentic AI engine."""
    pred_data = load("agentic_predictions", ttl=300, default={})
    signals = load("agentic_signals", ttl=300, default={})
    sc_data = load("agentic_supply_chain", ttl=300, default={})
    meta = load("agentic_meta", ttl=300, default={})

    predictions = pred_data.get("predictions", []) if pred_data else []
    metrics = pred_data.get("threat_metrics", {}) if pred_data else {}

    # Filter by context if provided
    if context and predictions:
        ctx_lower = context.lower()
        predictions = [p for p in predictions
                       if ctx_lower in str(p.get("prediction", "")).lower() or
                          ctx_lower in str(p.get("evidence", "")).lower()]

    return {
        "predictions": predictions,
        "threat_metrics": metrics,
        "supply_chain_summary": {
            "total_risks": sc_data.get("total_supply_chain_risks", 0) if sc_data else 0,
            "top_ecosystems": (sc_data.get("top_vulnerable_ecosystems", [])[:5]
                               if sc_data else []),
        },
        "actor_attribution_available": bool(
            signals and signals.get("actor_attribution", {}).get("total_attributed", 0) > 0
        ),
        "engine_meta": {
            "advisories_processed": meta.get("advisories_processed", 0) if meta else 0,
            "last_run": meta.get("run_timestamp") if meta else None,
        },
    }


def get_identity_risk() -> Dict:
    """Load identity risk data."""
    index = load("identity_index", ttl=300, default={})
    signals = load("identity_signals", ttl=300, default={})
    remediation = load("identity_remediation", ttl=300, default={})
    meta = load("identity_meta", ttl=300, default={})

    return {
        "risk_summary": index.get("risk_summary", {}) if index else {},
        "risk_distribution": index.get("risk_distribution", {}) if index else {},
        "top_stealer_families": index.get("top_stealer_families", {}) if index else {},
        "total_signals": signals.get("total_signals", 0) if signals else 0,
        "remediation_actions_pending": len(
            remediation.get("actions", []) if remediation else []
        ),
        "engine_meta": {
            "last_run": meta.get("run_timestamp") if meta else None,
            "stealer_families_detected": meta.get("stealer_families_detected", 0) if meta else 0,
        },
    }


def get_darkweb_intel() -> Dict:
    """Load dark web intelligence data."""
    entities = load("darkweb_entities", ttl=300, default={})
    actors = load("darkweb_actors", ttl=300, default={})
    campaigns = load("darkweb_campaigns", ttl=300, default={})
    meta = load("darkweb_meta", ttl=300, default={})

    return {
        "darkweb_signals": entities.get("darkweb_signals", [])[:20] if entities else [],
        "total_signals": entities.get("total_darkweb_signals", 0) if entities else 0,
        "sector_exposure": entities.get("sector_exposure", []) if entities else [],
        "high_risk_sectors": entities.get("high_risk_sectors", []) if entities else [],
        "actor_profiles_count": len(
            actors.get("actor_profiles", {}) if actors else {}
        ),
        "active_campaigns": campaigns.get("active_campaigns", [])[:10] if campaigns else [],
        "highest_campaign": campaigns.get("highest_threat", "NONE") if campaigns else "NONE",
        "engine_meta": {
            "last_run": meta.get("run_timestamp") if meta else None,
            "actors_profiled": meta.get("actors_profiled", 0) if meta else 0,
        },
    }


def get_risk_scores(limit: int = 20) -> Dict:
    """Load financial risk quantification data."""
    portfolio = load("risk_portfolio", ttl=300, default={})
    financial = load("risk_financial", ttl=300, default={})
    brand = load("risk_brand", ttl=300, default={})
    meta = load("risk_meta", ttl=300, default={})

    top_risks = (financial.get("top_financial_risks", [])[:limit]
                 if financial else [])

    return {
        "portfolio_summary": {
            "total_potential_loss_usd": portfolio.get("total_potential_loss_usd", 0) if portfolio else 0,
            "total_potential_loss_formatted": portfolio.get("total_potential_loss_formatted", "N/A") if portfolio else "N/A",
            "critical_cves": portfolio.get("critical_cves", 0) if portfolio else 0,
            "brand_risk_level": portfolio.get("brand_risk_level", "UNKNOWN") if portfolio else "UNKNOWN",
        },
        "top_financial_risks": top_risks,
        "severity_distribution": (financial.get("severity_distribution", {})
                                   if financial else {}),
        "brand_protection": {
            "phishing_threats": brand.get("total_phishing_threats", 0) if brand else 0,
            "takedown_queue": brand.get("takedown_queue_size", 0) if brand else 0,
            "impersonation_events": brand.get("total_impersonation_events", 0) if brand else 0,
        },
        "engine_meta": {
            "last_run": meta.get("run_timestamp") if meta else None,
            "cves_quantified": meta.get("cves_quantified", 0) if meta else 0,
        },
    }


def get_detections(limit: int = 50) -> Dict:
    """Load detection rules from TTP engine and Detection Engine."""
    ttp_matrix = load("ttp_matrix", ttl=300, default={})
    ttp_corr = load("ttp_correlations", ttl=300, default={})
    ttp_siem = load("ttp_siem_rules", ttl=300, default={})
    det_matrix = load("detection_matrix", ttl=300, default={})
    ttp_meta = load("ttp_meta", ttl=300, default={})

    siem_rules = ttp_siem.get("rules", [])[:limit] if ttp_siem else []

    return {
        "ttp_coverage": {
            "unique_techniques": ttp_matrix.get("unique_techniques", 0) if ttp_matrix else 0,
            "tactics_covered": ttp_matrix.get("tactics_covered_count", 0) if ttp_matrix else 0,
            "coverage_pct": ttp_matrix.get("coverage_pct", 0) if ttp_matrix else 0,
        },
        "top_techniques": (ttp_corr.get("top_techniques", [])[:20]
                           if ttp_corr else []),
        "siem_rules": siem_rules,
        "sigma_rules_generated": ttp_meta.get("sigma_rules_generated", 0) if ttp_meta else 0,
        "yara_rules_generated": ttp_meta.get("yara_rules_generated", 0) if ttp_meta else 0,
        "siem_export_available": bool(det_matrix),
        "engine_meta": {
            "last_run": ttp_meta.get("run_timestamp") if ttp_meta else None,
        },
    }


def get_soar_data(action_type: str, target: Optional[str] = None,
                  playbook: Optional[str] = None) -> Dict:
    """Execute a SOAR action (simulation mode)."""
    meta = load("soar_meta", ttl=300, default={})
    dispatch = load("soar_dispatch", ttl=300, default={})
    responses = load("soar_responses", ttl=300, default={})

    if action_type == "LIST_PLAYBOOKS":
        playbooks_dir = DATA_DIR / "soar_engine" / "playbooks"
        playbook_list = []
        if playbooks_dir.exists():
            for pb_file in playbooks_dir.glob("*.json"):
                try:
                    with open(pb_file) as f:
                        pb = json.load(f)
                    playbook_list.append({
                        "playbook_id": pb.get("playbook_id"),
                        "name": pb.get("playbook_name"),
                        "trigger": pb.get("trigger"),
                        "priority": pb.get("priority"),
                        "total_steps": pb.get("total_steps"),
                        "execution_mode": pb.get("execution_mode"),
                    })
                except Exception:
                    pass
        return {"playbooks": playbook_list, "total": len(playbook_list)}

    elif action_type == "GET_PLAYBOOK" and playbook:
        pb_path = DATA_DIR / "soar_engine" / "playbooks" / f"{playbook.lower()}.json"
        pb_data = _load_json_safe(pb_path, {})
        return {"playbook": pb_data} if pb_data else {"error": "Playbook not found"}

    elif action_type == "GET_DISPATCH_QUEUE":
        queue = dispatch.get("dispatch_queue", [])[:20] if dispatch else []
        return {
            "dispatch_queue": queue,
            "total": dispatch.get("total_dispatches", 0) if dispatch else 0,
            "execution_mode": "SIMULATION",
        }

    elif action_type == "ENRICH_IOC":
        soar_iocs = load("soar_iocs", ttl=300, default={})
        iocs = soar_iocs.get("ioc_sample", []) if soar_iocs else []
        if target:
            matches = [i for i in iocs if target in str(i.get("ioc_value", ""))]
            return {
                "target": target,
                "enrichment_results": matches[:5],
                "found": len(matches),
                "source": "SOAR IOC Database",
                "execution_mode": "SIMULATION",
            }
        return {
            "target": target,
            "enrichment_results": [],
            "message": "No target provided",
        }

    elif action_type in ("BLOCK_IP", "CREATE_INCIDENT"):
        resp_list = responses.get("response_actions", []) if responses else []
        return {
            "action_type": action_type,
            "target": target,
            "execution_mode": "SIMULATION",
            "status": "QUEUED_FOR_VALIDATION",
            "message": f"Action {action_type} queued. Manual approval required for live execution.",
            "response_actions_available": len(resp_list),
            "engine_meta": {
                "last_run": meta.get("run_timestamp") if meta else None,
            },
        }

    return {
        "action_type": action_type,
        "status": "ACKNOWLEDGED",
        "execution_mode": "SIMULATION",
        "engine_meta": meta or {},
    }
