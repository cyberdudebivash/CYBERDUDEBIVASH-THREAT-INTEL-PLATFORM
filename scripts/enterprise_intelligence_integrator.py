#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Enterprise Intelligence Integration Layer v1.0
================================================================================
FILE: scripts/enterprise_intelligence_integrator.py

PURPOSE:
    Single integration module that wires all 7 enterprise intelligence engines
    into the live process_entry() pipeline in agent/sentinel_blogger.py.

    Called at STEP 7g (after risk_reason, before premium report generation).
    Returns EnterpriseIntelResult with validated/enriched data that REPLACES
    the originals in the pipeline — zero regression, surgical replacement only.

ENGINE PIPELINE (in execution order):
    1. AHE  — Anti-Hallucination Engine  (detect + block fake intelligence)
    2. RSE  — Evidence-Weighted Risk Scoring Engine
    3. DCE  — Deterministic Confidence Engine  (Admiralty Scale)
    4. IIP  — IOC Intelligence Pipeline  (validate + remove fake IOCs)
    5. MAE  — MITRE ATT&CK Evidence Engine  (evidence-based technique mapping)
    6. NE   — Narrative Engine  (analyst-grade, tier-aware summaries)
    7. QGS  — Intelligence Quality Gates  (pre-publish 12-gate enforcement)

ZERO-REGRESSION CONTRACT:
    - If ANY engine raises an exception, original values are preserved unchanged.
    - Hard blocks are ONLY applied for critical AHE violations (fake IOCs,
      synthetic attribution injected without evidence).
    - Quality gate warnings are logged but do NOT block the pipeline by default.
    - All engine outputs are stored in enterprise_enrichment for STIX manifest.

INTEGRATION CONTRACT:
    Called from agent/sentinel_blogger.py:
        from enterprise_intelligence_integrator import integrate_intelligence
        ei = integrate_intelligence(
            headline=headline,
            enriched_content=enriched_content,
            source_url=source_url,
            extracted_iocs=extracted_iocs,   # dict[str, list[str]]
            risk_score=risk_score,
            confidence=confidence,
            severity=severity,
            mitre_data=mitre_data,           # list[dict]
            actor_data=actor_data,           # dict
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_present=kev_present,
            tlp_label=tlp.get("label", "TLP:CLEAR"),
        )
        # Replace originals with validated outputs
        if not ei.hard_block:
            extracted_iocs = ei.cleaned_iocs_dict
            risk_score     = ei.risk_score
            confidence     = ei.confidence
            mitre_data     = ei.mitre_data
            enriched_content = ei.enriched_content  # narrative-enriched

© 2026 CyberDudeBivash Pvt. Ltd.  |  v1.0  |  Production-grade.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-EII")

# ── Engine version tag ──────────────────────────────────────────────────────
ENGINE_ID      = "enterprise_intelligence_integrator"
ENGINE_VERSION = "1.0.0"

# ── Ensure scripts/ is importable ──────────────────────────────────────────
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)


# ============================================================================
# RESULT DATACLASS
# ============================================================================

@dataclass
class EnterpriseIntelResult:
    """
    Output of the Enterprise Intelligence Integration Layer.

    Replaces original pipeline values ONLY where engines produce validated output.
    All original values are preserved as fallbacks if engines fail.
    """
    # ── Decision ──────────────────────────────────────────────────────────
    hard_block:       bool  = False
    hard_block_reason: str  = ""

    # ── Enriched outputs (replace originals when hard_block=False) ────────
    cleaned_iocs_dict: Dict[str, List[str]]  = field(default_factory=dict)
    risk_score:        float                  = 0.0
    confidence:        float                  = 0.0
    mitre_data:        List[Dict]             = field(default_factory=list)
    enriched_content:  str                    = ""   # narrative-enriched content

    # ── Enterprise enrichment metadata (written to STIX manifest) ─────────
    enterprise_enrichment: Dict[str, Any] = field(default_factory=dict)

    # ── Quality gate summary ───────────────────────────────────────────────
    quality_passed:  int  = 0
    quality_failed:  int  = 0
    quality_warned:  int  = 0
    publishable:     bool = True

    # ── Audit trail ────────────────────────────────────────────────────────
    engine_results:  Dict[str, Any] = field(default_factory=dict)
    run_ts:          str = ""
    version:         str = ENGINE_VERSION


# ============================================================================
# FORMAT BRIDGE: pipeline ↔ engine IOC formats
# ============================================================================

def _iocs_dict_to_list(iocs_dict: Dict[str, List[str]]) -> List[Dict]:
    """
    Convert pipeline IOC format  →  engine IOC format.

    Pipeline: {"ipv4": ["1.2.3.4"], "domain": ["evil.com"], "cve": ["CVE-2026-9082"]}
    Engine:   [{"value": "1.2.3.4", "type": "IPV4", "context": "ipv4"}, ...]

    CRITICAL: CVE IDs are vulnerability identifiers, NOT indicators of compromise.
    They must NOT appear in the iocs/indicators list — only in the cve_ids field.
    The AHE will correctly reject any item with CVE IDs in the iocs list.
    """
    # IOC types that are genuine network/file indicators — exclude structural identifiers
    VALID_IOC_TYPES = {
        "ipv4", "ipv6", "domain", "url", "email",
        "md5", "sha1", "sha256", "hash", "file_hash",
        "filename", "registry", "mutex",
    }
    result = []
    if not isinstance(iocs_dict, dict):
        return result
    for ioc_type, values in iocs_dict.items():
        # Skip CVE IDs and source reference URLs — these are NOT IOCs
        if ioc_type.lower() in ("cve", "reference_url", "source_url"):
            continue
        if ioc_type.lower() not in VALID_IOC_TYPES:
            continue
        if not isinstance(values, list):
            continue
        for v in values:
            if v and isinstance(v, str):
                result.append({
                    "value":   v.strip(),
                    "type":    ioc_type.upper(),
                    "context": ioc_type.lower(),
                    "source":  "APEX-PIPELINE",
                })
    return result


def _valid_iocs_list_to_dict(valid_ioc_list: List[Dict]) -> Dict[str, List[str]]:
    """
    Convert validated engine IOC list  →  pipeline IOC dict.

    Only includes VALID status IOCs. INVALID and PSEUDO are excluded.
    """
    result: Dict[str, List[str]] = {}
    if not isinstance(valid_ioc_list, list):
        return result
    for ioc in valid_ioc_list:
        if not isinstance(ioc, dict):
            continue
        status = ioc.get("validation_status", "VALID")
        if status not in ("VALID",):
            continue
        raw_type = (ioc.get("type") or ioc.get("ioc_type") or "unknown").lower()
        value    = str(ioc.get("value") or "").strip()
        if not value:
            continue
        # Normalise type keys to match pipeline expectation
        type_map = {
            "ipv4": "ipv4", "ipv6": "ipv6", "domain": "domain",
            "url": "url", "email": "email", "md5": "md5",
            "sha1": "sha1", "sha256": "sha256", "cve": "cve",
            "hash": "sha256", "file_hash": "sha256",
        }
        normalised = type_map.get(raw_type, raw_type)
        result.setdefault(normalised, [])
        if value not in result[normalised]:
            result[normalised].append(value)
    return result


# ============================================================================
# ITEM DICT BUILDER: convert process_entry fields → engine-compatible item
# ============================================================================

def _build_item_dict(
    headline: str,
    enriched_content: str,
    source_url: str,
    extracted_iocs: Dict[str, List[str]],
    risk_score: float,
    confidence: float,
    severity: str,
    mitre_data: List[Dict],
    actor_data: Dict,
    cvss_score: Optional[float],
    epss_score: Optional[float],
    kev_present: bool,
    tlp_label: str,
) -> Dict:
    """
    Build a normalised item dict compatible with all 7 engine APIs.
    Engines operate on a unified item schema — this bridges the gap.
    """
    iocs_list = _iocs_dict_to_list(extracted_iocs)
    actor     = actor_data or {}
    actor_id  = actor.get("tracking_id", "UNC-CDB-99")
    actor_profile = actor.get("profile", {})

    # Determine CVE IDs
    cve_ids = extracted_iocs.get("cve", []) if isinstance(extracted_iocs, dict) else []

    # Build ATT&CK techniques list in engine-expected format
    ttp_list = []
    if isinstance(mitre_data, list):
        for t in mitre_data:
            if isinstance(t, dict):
                ttp_list.append({
                    "technique_id":   t.get("id") or t.get("technique_id", ""),
                    "technique_name": t.get("name") or t.get("technique_name", ""),
                    "tactic":         t.get("tactic", ""),
                    "confidence":     t.get("confidence", "MEDIUM"),
                })

    return {
        # Identity
        "id":                  f"entry-{abs(hash(headline + source_url)) % 10**8}",
        "stix_id":             f"entry-{abs(hash(headline + source_url)) % 10**8}",
        "title":               headline,
        "description":         enriched_content[:2000],
        "summary":             enriched_content[:1000],
        "source_url":          source_url,
        "blog_url":            source_url,

        # Scoring
        "risk_score":          risk_score,
        "severity":            severity,
        "confidence":          confidence,
        "cvss_score":          cvss_score,
        "cvss":                cvss_score,
        "epss_score":          epss_score,
        "epss":                epss_score,
        "kev_present":         kev_present,
        "kev_status":          kev_present,

        # IOCs in engine-list format
        "iocs":                iocs_list,
        "indicators":          iocs_list,
        "ioc_count":           sum(len(v) for v in (extracted_iocs or {}).values()
                                   if isinstance(v, list)),

        # ATT&CK
        "ttps":                ttp_list,
        "mitre_techniques":    [t.get("technique_id", "") for t in ttp_list],

        # Actor
        "actor_cluster":       actor_id,
        "actor_tracking_id":   actor_id,
        "actor_profile":       actor_profile,
        "actor_attributed":    not actor_id.startswith("UNC-"),
        "actor_confidence":    actor.get("confidence", 0),

        # CVE
        "cve_ids":             cve_ids,
        "vulnerability_type":  "CVE" if cve_ids else "",

        # TLP
        "tlp_label":           tlp_label,

        # Content
        "full_text":           enriched_content,
    }


# ============================================================================
# MITRE FORMAT BRIDGE: engine output → pipeline-compatible list
# ============================================================================

def _engine_ttps_to_mitre_data(ttps: List[Dict]) -> List[Dict]:
    """
    Convert engine TTP dicts → pipeline mitre_data list format.
    Preserves all evidence fields and adds them as enrichment.
    """
    result = []
    for t in (ttps or []):
        if not isinstance(t, dict):
            continue
        tid = t.get("technique_id", "")
        if not tid or tid == "UNRESOLVED":
            continue
        result.append({
            "id":                 tid,
            "technique_id":       tid,
            "name":               t.get("technique_name", ""),
            "technique_name":     t.get("technique_name", ""),
            "tactic":             t.get("tactic", ""),
            "confidence":         t.get("confidence", "MEDIUM"),
            # Enterprise enrichment fields
            "justification":      t.get("justification", ""),
            "observed_behavior":  t.get("observed_behavior", ""),
            "detection_guidance": t.get("detection_guidance", ""),
            "sigma_hint":         t.get("sigma_hint", ""),
            "kql_hint":           t.get("kql_hint", ""),
            "evidence_based":     True,
        })
    return result


# ============================================================================
# CORE: ENGINE 1 — Anti-Hallucination Engine
# ============================================================================

def _run_ahe(item: Dict) -> Dict:
    """Run Anti-Hallucination Engine. Returns {'hard_fail': bool, 'violations': [...]}"""
    try:
        from anti_hallucination_engine import HallucinationEngine
        ahe    = HallucinationEngine()
        result = ahe.audit(item)
        return {
            "engine":     "AHE",
            "hard_fail":  result.hard_fail,
            "violations": [v.__dict__ if hasattr(v, "__dict__") else str(v)
                           for v in (result.violations or [])],
            "warnings":   [w.__dict__ if hasattr(w, "__dict__") else str(w)
                           for w in (result.warnings   or [])],
            "pass_count": result.pass_count,
            "status":     "BLOCK" if result.hard_fail else "PASS",
        }
    except Exception as e:
        logger.debug("[EII-AHE] Engine unavailable (non-fatal): %s", e)
        return {"engine": "AHE", "status": "SKIPPED", "hard_fail": False, "error": str(e)}


# ============================================================================
# CORE: ENGINE 2 — Evidence-Weighted Risk Scoring Engine
# ============================================================================

def _run_rse(item: Dict, original_risk: float) -> Dict:
    """Run Risk Scoring Engine. Returns enriched item with apex_risk field."""
    try:
        from apex_risk_scoring_engine import compute_apex_risk
        enriched = compute_apex_risk(item)
        new_risk  = enriched.get("apex_risk", original_risk)
        evidence  = enriched.get("apex_risk_evidence", {})
        rationale = enriched.get("apex_risk_rationale", "")
        return {
            "engine":    "RSE",
            "status":    "PASS",
            "risk_score": float(new_risk),
            "evidence":   evidence,
            "rationale":  rationale,
        }
    except Exception as e:
        logger.debug("[EII-RSE] Engine unavailable (non-fatal): %s", e)
        return {
            "engine":     "RSE",
            "status":     "SKIPPED",
            "risk_score": original_risk,
            "error":      str(e),
        }


# ============================================================================
# CORE: ENGINE 3 — Deterministic Confidence Engine
# ============================================================================

def _run_dce(item: Dict, original_confidence: float) -> Dict:
    """Run Confidence Engine. Returns deterministic confidence with evidence."""
    try:
        from apex_confidence_engine import compute_confidence
        enriched   = compute_confidence(item)
        new_conf   = enriched.get("confidence_pct",
                     enriched.get("confidence_score", original_confidence))
        band       = enriched.get("confidence_band", "")
        breakdown  = enriched.get("confidence_breakdown", {})
        return {
            "engine":     "DCE",
            "status":     "PASS",
            "confidence": float(new_conf),
            "band":       band,
            "breakdown":  breakdown,
        }
    except Exception as e:
        logger.debug("[EII-DCE] Engine unavailable (non-fatal): %s", e)
        return {
            "engine":     "DCE",
            "status":     "SKIPPED",
            "confidence": original_confidence,
            "error":      str(e),
        }


# ============================================================================
# CORE: ENGINE 4 — IOC Intelligence Pipeline
# ============================================================================

def _run_iip(item: Dict, original_iocs_dict: Dict) -> Dict:
    """Run IOC Intelligence Pipeline. Returns validated IOC dict + stats."""
    try:
        from apex_ioc_intelligence_pipeline import process_item_iocs
        enriched         = process_item_iocs(item)
        valid_iocs_list  = enriched.get("iocs", [])
        invalid_count    = enriched.get("ioc_count_invalid", 0)
        pseudo_count     = enriched.get("ioc_count_pseudo", 0)
        valid_count      = enriched.get("ioc_count", 0)

        # Rebuild pipeline-compatible dict from VALID IOCs only
        cleaned_dict = _valid_iocs_list_to_dict(valid_iocs_list)

        # If validation wiped ALL IOCs (over-aggressive), fall back to originals
        # This protects against edge cases where CVE IDs are wrongly invalidated
        original_total = sum(len(v) for v in (original_iocs_dict or {}).values()
                             if isinstance(v, list))
        if valid_count == 0 and original_total > 0:
            logger.warning(
                "[EII-IIP] IOC pipeline produced 0 valid IOCs from %d originals "
                "— falling back to original dict to prevent data loss",
                original_total,
            )
            cleaned_dict = original_iocs_dict

        # Always keep CVE IDs — they are structural identifiers, not network IOCs
        if "cve" in (original_iocs_dict or {}):
            cleaned_dict.setdefault("cve", [])
            for cve in original_iocs_dict["cve"]:
                if cve not in cleaned_dict["cve"]:
                    cleaned_dict["cve"].append(cve)

        return {
            "engine":         "IIP",
            "status":         "PASS",
            "cleaned_dict":   cleaned_dict,
            "valid_count":    valid_count,
            "invalid_count":  invalid_count,
            "pseudo_count":   pseudo_count,
            "ioc_detail":     valid_iocs_list,
        }
    except Exception as e:
        logger.debug("[EII-IIP] Engine unavailable (non-fatal): %s", e)
        return {
            "engine":       "IIP",
            "status":       "SKIPPED",
            "cleaned_dict": original_iocs_dict,
            "error":        str(e),
        }


# ============================================================================
# CORE: ENGINE 5 — MITRE ATT&CK Evidence Engine
# ============================================================================

def _run_mae(item: Dict, original_mitre: List[Dict]) -> Dict:
    """Run MITRE ATT&CK Engine. Returns evidence-based technique mapping."""
    try:
        from apex_mitre_attack_engine import enrich_attack_mapping
        enriched   = enrich_attack_mapping(item)
        ttps       = enriched.get("ttps", [])
        ttp_count  = enriched.get("ttp_count", 0)

        # Convert to pipeline-compatible mitre_data format
        new_mitre = _engine_ttps_to_mitre_data(ttps)

        # If engine produced 0 valid techniques, preserve originals
        if not new_mitre and original_mitre:
            logger.debug("[EII-MAE] Engine produced 0 techniques — preserving originals")
            new_mitre = original_mitre

        return {
            "engine":    "MAE",
            "status":    "PASS",
            "mitre_data": new_mitre,
            "ttp_count":  ttp_count,
            "ttps_raw":   ttps,
        }
    except Exception as e:
        logger.debug("[EII-MAE] Engine unavailable (non-fatal): %s", e)
        return {
            "engine":     "MAE",
            "status":     "SKIPPED",
            "mitre_data": original_mitre,
            "error":      str(e),
        }


# ============================================================================
# CORE: ENGINE 6 — Narrative Intelligence Engine
# ============================================================================

def _run_narrative(item: Dict, original_content: str) -> Dict:
    """Run Narrative Engine. Returns analyst-grade, tier-aware summary."""
    try:
        from apex_narrative_engine import NarrativeEngine
        ne       = NarrativeEngine()
        enriched = ne.generate(item)

        summary   = enriched.get("executive_summary", "")
        tier      = enriched.get("intelligence_tier", "generic")
        entropy   = enriched.get("narrative_entropy", 0.0)

        # If engine produced empty summary, preserve original content
        if not summary or len(summary.strip()) < 100:
            logger.debug("[EII-NE] Empty narrative — preserving original content")
            return {
                "engine":   "NE",
                "status":   "WARN",
                "summary":  "",
                "tier":     tier,
                "entropy":  entropy,
            }

        return {
            "engine":   "NE",
            "status":   "PASS",
            "summary":  summary,
            "tier":     tier,
            "entropy":  entropy,
        }
    except Exception as e:
        logger.debug("[EII-NE] Engine unavailable (non-fatal): %s", e)
        return {
            "engine":  "NE",
            "status":  "SKIPPED",
            "summary": "",
            "error":   str(e),
        }


# ============================================================================
# CORE: ENGINE 7 — Intelligence Quality Gates
# ============================================================================

def _run_quality_gates(item: Dict) -> Dict:
    """
    Run 12-gate Quality Gate System.
    Returns publishable decision + gate results.
    Gates 8 (duplicate), 10 (stix_id) are advisory-only in pipeline context
    since STIX IDs are assigned post-processing.
    """
    ADVISORY_GATES = {"gate08_duplicate", "gate10_stix_id", "gate09_tlp"}
    try:
        from apex_intelligence_quality_gates import QualityGateSystem
        qgs    = QualityGateSystem()
        report = qgs.evaluate(item)

        # Override: advisory gates never cause hard block in pipeline context
        gates_passed = report.gates_passed
        gates_failed = report.gates_failed
        gates_warned = report.gates_warned
        publishable  = report.publishable

        gate_details = []
        for r in (report.results or []):
            gate_name = getattr(r, "gate_name", "") or getattr(r, "name", "")
            is_advisory = any(ag in str(gate_name).lower() for ag in
                              ["duplicate", "stix_id", "tlp"])
            gate_details.append({
                "gate":      gate_name,
                "passed":    r.passed,
                "severity":  r.severity if hasattr(r, "severity") else "HARD_FAIL",
                "detail":    r.detail   if hasattr(r, "detail")   else "",
                "advisory":  is_advisory,
            })
            # Re-evaluate publishable with advisory exclusions
            if not r.passed and hasattr(r, "severity") and r.severity == "HARD_FAIL":
                if is_advisory:
                    # Don't count advisory gates in hard fail count
                    gates_failed = max(0, gates_failed - 1)
                    publishable  = (gates_failed == 0)

        return {
            "engine":        "QGS",
            "status":        "PASS" if publishable else "BLOCK",
            "publishable":   publishable,
            "gates_passed":  gates_passed,
            "gates_failed":  gates_failed,
            "gates_warned":  gates_warned,
            "gate_details":  gate_details,
        }
    except Exception as e:
        logger.debug("[EII-QGS] Engine unavailable (non-fatal): %s", e)
        return {
            "engine":      "QGS",
            "status":      "SKIPPED",
            "publishable": True,   # Non-blocking on engine failure
            "error":       str(e),
        }


# ============================================================================
# MAIN INTEGRATION FUNCTION
# ============================================================================

def integrate_intelligence(
    headline:         str,
    enriched_content: str,
    source_url:       str,
    extracted_iocs:   Dict[str, List[str]],
    risk_score:       float,
    confidence:       float,
    severity:         str,
    mitre_data:       List[Dict],
    actor_data:       Dict,
    cvss_score:       Optional[float]  = None,
    epss_score:       Optional[float]  = None,
    kev_present:      bool             = False,
    tlp_label:        str              = "TLP:CLEAR",
) -> EnterpriseIntelResult:
    """
    Main entry point. Runs all 7 engines and returns EnterpriseIntelResult.

    ZERO-REGRESSION CONTRACT:
    - Wrapped in outer try/except — pipeline NEVER crashes on EII failure.
    - Each engine is independently fault-tolerant.
    - Original values used as fallback if any engine fails.
    - Hard blocks are only issued for AHE violations (fake/fabricated intelligence).
    """
    run_ts = datetime.now(timezone.utc).isoformat()

    try:
        logger.info(
            "[EII] Starting enterprise intelligence integration for: %s",
            headline[:80],
        )

        # ── Build normalised item dict ─────────────────────────────────────
        item = _build_item_dict(
            headline=headline,
            enriched_content=enriched_content,
            source_url=source_url,
            extracted_iocs=extracted_iocs,
            risk_score=risk_score,
            confidence=confidence,
            severity=severity,
            mitre_data=mitre_data,
            actor_data=actor_data,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_present=kev_present,
            tlp_label=tlp_label,
        )

        engine_results: Dict[str, Any] = {}

        # ── ENGINE ORDER: IIP → MAE → AHE → RSE → DCE → NE → QGS ──────────
        # Rationale:
        #   IIP first: clean IOCs before AHE sees them (removes pseudo/invalid)
        #   MAE second: enrich TTPs with justification before AHE checks them
        #   AHE third: now validates clean IOCs + justified TTPs (no false blocks)
        #   RSE/DCE: use cleaned IOCs for evidence-weighted scoring
        #   NE: uses enriched TTPs for analyst-grade narratives
        #   QGS: final 12-gate quality check on fully enriched item

        # ── ENGINE 1: IOC Intelligence Pipeline ───────────────────────────
        iip_result = _run_iip(item, extracted_iocs)
        engine_results["iip"] = iip_result
        cleaned_iocs = iip_result.get("cleaned_dict", extracted_iocs)
        original_total = sum(len(v) for v in (extracted_iocs or {}).values()
                             if isinstance(v, list))
        cleaned_total  = sum(len(v) for v in (cleaned_iocs or {}).values()
                             if isinstance(v, list))
        logger.info("[EII-1/7] IIP: %s | iocs=%d → %d (removed=%d invalid/pseudo)",
                    iip_result.get("status", "?"),
                    original_total, cleaned_total,
                    iip_result.get("invalid_count", 0) + iip_result.get("pseudo_count", 0))

        # Update item with cleaned IOCs
        item["iocs"]       = _iocs_dict_to_list(cleaned_iocs)
        item["indicators"] = item["iocs"]

        # ── ENGINE 2: MITRE ATT&CK Evidence Engine ────────────────────────
        mae_result = _run_mae(item, mitre_data)
        engine_results["mae"] = mae_result
        new_mitre = mae_result.get("mitre_data", mitre_data)
        logger.info("[EII-2/7] MAE: %s | techniques=%d → %d",
                    mae_result.get("status", "?"),
                    len(mitre_data), len(new_mitre))

        # Update item with MAE-enriched TTPs (now have justification) before AHE
        item["ttps"]             = mae_result.get("ttps_raw", item.get("ttps", []))
        item["mitre_techniques"] = [t.get("id", "") for t in new_mitre]

        # ── ENGINE 3: Anti-Hallucination Engine ───────────────────────────
        # Runs on cleaned IOCs + MAE-enriched TTPs — avoids false hard blocks
        ahe_result = _run_ahe(item)
        engine_results["ahe"] = ahe_result
        logger.info("[EII-3/7] AHE: %s | violations=%d",
                    ahe_result.get("status", "?"),
                    len(ahe_result.get("violations", [])))

        if ahe_result.get("hard_fail"):
            violations = ahe_result.get("violations", [])
            reason = "; ".join(
                str(v.get("explanation", v.get("description", v))
                    if isinstance(v, dict) else v)
                for v in violations[:3]
            )
            logger.warning(
                "[EII] AHE HARD BLOCK on '%s': %s", headline[:60], reason[:200]
            )
            return EnterpriseIntelResult(
                hard_block=True,
                hard_block_reason=f"AHE: {reason[:300]}",
                cleaned_iocs_dict=cleaned_iocs,
                risk_score=risk_score,
                confidence=confidence,
                mitre_data=new_mitre,
                enriched_content=enriched_content,
                engine_results=engine_results,
                run_ts=run_ts,
            )

        # ── ENGINE 4: Evidence-Weighted Risk Scoring ───────────────────────
        rse_result = _run_rse(item, risk_score)
        engine_results["rse"] = rse_result
        new_risk = rse_result.get("risk_score", risk_score)

        # ── IMMUTABLE SEVERITY FLOORS v171.1 ────────────────────────────────
        # The RSE is an evidence-weighted FORECAST engine and may legitimately
        # reduce scores for low-signal items.  However, it MUST NOT reduce the
        # published risk_score below the minimum that corresponds to the item's
        # confirmed threat tier.  Doing so causes severity to be re-derived as
        # LOW even when CVSS >= 9, KEV is confirmed, or active exploitation is
        # observed — a P0 governance failure.
        #
        # Rules (immutable — cannot be overridden by any downstream engine):
        #   KEV confirmed                    → risk_score >= 7.5 (HIGH floor)
        #   Active exploitation in title/desc → risk_score >= 7.0 (HIGH floor)
        #   CVSS >= 9.5                       → risk_score >= 8.0 (HIGH floor)
        #   CVSS >= 9.0                       → risk_score >= 7.0 (HIGH floor)
        #   CVSS >= 8.0                       → risk_score >= 6.0 (HIGH floor)
        #   KEV + active exploitation         → risk_score >= 8.5 (CRITICAL floor)
        _kev_val   = str(item.get("kev") or item.get("kev_present") or "").upper()
        _kev_conf  = _kev_val in ("YES", "TRUE", "1", "LISTED")
        _cvss_rse  = 0.0
        for _f in ("cvss_score", "cvss", "cvss_base", "cvss_v3"):
            _v = item.get(_f)
            if _v is not None:
                try:
                    _cvss_rse = float(_v)
                    break
                except (TypeError, ValueError):
                    pass
        _title_rse = (item.get("title", "") + " " + item.get("description", "")).lower()
        _active_exploit_signals = [
            "actively exploited", "actively exploiting", "attackers actively exploit",
            "exploited in the wild", "active exploitation", "under active attack",
        ]
        _active_exp_rse = any(s in _title_rse for s in _active_exploit_signals)

        _risk_floor = 0.0
        _floor_reason = ""
        if _kev_conf and _active_exp_rse:
            _risk_floor = 8.5
            _floor_reason = "KEV+ACTIVE_EXPLOIT→8.5_floor"
        elif _kev_conf:
            _risk_floor = 7.5
            _floor_reason = "KEV_CONFIRMED→7.5_floor"
        elif _active_exp_rse:
            _risk_floor = 7.0
            _floor_reason = "ACTIVE_EXPLOIT→7.0_floor"
        elif _cvss_rse >= 9.5:
            _risk_floor = 8.0
            _floor_reason = f"CVSS={_cvss_rse}>=9.5→8.0_floor"
        elif _cvss_rse >= 9.0:
            _risk_floor = 7.0
            _floor_reason = f"CVSS={_cvss_rse}>=9.0→7.0_floor"
        elif _cvss_rse >= 8.0:
            _risk_floor = 6.0
            _floor_reason = f"CVSS={_cvss_rse}>=8.0→6.0_floor"

        if _risk_floor > 0.0 and new_risk < _risk_floor:
            logger.info(
                "[EII-4/7] RSE FLOOR APPLIED: %.2f → %.2f (%s) [original=%.2f]",
                new_risk, _risk_floor, _floor_reason, risk_score
            )
            new_risk = _risk_floor
            rse_result["risk_score"] = new_risk
            rse_result["floor_applied"] = _floor_reason
        # ── END IMMUTABLE FLOORS ─────────────────────────────────────────────

        logger.info("[EII-4/7] RSE: %s | score=%.2f → %.2f",
                    rse_result.get("status", "?"), risk_score, new_risk)

        # ── ENGINE 5: Deterministic Confidence ────────────────────────────
        item["risk_score"] = new_risk
        dce_result = _run_dce(item, confidence)
        engine_results["dce"] = dce_result
        new_confidence = dce_result.get("confidence", confidence)
        logger.info("[EII-5/7] DCE: %s | conf=%.1f → %.1f (%s)",
                    dce_result.get("status", "?"),
                    confidence, new_confidence,
                    dce_result.get("band", "?"))

        # ── ENGINE 6: Narrative Engine ─────────────────────────────────────
        item["confidence"] = new_confidence
        ne_result = _run_narrative(item, enriched_content)
        engine_results["ne"] = ne_result
        narrative_summary = ne_result.get("summary", "")
        logger.info("[EII-6/7] NE: %s | tier=%s | entropy=%.2f | len=%d",
                    ne_result.get("status", "?"),
                    ne_result.get("tier", "?"),
                    ne_result.get("entropy", 0.0),
                    len(narrative_summary))

        # Prepend narrative summary to enriched_content for premium report generator
        if narrative_summary and len(narrative_summary.strip()) >= 100:
            new_enriched = f"{narrative_summary}\n\n{enriched_content}"
        else:
            new_enriched = enriched_content

        # ── ENGINE 7: Intelligence Quality Gates ──────────────────────────
        item["risk_score"]  = new_risk
        item["confidence"]  = new_confidence
        item["description"] = new_enriched[:2000]
        qgs_result = _run_quality_gates(item)
        engine_results["qgs"] = qgs_result
        publishable = qgs_result.get("publishable", True)
        logger.info(
            "[EII-7/7] QGS: %s | passed=%d failed=%d warned=%d",
            qgs_result.get("status", "?"),
            qgs_result.get("gates_passed", 0),
            qgs_result.get("gates_failed", 0),
            qgs_result.get("gates_warned", 0),
        )

        # ── Build enterprise enrichment metadata ──────────────────────────
        enterprise_enrichment = {
            "eii_version":       ENGINE_VERSION,
            "eii_run_ts":        run_ts,
            "risk_evidence":     rse_result.get("evidence", {}),
            "risk_rationale":    rse_result.get("rationale", ""),
            "confidence_band":   dce_result.get("band", ""),
            "confidence_breakdown": dce_result.get("breakdown", {}),
            "ioc_validation": {
                "valid":   iip_result.get("valid_count", 0),
                "invalid": iip_result.get("invalid_count", 0),
                "pseudo":  iip_result.get("pseudo_count", 0),
            },
            "ioc_detail":        iip_result.get("ioc_detail", []),
            "mitre_evidence":    mae_result.get("ttps_raw", []),
            "narrative_tier":    ne_result.get("tier", "generic"),
            "narrative_entropy": ne_result.get("entropy", 0.0),
            "quality_gates": {
                "publishable":  publishable,
                "passed":       qgs_result.get("gates_passed", 0),
                "failed":       qgs_result.get("gates_failed", 0),
                "warned":       qgs_result.get("gates_warned", 0),
                "details":      qgs_result.get("gate_details", []),
            },
            "ahe_violations":    ahe_result.get("violations", []),
            "ahe_warnings":      ahe_result.get("warnings", []),
        }

        logger.info(
            "[EII] COMPLETE — risk=%.2f→%.2f conf=%.1f→%.1f "
            "iocs=%d→%d techniques=%d→%d publishable=%s",
            risk_score, new_risk,
            confidence, new_confidence,
            original_total, cleaned_total,
            len(mitre_data), len(new_mitre),
            publishable,
        )

        return EnterpriseIntelResult(
            hard_block=False,
            hard_block_reason="",
            cleaned_iocs_dict=cleaned_iocs,
            risk_score=float(new_risk),
            confidence=float(new_confidence),
            mitre_data=new_mitre,
            enriched_content=new_enriched,
            enterprise_enrichment=enterprise_enrichment,
            quality_passed=qgs_result.get("gates_passed", 0),
            quality_failed=qgs_result.get("gates_failed", 0),
            quality_warned=qgs_result.get("gates_warned", 0),
            publishable=publishable,
            engine_results=engine_results,
            run_ts=run_ts,
            version=ENGINE_VERSION,
        )

    except Exception as outer_e:
        # Outer safety net — EII failure NEVER crashes the pipeline
        logger.warning(
            "[EII] OUTER SAFETY NET — integration failed (%s). "
            "Continuing with original values. Pipeline unaffected.",
            outer_e,
        )
        return EnterpriseIntelResult(
            hard_block=False,
            cleaned_iocs_dict=extracted_iocs,
            risk_score=risk_score,
            confidence=confidence,
            mitre_data=mitre_data,
            enriched_content=enriched_content,
            enterprise_enrichment={"eii_status": "OUTER_FAIL", "error": str(outer_e)},
            run_ts=run_ts,
        )


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main() -> int:
    """
    CLI test: run EII against a synthetic item and report results.
    """
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [EII] %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Enterprise Intelligence Integration Layer — self-test"
    )
    parser.add_argument("--test", action="store_true", help="Run synthetic self-test")
    args = parser.parse_args()

    if args.test:
        logger.info("Running EII self-test with synthetic data...")
        result = integrate_intelligence(
            headline         = "Exploit for CVE-2026-9082 — Remote Code Execution",
            enriched_content = (
                "A critical vulnerability in example software allows unauthenticated "
                "remote code execution via heap overflow. CVSS 9.8. Affects versions "
                "prior to 3.2.1. Patch available. Exploit PoC published."
            ),
            source_url       = "https://vulners.com/test/CVE-2026-9082",
            extracted_iocs   = {
                "cve":    ["CVE-2026-9082"],
                "ipv4":   ["192.0.2.1"],
                "domain": ["malicious-test.example.com"],
            },
            risk_score   = 5.6,
            confidence   = 46.0,
            severity     = "MEDIUM",
            mitre_data   = [{"id": "T1203", "name": "Exploitation for Client Execution",
                              "tactic": "Execution", "confidence": "HIGH"}],
            actor_data   = {"tracking_id": "UNC-CDB-99", "confidence": 0},
            cvss_score   = None,
            epss_score   = None,
            kev_present  = False,
            tlp_label    = "TLP:GREEN",
        )
        import json
        print(json.dumps({
            "hard_block":      result.hard_block,
            "risk_score":      result.risk_score,
            "confidence":      result.confidence,
            "iocs_cleaned":    result.cleaned_iocs_dict,
            "techniques":      len(result.mitre_data),
            "publishable":     result.publishable,
            "quality_passed":  result.quality_passed,
            "quality_failed":  result.quality_failed,
        }, indent=2))
        logger.info("EII self-test COMPLETE")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
