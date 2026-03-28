#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Auto Response Engine v1.0
===========================================================
Orchestrates automated SOC responses to P1/CRITICAL/CRITICAL_SURGE threats.

DETECTION CRITERIA (ALL three must be true):
  1. APEX priority == "P1"  OR  severity == "CRITICAL"  OR  risk_score >= 9.0
  2. APEX threat_level contains "CRITICAL_SURGE"  OR  kev_present == True
     OR  confidence >= CONFIDENCE_THRESHOLD (0.6)
  3. Advisory NOT already responded to (dedup TTL = 48h)

CONFIG FLAGS (GitHub repo variables):
  CDB_AUTO_RESPONSE_ENABLED = true|false   (default: true)
  CDB_AUTO_RESPONSE_MODE    = safe|live    (default: safe)
    safe = log + write files, zero system changes
    live = execute real firewall blocks + ITSM tickets

RESPONDERS (all optional, all isolated):
  1. Firewall — block malicious IPs (safe: logs commands / live: API call)
  2. SOC Ticket — create incident (safe: JSON file / live: ITSM API)

INTEGRATION:
  Called from sentinel_blogger.py AFTER alert engine [R-09]
  Returns result dict — never raises, never blocks pipeline.

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-RESPONSE-ENGINE")

# ── Configuration ─────────────────────────────────────────────────────────────
AUTO_RESPONSE_ENABLED    = os.environ.get("CDB_AUTO_RESPONSE_ENABLED", "true").lower() in ("true","1","yes")
RESPONSE_MODE            = os.environ.get("CDB_AUTO_RESPONSE_MODE", "safe").lower()
CONFIDENCE_THRESHOLD     = float(os.environ.get("CDB_RESPONSE_CONFIDENCE", "0.6"))
MAX_RESPONSES_PER_RUN    = int(os.environ.get("CDB_MAX_RESPONSES_PER_RUN", "5"))
RESPONSE_DEDUP_TTL_HOURS = int(os.environ.get("CDB_RESPONSE_TTL_HOURS", "48"))

BASE_DIR          = Path(__file__).resolve().parent.parent
MANIFEST_PATH     = BASE_DIR / "data" / "stix" / "feed_manifest.json"
RESPONSE_STATE    = BASE_DIR / "data" / "auto_response" / "response_state.json"


# ── Response State (Deduplication) ────────────────────────────────────────────

def _load_response_state() -> Dict[str, str]:
    """Load response state: {stix_id: iso_timestamp}."""
    try:
        if not RESPONSE_STATE.exists():
            return {}
        with open(RESPONSE_STATE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_response_state(state: Dict[str, str]) -> None:
    """Persist response state atomically."""
    try:
        RESPONSE_STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(RESPONSE_STATE) + ".tmp"
        raw = json.dumps(state, indent=2, ensure_ascii=False)
        with open(tmp, "wb") as f:
            f.write(raw.encode("utf-8"))
        os.replace(tmp, RESPONSE_STATE)
    except Exception as e:
        logger.warning(f"[RESPONSE-ENGINE] State save failed (non-fatal): {e}")


def _already_responded(stix_id: str, state: Dict[str, str]) -> bool:
    """True if this advisory was already responded to within TTL."""
    ts = state.get(stix_id)
    if not ts:
        return False
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt > datetime.now(timezone.utc) - timedelta(hours=RESPONSE_DEDUP_TTL_HOURS)
    except Exception:
        return False


# ── Detection (Compound Multi-Signal) ─────────────────────────────────────────

def _needs_response(entry: Dict) -> bool:
    """
    Three-layer compound detection.
    All conditions evaluated safely — never raises.

    CONDITION 1 (PRIMARY SIGNAL — any one):
      - APEX priority == P1
      - severity == CRITICAL
      - risk_score >= 9.0

    CONDITION 2 (CONFIRMATION SIGNAL — any one):
      - APEX threat_level contains CRITICAL_SURGE
      - kev_present == True
      - confidence_score >= CONFIDENCE_THRESHOLD (0.6 = 60%)

    CONDITION 3: Advisory has at least a stix_id (can be tracked)
    """
    try:
        risk      = float(entry.get("risk_score", 0))
        sev       = str(entry.get("severity", "")).upper()
        apex      = entry.get("apex") or {}
        prio      = str(apex.get("priority", "")).upper()
        tlevel    = str(apex.get("threat_level", "")).upper()
        conf_raw  = entry.get("confidence_score") or entry.get("confidence") or 0
        try:
            conf = float(conf_raw) / 100.0 if float(conf_raw) > 1 else float(conf_raw)
        except Exception:
            conf = 0.0

        # Condition 1: Primary critical signal
        c1 = (prio == "P1" or sev == "CRITICAL" or risk >= 9.0)
        if not c1:
            return False

        # Condition 2: Confirmation signal
        c2 = (
            "CRITICAL_SURGE" in tlevel or
            bool(entry.get("kev_present")) or
            conf >= CONFIDENCE_THRESHOLD
        )
        if not c2:
            return False

        # Condition 3: Trackable
        return bool(entry.get("stix_id"))

    except Exception:
        return False


# ── IOC Extraction from STIX File ─────────────────────────────────────────────

def _extract_iocs_from_stix(entry: Dict) -> Dict[str, List[str]]:
    """
    Extract IOC lists from the STIX bundle file for the advisory.
    Returns {"ipv4": [...], "domain": [...], "sha256": [...], "url": [...]}
    Falls back gracefully if file missing or malformed.
    """
    iocs: Dict[str, List] = {"ipv4": [], "domain": [], "sha256": [], "url": []}
    stix_file = entry.get("stix_file", "")
    if not stix_file:
        return iocs
    stix_path = BASE_DIR / "data" / "stix" / stix_file
    if not stix_path.exists():
        return iocs
    try:
        with open(stix_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        for obj in bundle.get("objects", []):
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            # Parse STIX patterns: [ipv4-addr:value = '1.2.3.4']
            import re
            for ip in re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern):
                iocs["ipv4"].append(ip)
            for domain in re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern):
                iocs["domain"].append(domain)
            for sha in re.findall(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'", pattern):
                iocs["sha256"].append(sha)
            for url in re.findall(r"url:value\s*=\s*'([^']+)'", pattern):
                iocs["url"].append(url)
    except Exception as e:
        logger.debug(f"[RESPONSE-ENGINE] STIX IOC extract failed (non-fatal): {e}")
    return iocs


# ── Responder Dispatcher ──────────────────────────────────────────────────────

def _dispatch_responders(entry: Dict, alert_payload: Dict) -> Dict:
    """
    Execute all configured responders for one advisory.
    Each responder runs in isolation — one failure never stops others.
    """
    results = {}

    # ── Responder 1: Firewall IP Block ──────────────────────────────────────
    try:
        from agent.auto_response.firewall import block_malicious_ips
        iocs = _extract_iocs_from_stix(entry)
        ips  = iocs.get("ipv4", [])
        if ips:
            fw_result = block_malicious_ips(
                ips=ips,
                reason=entry.get("title", "")[:100],
                alert_id=alert_payload.get("alert_id", ""),
            )
            results["firewall"] = fw_result
            logger.info(
                f"[RESPONSE-ENGINE] Firewall: blocked={len(fw_result.get('blocked',[]))} "
                f"skipped={len(fw_result.get('skipped',[]))} mode={fw_result.get('mode')}"
            )
        else:
            results["firewall"] = {"status": "no_ips", "blocked": [], "skipped": []}
            logger.debug(f"[RESPONSE-ENGINE] No IPs to block for: {entry.get('title','')[:50]}")
    except Exception as e:
        results["firewall"] = {"status": "error", "error": str(e)[:100]}
        logger.warning(f"[RESPONSE-ENGINE] Firewall responder failed (non-fatal): {e}")

    # ── Responder 2: SOC Ticket ──────────────────────────────────────────────
    try:
        from agent.auto_response.soc_ticket import create_incident_ticket
        ticket_result = create_incident_ticket(alert_payload)
        results["soc_ticket"] = ticket_result
        logger.info(
            f"[RESPONSE-ENGINE] SOC Ticket: id={ticket_result.get('ticket_id','')} "
            f"status={ticket_result.get('status','')} "
            f"priority={ticket_result.get('priority','')} "
            f"sla={ticket_result.get('sla_minutes','')}min"
        )
    except Exception as e:
        results["soc_ticket"] = {"status": "error", "error": str(e)[:100]}
        logger.warning(f"[RESPONSE-ENGINE] SOC ticket responder failed (non-fatal): {e}")

    return results


# ── Alert Payload Builder (mirrors alert_engine.py shape) ─────────────────────

def _build_payload(entry: Dict) -> Dict:
    """Build alert payload from manifest entry for responders."""
    apex  = entry.get("apex") or {}
    stix  = entry.get("stix_id", "")
    risk  = float(entry.get("risk_score", 0))
    h     = stix[-8:].upper() if stix else "UNKNOWN"
    return {
        "alert_id":           f"CDB-ALERT-{h}",
        "stix_id":            stix,
        "title":              entry.get("title", "")[:200],
        "risk_score":         risk,
        "severity":           entry.get("severity", ""),
        "trigger":            "AUTO_RESPONSE",
        "blog_url":           entry.get("blog_url", ""),
        "source_url":         entry.get("source_url", ""),
        "kev_present":        bool(entry.get("kev_present")),
        "cvss_score":         entry.get("cvss_score"),
        "epss_score":         entry.get("epss_score"),
        "actor_tag":          entry.get("actor_tag", ""),
        "feed_source":        entry.get("feed_source", ""),
        "supply_chain":       bool(entry.get("supply_chain", False)),
        "mitre_tactics":      (entry.get("mitre_tactics") or [])[:5],
        "ioc_count":          sum(v for v in (entry.get("ioc_counts") or {}).values()
                                  if isinstance(v, int)),
        "confidence_score":   entry.get("confidence_score", 0),
        "apex_priority":      apex.get("priority", "P4"),
        "apex_threat_level":  apex.get("threat_level", ""),
        "apex_campaign_id":   apex.get("campaign_id", ""),
        "apex_category":      apex.get("threat_category", ""),
        "apex_behavioral_tags": apex.get("behavioral_tags", []),
        "apex_action":        apex.get("recommended_action", ""),
        "apex_ai_summary":    apex.get("ai_summary", "")[:300],
    }


# ── Main Entry Point ──────────────────────────────────────────────────────────

def run_response_engine(manifest: Optional[List[Dict]] = None) -> Dict:
    """
    Main auto-response orchestrator.

    Reads manifest, detects response-worthy threats,
    deduplicates, dispatches firewall + SOC ticket responders.

    CALL AFTER alert engine [R-09] in sentinel_blogger.py.

    Returns:
        {"responses_executed": int, "skipped_dedup": int,
         "total_detected": int, "mode": str, "status": str}
    """
    if not AUTO_RESPONSE_ENABLED:
        logger.info(f"[RESPONSE-ENGINE] Disabled via CDB_AUTO_RESPONSE_ENABLED=false")
        return {"responses_executed": 0, "skipped_dedup": 0,
                "total_detected": 0, "mode": RESPONSE_MODE, "status": "DISABLED"}

    result = {
        "responses_executed": 0,
        "skipped_dedup":      0,
        "total_detected":     0,
        "mode":               RESPONSE_MODE,
        "status":             "OK",
    }

    logger.info(f"[RESPONSE-ENGINE] Starting | mode={RESPONSE_MODE} | "
                f"confidence_threshold={CONFIDENCE_THRESHOLD}")

    try:
        # Load manifest
        if manifest is None:
            if not MANIFEST_PATH.exists():
                result["status"] = "NO_MANIFEST"
                return result
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest = json.load(f)

        if not isinstance(manifest, list) or not manifest:
            result["status"] = "NO_DATA"
            return result

        # Detect response-worthy entries
        targets = sorted(
            [e for e in manifest if _needs_response(e)],
            key=lambda x: float(x.get("risk_score", 0)),
            reverse=True,
        )
        result["total_detected"] = len(targets)

        if not targets:
            logger.info("[RESPONSE-ENGINE] No entries meet response criteria this run")
            result["status"] = "NO_TARGETS"
            return result

        logger.info(f"[RESPONSE-ENGINE] Detected {len(targets)} response targets")

        state     = _load_response_state()
        responses = 0
        skipped   = 0

        for entry in targets:
            if responses >= MAX_RESPONSES_PER_RUN:
                logger.info(f"[RESPONSE-ENGINE] MAX_RESPONSES_PER_RUN={MAX_RESPONSES_PER_RUN} reached")
                break

            stix_id = entry.get("stix_id", "")
            if not stix_id:
                continue

            if _already_responded(stix_id, state):
                skipped += 1
                continue

            payload = _build_payload(entry)
            resp_result = _dispatch_responders(entry, payload)

            state[stix_id] = datetime.now(timezone.utc).isoformat()
            responses += 1
            logger.info(
                f"[RESPONSE-ENGINE] Response executed: {entry.get('title','')[:60]} | "
                f"risk={entry.get('risk_score',0):.1f} | "
                f"responders={list(resp_result.keys())}"
            )

        _save_response_state(state)

        result["responses_executed"] = responses
        result["skipped_dedup"]      = skipped

        logger.info(
            f"[RESPONSE-ENGINE] Complete | mode={RESPONSE_MODE} | "
            f"executed={responses} | dedup_skip={skipped} | "
            f"total_detected={len(targets)}"
        )

    except Exception as e:
        logger.error(f"[RESPONSE-ENGINE] Engine error (pipeline safe): {e}")
        result["status"] = "ERROR"

    return result


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [RESPONSE-ENGINE] %(message)s")
    result = run_response_engine()
    print(json.dumps(result, indent=2))
    sys.exit(0)
