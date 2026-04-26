"""
CYBERDUDEBIVASH® SENTINEL APEX — SOC Ticket Responder v1.0
===========================================================
Creates structured SOC incident tickets for P1/CRITICAL threats.

SAFE MODE: Writes ticket to data/auto_response/incidents/ as JSON.
LIVE MODE: POSTs ticket to configured ITSM/SIEM endpoint.

Ticket schema is STIX-aligned and SOC-ready:
  - Severity classification + priority
  - APEX intelligence (campaign, behavioral tags, AI summary)
  - IOC inventory (IPs, domains, hashes, URLs, CVEs)
  - MITRE ATT&CK tactics
  - Recommended action + SLA deadline
  - Full audit trail

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-SOC-TICKET")

ITSM_API_URL     = os.environ.get("CDB_ITSM_API_URL", "")
ITSM_API_KEY     = os.environ.get("CDB_ITSM_API_KEY", "")
RESPONSE_MODE    = os.environ.get("CDB_AUTO_RESPONSE_MODE", "safe").lower()

BASE_DIR         = Path(__file__).resolve().parent.parent.parent
INCIDENTS_DIR    = BASE_DIR / "data" / "auto_response" / "incidents"
TICKET_IDX_FILE  = BASE_DIR / "data" / "auto_response" / "ticket_index.json"

# SLA mapping by priority — aligned with AlertPrioritizer thresholds
# P1: 15 min  (CRITICAL — immediate response)
# P2: 1 hour  (HIGH — rapid response)
# P3: 4 hours (MEDIUM — standard response)
# P4: 24 hours(LOW — scheduled review)
_SLA_MAP = {
    "P1": timedelta(minutes=15),
    "P2": timedelta(hours=1),
    "P3": timedelta(hours=4),
    "P4": timedelta(hours=24),
}

# Risk score → priority thresholds (mirrors agent/soc/alert_prioritizer.py)
_RISK_PRIORITY_MAP = [
    (9.0, "P1"),
    (7.0, "P2"),
    (5.0, "P3"),
    (0.0, "P4"),
]


def _risk_to_priority(risk_score: float) -> str:
    """Derive P1-P4 priority from risk_score when APEX priority is unavailable."""
    for threshold, priority in _RISK_PRIORITY_MAP:
        if risk_score >= threshold:
            return priority
    return "P4"


def _ticket_id(stix_id: str) -> str:
    """Generate deterministic ticket ID from stix_id."""
    h = hashlib.md5(stix_id.encode()).hexdigest()[:8].upper()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"INC-{ts}-{h}"


def _load_ticket_index() -> Dict[str, str]:
    """Load ticket index: {stix_id: ticket_id}."""
    try:
        if not TICKET_IDX_FILE.exists():
            return {}
        with open(TICKET_IDX_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_ticket_index(index: Dict[str, str]) -> None:
    """Persist ticket index atomically."""
    try:
        TICKET_IDX_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(TICKET_IDX_FILE) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(json.dumps(index, indent=2).encode("utf-8"))
        os.replace(tmp, TICKET_IDX_FILE)
    except Exception as e:
        logger.warning(f"[SOC-TICKET] Index save failed (non-fatal): {e}")


def _build_ticket(payload: Dict) -> Dict:
    """
    Build structured SOC incident ticket from alert payload.

    Priority resolution order (highest precedence first):
      1. apex_priority from APEX intelligence (P1/P2/P3/P4)
      2. Derived from risk_score via _risk_to_priority()
      3. Fallback: P4 (should never reach here in practice)

    This ensures CRITICAL/risk=10.0 threats always get P1 tickets,
    not P4 tickets, regardless of whether APEX enrichment ran.
    """
    stix_id   = payload.get("stix_id", "")
    title     = payload.get("title", "Unknown Advisory")
    risk      = float(payload.get("risk_score", 0))
    severity  = payload.get("severity", "UNKNOWN")
    apex      = {k: v for k, v in payload.items() if k.startswith("apex_")}

    # Resolve priority — never fall through to P4 for high-risk threats
    apex_priority_raw = str(apex.get("apex_priority", "") or "")
    if apex_priority_raw in ("P1", "P2", "P3", "P4"):
        priority = apex_priority_raw
    else:
        # APEX priority absent or invalid — derive from risk_score
        priority = _risk_to_priority(risk)

    sla_delta = _SLA_MAP.get(priority, _SLA_MAP["P4"])
    now       = datetime.now(timezone.utc)

    return {
        "ticket_id":         _ticket_id(stix_id),
        "status":            "OPEN",
        "priority":          priority,
        "severity":          severity,
        "risk_score":        risk,
        "title":             title,
        "stix_id":           stix_id,
        "alert_id":          payload.get("alert_id", ""),
        "trigger":           payload.get("trigger", ""),
        # SLA
        "created_at":        now.isoformat(),
        "sla_deadline":      (now + sla_delta).isoformat(),
        "sla_minutes":       int(sla_delta.total_seconds() / 60),
        # APEX intelligence
        "apex_priority":     apex.get("apex_priority", ""),
        "apex_threat_level": apex.get("apex_threat_level", ""),
        "apex_campaign_id":  apex.get("apex_campaign_id", ""),
        "apex_category":     apex.get("apex_category", ""),
        "apex_behavioral_tags": apex.get("apex_behavioral_tags", []),
        "apex_recommended_action": apex.get("apex_action", ""),
        "apex_ai_summary":   apex.get("apex_ai_summary", ""),
        # IOC inventory
        "ioc_count":         payload.get("ioc_count", 0),
        "mitre_tactics":     payload.get("mitre_tactics", []),
        "kev_present":       payload.get("kev_present", False),
        "cvss_score":        payload.get("cvss_score"),
        "epss_score":        payload.get("epss_score"),
        "supply_chain":      payload.get("supply_chain", False),
        "actor_tag":         payload.get("actor_tag", ""),
        "feed_source":       payload.get("feed_source", ""),
        "blog_url":          payload.get("blog_url", ""),
        "source_url":        payload.get("source_url", ""),
        # Metadata
        "platform":          "CYBERDUDEBIVASH\u00ae Sentinel APEX",
        "auto_response_mode": RESPONSE_MODE,
        # Tier assignment and escalation path are priority-driven
        "assigned_to":       "SOC-TIER1" if priority in ("P3", "P4") else "SOC-TIER2",
        "escalation_path":   (
            ["SOC-TIER1", "SOC-TIER2", "INCIDENT-COMMANDER", "CISO-BRIDGE"]
            if priority == "P1"
            else ["SOC-TIER1", "SOC-TIER2", "INCIDENT-COMMANDER"]
            if priority == "P2"
            else ["SOC-TIER1", "SOC-TIER2"]
        ),
        "auto_escalate":     priority in ("P1", "P2"),
    }


def create_incident_ticket(payload: Dict) -> Dict:
    """
    Create SOC incident ticket for a critical threat.

    SAFE mode: Writes JSON ticket to data/auto_response/incidents/.
    LIVE mode: POSTs to ITSM API, falls back to file write on failure.

    Returns: {"ticket_id": str, "mode": str, "status": "created"|"duplicate"|"error"}
    """
    stix_id = payload.get("stix_id", "")
    if not stix_id:
        return {"ticket_id": "", "mode": RESPONSE_MODE, "status": "error",
                "reason": "missing_stix_id"}

    # Dedup — don't create duplicate tickets
    index = _load_ticket_index()
    if stix_id in index:
        existing = index[stix_id]
        logger.info(f"[SOC-TICKET] Duplicate skip — ticket {existing} exists for {stix_id[:30]}")
        return {"ticket_id": existing, "mode": RESPONSE_MODE, "status": "duplicate"}

    ticket = _build_ticket(payload)
    ticket_id = ticket["ticket_id"]

    if RESPONSE_MODE == "live" and ITSM_API_URL:
        try:
            import requests
            resp = requests.post(
                ITSM_API_URL,
                json=ticket,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": ITSM_API_KEY,
                    "X-Source": "CYBERDUDEBIVASH-SENTINEL-APEX",
                },
                timeout=10,
            )
            if resp.status_code in (200, 201, 202):
                logger.info(f"[SOC-TICKET] LIVE ticket created: {ticket_id} \u2192 HTTP {resp.status_code}")
            else:
                logger.warning(f"[SOC-TICKET] ITSM API HTTP {resp.status_code} \u2014 writing locally")
                _write_ticket_file(ticket)
        except Exception as e:
            logger.warning(f"[SOC-TICKET] ITSM call failed (non-fatal): {e} \u2014 writing locally")
            _write_ticket_file(ticket)
    else:
        # SAFE MODE: write to local file system
        _write_ticket_file(ticket)

    # Update index
    index[stix_id] = ticket_id
    _save_ticket_index(index)

    logger.info(
        f"[SOC-TICKET] Ticket created: {ticket_id} | "
        f"priority={ticket['priority']} | sla={ticket['sla_minutes']}min | "
        f"mode={RESPONSE_MODE}"
    )
    return {"ticket_id": ticket_id, "mode": RESPONSE_MODE, "status": "created",
            "priority": ticket["priority"], "sla_minutes": ticket["sla_minutes"]}


def _write_ticket_file(ticket: Dict) -> None:
    """Write ticket JSON to incidents directory. Never raises."""
    try:
        INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
        tid = ticket.get("ticket_id", "UNKNOWN")
        path = INCIDENTS_DIR / f"{tid}.json"
        raw = json.dumps(ticket, indent=2, default=str, ensure_ascii=False)
        with open(path, "wb") as f:
            f.write(raw.encode("utf-8"))
        logger.info(f"[SOC-TICKET] Ticket written: {path.name}")
    except Exception as e:
        logger.warning(f"[SOC-TICKET] File write failed (non-fatal): {e}")
