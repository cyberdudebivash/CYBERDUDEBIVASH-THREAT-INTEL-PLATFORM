#!/usr/bin/env python3
"""
api/enterprise.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Enterprise Lead Capture v1.0
=================================================================
Handles enterprise prospect lead capture and qualification.

Endpoint: POST /api/enterprise/lead
Fields:   name, company, email, use_case, [employees, budget_range, timeline]

Actions:
  1. Validate and sanitize input
  2. Store lead to data/leads.json (atomic write via safe_io)
  3. Log to data/logs/enterprise_leads.jsonl
  4. Optional: send Telegram notification if TELEGRAM_BOT_TOKEN set
  5. Optional: trigger GUMROAD_ACCESS_TOKEN demo provisioning

Lead scoring:
  HIGH   -- enterprise keywords + budget mentioned
  MEDIUM -- company + valid email
  LOW    -- minimal info

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-ENTERPRISE")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR       = Path(__file__).resolve().parent.parent
DATA_DIR       = BASE_DIR / "data"
LEADS_FILE     = DATA_DIR / "leads.json"
LEADS_LOG      = DATA_DIR / "logs" / "enterprise_leads.jsonl"

# ---------------------------------------------------------------------------
# Lead scoring keywords
# ---------------------------------------------------------------------------
HIGH_VALUE_KEYWORDS = frozenset({
    "soc", "siem", "mssp", "enterprise", "government", "federal",
    "bank", "financial", "healthcare", "critical infrastructure",
    "red team", "threat hunting", "incident response", "ciso",
    "10000", "50000", "100000", "unlimited", "annual",
})

MEDIUM_VALUE_KEYWORDS = frozenset({
    "security", "analyst", "team", "compliance", "audit",
    "penetration", "pentest", "threat intel", "vulnerability",
    "startup", "smb", "managed",
})


# ---------------------------------------------------------------------------
# Safe atomic write (no dependency on safe_io to keep module standalone)
# ---------------------------------------------------------------------------
def _atomic_json_write(path: Path, data: Any) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        tmp.rename(path)
        return True
    except Exception as e:
        logger.error("_atomic_json_write failed %s: %s", path.name, e)
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def _safe_load_json(path: Path, default: Any = None) -> Any:
    try:
        if path.exists() and path.stat().st_size > 0:
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("_safe_load_json %s: %s", path.name, e)
    return default if default is not None else {}


def _append_lead_log(entry: Dict) -> None:
    LEADS_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(LEADS_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        logger.warning("Lead log append failed: %s", e)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_SAFE_STR = re.compile(r"[<>\"';&|`$\\]")

MAX_FIELD_LEN = 500


def _sanitize(value: Any, max_len: int = MAX_FIELD_LEN) -> str:
    if not isinstance(value, str):
        value = str(value)
    value = _SAFE_STR.sub("", value).strip()
    return value[:max_len]


def validate_lead_payload(payload: Dict) -> Tuple[bool, str, Dict]:
    """
    Validate and sanitize lead payload.
    Returns (is_valid, error_message, sanitized_payload).
    """
    errors: List[str] = []

    name     = _sanitize(payload.get("name", ""))
    company  = _sanitize(payload.get("company", ""))
    email    = _sanitize(payload.get("email", ""))
    use_case = _sanitize(payload.get("use_case", ""))

    if not name or len(name) < 2:
        errors.append("name: required, min 2 characters")
    if not company or len(company) < 2:
        errors.append("company: required, min 2 characters")
    if not email or not _EMAIL_RE.match(email):
        errors.append("email: valid email address required")
    if not use_case or len(use_case) < 10:
        errors.append("use_case: required, min 10 characters")

    if errors:
        return False, "; ".join(errors), {}

    sanitized = {
        "name":         name,
        "company":      company,
        "email":        email,
        "use_case":     use_case,
        "employees":    _sanitize(payload.get("employees", ""), 50),
        "budget_range": _sanitize(payload.get("budget_range", ""), 100),
        "timeline":     _sanitize(payload.get("timeline", ""), 100),
        "phone":        _sanitize(payload.get("phone", ""), 30),
        "website":      _sanitize(payload.get("website", ""), 200),
    }
    return True, "", sanitized


# ---------------------------------------------------------------------------
# Lead scoring
# ---------------------------------------------------------------------------
def score_lead(payload: Dict) -> Tuple[str, int]:
    """
    Score a lead based on payload content.
    Returns (tier: HIGH|MEDIUM|LOW, score: 0-100).
    """
    text = " ".join([
        payload.get("company", ""),
        payload.get("use_case", ""),
        payload.get("employees", ""),
        payload.get("budget_range", ""),
    ]).lower()

    score = 0
    for kw in HIGH_VALUE_KEYWORDS:
        if kw in text:
            score += 15
    for kw in MEDIUM_VALUE_KEYWORDS:
        if kw in text:
            score += 5

    # Email domain bonus (non-gmail/yahoo = business)
    email = payload.get("email", "")
    if email and not any(d in email for d in ("gmail", "yahoo", "hotmail", "outlook")):
        score += 10

    # Use case length bonus (detailed = serious)
    use_len = len(payload.get("use_case", ""))
    if use_len > 200:
        score += 10
    elif use_len > 100:
        score += 5

    score = min(score, 100)
    tier  = "HIGH" if score >= 40 else "MEDIUM" if score >= 15 else "LOW"
    return tier, score


# ---------------------------------------------------------------------------
# Lead ID
# ---------------------------------------------------------------------------
def _lead_id(email: str) -> str:
    ts  = int(time.time())
    raw = f"{email}:{ts}"
    return "LEAD-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


# ---------------------------------------------------------------------------
# Telegram notification
# ---------------------------------------------------------------------------
def _send_telegram_notification(lead: Dict) -> bool:
    """Send enterprise lead notification via Telegram if configured."""
    token   = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return False

    try:
        import urllib.request
        import urllib.parse

        tier, score = score_lead(lead)
        emoji = {"HIGH": "🔥", "MEDIUM": "⚡", "LOW": "📩"}.get(tier, "📩")
        msg = (
            f"{emoji} *New Enterprise Lead [{tier}]*\n"
            f"Name: {lead.get('name')}\n"
            f"Company: {lead.get('company')}\n"
            f"Email: {lead.get('email')}\n"
            f"Score: {score}/100\n"
            f"Use Case: {lead.get('use_case', '')[:100]}\n"
            f"Lead ID: {lead.get('lead_id')}\n"
            f"Time: {lead.get('captured_at')}"
        )
        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = urllib.parse.urlencode({
            "chat_id":    chat_id,
            "text":       msg,
            "parse_mode": "Markdown",
        }).encode()
        req = urllib.request.Request(url, data=payload, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as e:
        logger.warning("Telegram notification failed (non-fatal): %s", e)
        return False


# ---------------------------------------------------------------------------
# Lead storage
# ---------------------------------------------------------------------------
def store_lead(sanitized: Dict) -> Tuple[bool, str, Dict]:
    """
    Store a validated lead to leads.json and JSONL log.
    Returns (success, message, lead_record).
    """
    now     = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tier, score = score_lead(sanitized)
    lead_id = _lead_id(sanitized.get("email", ""))

    lead_record: Dict[str, Any] = {
        "lead_id":     lead_id,
        "captured_at": now,
        "score":       score,
        "lead_tier":   tier,
        **sanitized,
    }

    # Load existing leads
    data   = _safe_load_json(LEADS_FILE, default={"leads": [], "version": "1.0"})
    leads  = data.get("leads", [])

    # Dedup by email (update if exists)
    existing_idx = next((i for i, l in enumerate(leads) if l.get("email") == sanitized.get("email")), None)
    if existing_idx is not None:
        lead_record["updated_at"] = now
        lead_record["lead_id"] = leads[existing_idx].get("lead_id", lead_id)
        leads[existing_idx] = lead_record
        is_new = False
    else:
        leads.append(lead_record)
        is_new = True

    data["leads"] = leads
    data["total"] = len(leads)
    data["last_updated"] = now

    ok = _atomic_json_write(LEADS_FILE, data)
    if not ok:
        return False, "Failed to store lead — please retry", {}

    # Append to JSONL log
    _append_lead_log({**lead_record, "event": "lead.created" if is_new else "lead.updated"})

    # Telegram notification (non-fatal)
    _send_telegram_notification(lead_record)

    logger.info("Lead stored: %s tier=%s score=%d company=%s new=%s",
                lead_id, tier, score, sanitized.get("company"), is_new)

    return True, "Lead captured successfully", lead_record


# ---------------------------------------------------------------------------
# Main handler (framework-agnostic)
# ---------------------------------------------------------------------------
def handle_lead_request(payload: Dict) -> Tuple[int, Dict]:
    """
    Handle POST /api/enterprise/lead request.
    Returns (http_status_code, response_dict).

    Framework-agnostic: wire into FastAPI/Flask/Cloudflare Worker.
    """
    # Validate
    valid, error_msg, sanitized = validate_lead_payload(payload)
    if not valid:
        return 400, {
            "success": False,
            "error": "validation_error",
            "details": error_msg,
        }

    # Store
    ok, message, record = store_lead(sanitized)
    if not ok:
        return 500, {
            "success": False,
            "error": "storage_error",
            "message": message,
        }

    tier_label = record.get("lead_tier", "MEDIUM")
    next_steps = {
        "HIGH": (
            "Our enterprise team will contact you within 2 business hours "
            "with a customized demo and pricing proposal."
        ),
        "MEDIUM": (
            "We will reach out within 1 business day to schedule a demo "
            "tailored to your security operations."
        ),
        "LOW": (
            "Thank you for your interest. We will be in touch "
            "within 2-3 business days."
        ),
    }

    return 200, {
        "success":     True,
        "lead_id":     record.get("lead_id"),
        "message":     message,
        "lead_score":  record.get("score"),
        "next_steps":  next_steps.get(tier_label, next_steps["LOW"]),
        "demo_url":    "https://intel.cyberdudebivash.com/api",
        "contact":     "enterprise@cyberdudebivash.in",
    }


def get_leads_summary() -> Dict:
    """Admin: return lead summary stats."""
    data  = _safe_load_json(LEADS_FILE, default={"leads": []})
    leads = data.get("leads", [])
    by_tier: Dict[str, int] = {}
    for lead in leads:
        t = lead.get("lead_tier", "LOW")
        by_tier[t] = by_tier.get(t, 0) + 1
    return {
        "total_leads":  len(leads),
        "by_tier":      by_tier,
        "last_updated": data.get("last_updated"),
    }


# ---------------------------------------------------------------------------
# CLI harness
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _payload = {
        "name":      "Jane Smith",
        "company":   "ACME Financial Corp",
        "email":     "jane.smith@acmefinancial.com",
        "use_case":  "We need enterprise threat intelligence for our SOC team of 25 analysts. "
                     "Looking for SIEM integration, IOC feeds, and detection rules for our MSSP operations.",
        "employees": "1000-5000",
        "budget_range": "$50,000-$100,000/year",
    }
    status, resp = handle_lead_request(_payload)
    import json as _json
    print(f"HTTP {status}")
    print(_json.dumps(resp, indent=2))
