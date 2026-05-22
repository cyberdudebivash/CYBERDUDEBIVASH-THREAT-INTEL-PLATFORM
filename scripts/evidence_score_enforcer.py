#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v146.0.0
EVIDENCE-WEIGHTED CONFIDENCE SCORE ENFORCER
===============================================================================
PURPOSE:
  Eliminates confidence inflation by enforcing evidence-backed risk scoring.
  Items claiming risk=10 (CRITICAL) must have corroborating evidence.
  Without evidence, the score is capped to prevent false-positive CRITICAL alerts.

EVIDENCE HIERARCHY (each tier unlocks a higher max score):
  Tier 5 — MAX 10.0:  KEV confirmed + active exploit + EPSS >= 50%
  Tier 4 — MAX 9.5:   KEV OR (exploit + EPSS >= 25%)
  Tier 3 — MAX 8.5:   CVSS >= 9.0 OR EPSS >= 10% OR IOC count >= 20
  Tier 2 — MAX 7.5:   CVSS >= 7.0 OR EPSS >= 1% OR IOC count >= 5
  Tier 1 — MAX 6.5:   Any CVSS/EPSS present
  Tier 0 — MAX 5.5:   No quantifiable evidence (title/actor only)

ENFORCEMENT POLICY:
  - Score is LOWERED if claimed risk exceeds tier maximum
  - Score is NEVER raised (no artificial boosting)
  - All adjustments are logged with full audit trail
  - Original scores are preserved in adjustment_log for auditability
  - Idempotent: re-running on already-corrected feed is safe

OUTPUTS:
  api/feed.json                                  — corrected feed (atomic)
  data/governance/evidence_score_enforcement.json — enforcement audit log

EXIT CODES:
  0 — OK (0 adjustments or all within tolerance)
  1 — FATAL (feed unreadable or write failed)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [evidence_enforcer] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-EVIDENCE-ENFORCER")

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = pathlib.Path(__file__).resolve().parent.parent
FEED_PATH   = REPO_ROOT / "api" / "feed.json"
API_FEED    = REPO_ROOT / "api" / "feed.json"   # same; kept explicit for clarity
GOV_DIR     = REPO_ROOT / "data" / "governance"
REPORT_PATH = GOV_DIR / "evidence_score_enforcement.json"

VERSION = "160.1.0"  # v160.1.0: EPSS normalization + governance field backfill

# ── Evidence Tier Thresholds ──────────────────────────────────────────────────
# (min_score_claim, max_allowed_without_evidence)
EVIDENCE_TIERS = [
    # (label,         max_score, kev_req, exploit_req, epss_min, cvss_min, ioc_min)
    ("TIER5_CONFIRMED", 10.0, True,  True,  50.0, None, None),
    ("TIER4_STRONG",     9.5, True,  False, 25.0, None, None),
    ("TIER3_SOLID",      8.5, False, False, 10.0, 9.0,  20),
    ("TIER2_MODERATE",   7.5, False, False,  1.0, 7.0,   5),
    ("TIER1_MINIMAL",    6.5, False, False,  0.0, 0.1,   1),
    ("TIER0_NONE",       5.5, False, False,  None,None,  None),  # fallback
]

INFLATION_THRESHOLD = 9.0  # only check items claiming >= this score


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: pathlib.Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".esc_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def normalize_epss(raw: Any) -> float:
    """
    Normalize EPSS to a 0–100 percentage scale.
    EPSS is officially 0.0–1.0 probability, but enrichment pipelines often
    store it as percentage (0–100) or mis-multiplied (e.g. 9043 instead of 90.43).
    Rules:
      0.0–1.0   → multiply by 100 (fraction → pct)
      1.0–100   → use as-is (already a percentage)
      100–10000 → divide by 100 (stored as pct*100, e.g. 9043 → 90.43)
      >10000    → clamp to 99.99 (nonsensical value, treat as very high)
      negative  → -1.0 (unknown)
    """
    v = _safe_float(raw, -1.0)
    if v < 0:
        return -1.0
    if v == 0.0:
        return 0.0
    if v <= 1.0:
        return round(v * 100.0, 4)
    if v <= 100.0:
        return round(v, 4)
    if v <= 10000.0:
        return round(v / 100.0, 4)   # e.g. 9043 → 90.43
    return 99.99   # clamp absurd values


def compute_evidence_tier(item: Dict[str, Any]) -> Tuple[str, float]:
    """Return (tier_label, max_allowed_score) for this item based on evidence."""
    kev = bool(
        item.get("kev") or item.get("kev_confirmed") or item.get("kev_present") or
        str(item.get("in_kev", "")).upper() in ("YES", "TRUE", "1")
    )
    exploit   = bool(item.get("exploit_available") or item.get("has_exploit"))
    epss_raw  = item.get("epss_score") or item.get("epss") or item.get("epss_pct")
    epss      = normalize_epss(epss_raw)   # always 0–100 pct after this

    cvss_raw  = item.get("cvss_score") or item.get("cvss") or item.get("cvss_v3")
    cvss      = _safe_float(cvss_raw, -1.0)

    ioc_count = int(item.get("ioc_count", 0) or 0)

    # Tier 5
    if kev and exploit and epss >= 50.0:
        return "TIER5_CONFIRMED", 10.0

    # Tier 4
    if kev or (exploit and epss >= 25.0):
        return "TIER4_STRONG", 9.5

    # Tier 3
    if (cvss >= 9.0) or (epss >= 10.0) or (ioc_count >= 20):
        return "TIER3_SOLID", 8.5

    # Tier 2
    if (cvss >= 7.0) or (0.0 <= epss < 10.0 and epss >= 1.0) or (ioc_count >= 5):
        return "TIER2_MODERATE", 7.5

    # Tier 1
    if cvss > 0 or (epss >= 0.0 and epss_raw is not None):
        return "TIER1_MINIMAL", 6.5

    # Tier 0 — no quantifiable evidence
    return "TIER0_NONE", 5.5


def backfill_governance_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Backfill governance-required fields that may be missing due to enrichment
    pipeline field-name mismatches. This ensures the governance engine can find
    evidence correctly without treating properly-evidenced items as inflation.

    Fields backfilled:
      cve_id      -- singular primary CVE from the 'cve' array (governance expects this)
      kev_present -- bool, derived from any KEV indicator field
      cvss_score  -- copy from 'cvss' alias if 'cvss_score' absent
      epss_score  -- normalized 0-100 pct (fixes 9043→90.43 format errors)
    """
    item = dict(item)

    # cve_id: governance engine uses this singular field; pipeline may produce 'cve' array
    if not item.get("cve_id"):
        cve_list = item.get("cve") or item.get("cves") or []
        if isinstance(cve_list, list) and cve_list:
            item["cve_id"] = cve_list[0]
        elif isinstance(cve_list, str) and cve_list.startswith("CVE-"):
            item["cve_id"] = cve_list

    # kev_present: normalize any KEV indicator to bool field
    if "kev_present" not in item:
        kev_val = (item.get("kev") or item.get("kev_confirmed") or
                   item.get("in_kev") or item.get("cisa_kev"))
        item["kev_present"] = bool(
            kev_val and str(kev_val).upper() not in ("FALSE", "NO", "0", "NONE", "NULL", "")
        )

    # cvss_score: unify 'cvss' alias
    if not item.get("cvss_score") and item.get("cvss"):
        item["cvss_score"] = item["cvss"]

    # epss_score: normalize malformed values (9043 → 90.43)
    raw_epss = item.get("epss_score") or item.get("epss")
    if raw_epss is not None:
        normalized = normalize_epss(raw_epss)
        if normalized >= 0:
            item["epss_score"] = normalized  # always write normalized value back

    return item


def enforce_feed(items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Apply evidence-weighted enforcement. Returns (corrected_items, adjustment_log)."""
    corrected: List[Dict[str, Any]] = []
    adjustment_log: List[Dict[str, Any]] = []

    for item in items:
        # Always backfill governance fields (normalizes EPSS, maps cve→cve_id, etc.)
        item = backfill_governance_fields(item)

        risk_raw    = item.get("risk_score") or item.get("score") or 0
        risk_score  = _safe_float(risk_raw, 0.0)

        if risk_score < INFLATION_THRESHOLD:
            corrected.append(item)
            continue

        tier_label, max_score = compute_evidence_tier(item)

        if risk_score <= max_score:
            # Within evidence tier — no adjustment needed
            corrected.append(item)
            continue

        # Inflation detected — cap to tier maximum
        new_score = round(min(risk_score, max_score), 1)
        adj = {
            "stix_id"        : item.get("stix_id") or item.get("id", ""),
            "title"          : (item.get("title") or "")[:120],
            "original_score" : risk_score,
            "corrected_score": new_score,
            "evidence_tier"  : tier_label,
            "max_allowed"    : max_score,
            "delta"          : round(risk_score - new_score, 1),
            "kev"            : bool(item.get("kev") or item.get("kev_confirmed") or item.get("kev_present")),
            "exploit"        : bool(item.get("exploit_available") or item.get("has_exploit")),
            "epss"           : _safe_float(item.get("epss_score"), -1),
            "cvss"           : _safe_float(item.get("cvss_score") or item.get("cvss"), -1),
            "ioc_count"      : int(item.get("ioc_count", 0) or 0),
            "timestamp"      : now_iso(),
        }
        adjustment_log.append(adj)

        corrected_item = dict(item)
        corrected_item["risk_score"]          = new_score
        corrected_item["_evidence_tier"]      = tier_label
        corrected_item["_score_adjusted"]     = True
        corrected_item["_original_risk_score"]= risk_score
        corrected.append(corrected_item)

        log.warning(
            "[INFLATION] %s | score %.1f→%.1f | tier=%s | kev=%s exploit=%s epss=%s cvss=%s ioc=%d",
            adj["title"][:60], risk_score, new_score, tier_label,
            adj["kev"], adj["exploit"], adj["epss"], adj["cvss"], adj["ioc_count"]
        )

    return corrected, adjustment_log


def main() -> int:
    t0 = time.monotonic()
    log.info("=" * 66)
    log.info("SENTINEL APEX %s -- Evidence Score Enforcer", VERSION)
    log.info("Feed: %s", FEED_PATH)
    log.info("Enhancements: EPSS normalization + governance field backfill")
    log.info("=" * 66)

    # Load feed
    if not FEED_PATH.exists():
        log.error("[FATAL] Feed not found: %s", FEED_PATH)
        return 1
    try:
        with open(FEED_PATH, encoding="utf-8", errors="replace") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        log.error("[FATAL] Feed JSON parse error: %s", e)
        return 1

    if not isinstance(raw, list):
        log.error("[FATAL] Feed is not a JSON array")
        return 1

    log.info("Loaded %d items", len(raw))

    # Count items that could be inflated (claimed >= threshold)
    candidates = [i for i in raw if _safe_float(i.get("risk_score", 0)) >= INFLATION_THRESHOLD]
    log.info("Checking %d items claiming risk >= %.1f", len(candidates), INFLATION_THRESHOLD)

    # Enforce
    corrected, adj_log = enforce_feed(raw)

    # Summary
    n_adj = len(adj_log)
    log.info("=" * 66)
    log.info("ENFORCEMENT RESULT: %d adjustments in %d items", n_adj, len(raw))
    if n_adj == 0:
        log.info("[PASS] No confidence inflation detected")
    else:
        for adj in adj_log:
            log.info("  [FIX] %s | %.1f→%.1f (%s)",
                     adj["title"][:60], adj["original_score"],
                     adj["corrected_score"], adj["evidence_tier"])
    log.info("=" * 66)

    runtime = round(time.monotonic() - t0, 3)

    # Write corrected feed atomically
    # Always write: backfill_governance_fields normalizes EPSS/fields even if no score adjustments
    feed_str = json.dumps(corrected, ensure_ascii=False, indent=None, separators=(",", ":"))
    atomic_write(FEED_PATH, feed_str)
    log.info("[WRITE] Feed written: %s (%d items, %d score adjustments, fields normalized)",
             FEED_PATH, len(corrected), n_adj)

    # Write enforcement report
    report = {
        "schema_version"      : "1.0",
        "generated_at"        : now_iso(),
        "generator"           : "evidence_score_enforcer.py",
        "version"             : VERSION,
        "feed_path"           : str(FEED_PATH),
        "total_items"         : len(raw),
        "candidates_checked"  : len(candidates),
        "adjustments_made"    : n_adj,
        "inflation_threshold" : INFLATION_THRESHOLD,
        "overall_pass"        : n_adj == 0,
        "runtime_seconds"     : runtime,
        "adjustment_log"      : adj_log,
    }
    GOV_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(REPORT_PATH, json.dumps(report, ensure_ascii=False, indent=2))
    log.info("[WRITE] Enforcement report: %s", REPORT_PATH)

    return 0


if __name__ == "__main__":
    sys.exit(main())
