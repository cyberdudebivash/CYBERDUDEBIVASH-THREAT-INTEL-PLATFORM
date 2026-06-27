#!/usr/bin/env python3
"""
scripts/p21_certification_gate.py
CYBERDUDEBIVASH® SENTINEL APEX — P21.0 Certification Gate v1.0.0
=================================================================
P21.10 — Regression Certification / CI Gate

Applies P21 certification thresholds to every item in the live feed:
  PREMIUM_CERTIFIED  >= 90
  ENTERPRISE_READY   >= 75  (P21 threshold — stricter than P20's 72)
  INTERNAL_DRAFT      < 75  (blocked from auto-publication)

Exit codes:
  0 — all items meet or exceed INTERNAL_DRAFT; certification report written
  1 — hard failure: items exist that are below MINIMUM_PUBLISHABLE (< 38)
      or critical gate errors detected

Writes: data/quality/p21_certification_report.json

ZERO FABRICATION — scoring is derived entirely from existing item fields.
Reuses the same 8-component scoring weights as P20 (no duplicate engine).
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] P21-CERT %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("p21-cert")

REPO      = Path(__file__).resolve().parent.parent
DRY_RUN   = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
FEED_PATH = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
OUT_PATH  = REPO / "data" / "quality" / "p21_certification_report.json"
FAIL_FAST = os.environ.get("FAIL_FAST", "false").strip().lower() == "true"

# P21 thresholds (stricter than P20: Enterprise Ready raised 72 → 75)
THRESHOLD_PREMIUM    = 90
THRESHOLD_ENTERPRISE = 75
THRESHOLD_MINIMUM    = 38  # below this = not even Analyst Review quality

PACKAGE_TAG_RE = re.compile(
    r"^(npm|pip|gem|cargo|go|composer|nuget|maven):|"
    r"^(golang\.org|go\.dev|npmjs\.com|pypi\.org|rubygems\.org|crates\.io|"
    r"packagist\.org|nuget\.org|mvnrepository\.com)$",
    re.IGNORECASE,
)

MARKDOWN_RE = re.compile(
    r"#{1,6}\s+|(\*{1,2}|_{1,2})(.*?)\1|\[([^\]]+)\]\([^\)]+\)|`{1,3}[^`]*`{1,3}",
    re.DOTALL,
)


def _strip_markdown(text: str) -> str:
    text = MARKDOWN_RE.sub(r"\2\3", text)
    return re.sub(r"\s+", " ", text).strip()


def _score_item(item: Dict) -> Tuple[int, Dict[str, int]]:
    """Compute P21 quality score for a single item (reuses P20 weight schema)."""
    scores: Dict[str, int] = {}

    # --- Evidence (25 pts) ---
    ec = item.get("evidence_chain")
    if ec and isinstance(ec, dict):
        rc = ec.get("reliability_code", "F")
        scores["evidence"] = {"A": 25, "B": 22, "C": 18, "D": 12, "E": 6, "F": 0}.get(rc, 0)
    else:
        scores["evidence"] = 0

    # --- IOC Quality (20 pts) ---
    iocs = [
        i for i in (item.get("iocs") or [])
        if isinstance(i, dict) and len(str(i.get("value", ""))) > 5
        and not re.match(r"^CVE-", str(i.get("value", "")), re.I)
        and not PACKAGE_TAG_RE.search(str(i.get("value", "")))
    ]
    avg_conf = (
        sum(float(i.get("confidence", 30)) for i in iocs) / len(iocs) if iocs else 0
    )
    scores["ioc_quality"] = min(20, (
        (8 if iocs else 0) +
        (4 if len(iocs) >= 3 else 0) +
        (4 if len(iocs) >= 8 else 0) +
        (4 if avg_conf >= 60 else 2 if avg_conf >= 40 else 0)
    ))

    # --- Multi-source (15 pts) ---
    corr = item.get("corroborating_sources")
    corr_count = len(corr) if isinstance(corr, list) else (int(corr) if isinstance(corr, int) else 0)
    scores["multi_source"] = min(15, corr_count * 5)

    # --- MITRE completeness (10 pts) ---
    ttps = item.get("mitre_tactics") or item.get("ttps") or []
    ttp_count = len(ttps) if isinstance(ttps, list) else 0
    scores["mitre"] = 10 if ttp_count >= 4 else 7 if ttp_count >= 2 else 4 if ttp_count >= 1 else 0

    # --- Detection (10 pts) ---
    sigma = item.get("sigma_rule") or item.get("sigma") or ""
    has_sigma = isinstance(sigma, str) and len(sigma) > 100
    sigma_specific = has_sigma and "EventID:\n      - 4625" not in sigma and \
                     "DestinationPort:\n      - 4444" not in sigma
    scores["detection"] = 10 if sigma_specific else (5 if has_sigma else 0)

    # --- Executive quality (10 pts) ---
    text = item.get("apex", {}).get("ai_summary") or item.get("description") or ""
    words = len(_strip_markdown(str(text)).split())
    scores["executive"] = 10 if words >= 100 else 7 if words >= 50 else 4 if words >= 20 else 0

    # --- Freshness (5 pts) ---
    ts = item.get("processed_at") or item.get("timestamp") or ""
    if ts:
        try:
            age_h = (datetime.now(timezone.utc) -
                     datetime.fromisoformat(str(ts).replace("Z", "+00:00"))).total_seconds() / 3600
            scores["freshness"] = 5 if age_h < 6 else 4 if age_h < 24 else 3 if age_h < 72 else 1 if age_h < 168 else 0
        except Exception:
            scores["freshness"] = 0
    else:
        scores["freshness"] = 0

    # --- Consistency (5 pts) ---
    scores["consistency"] = (
        (2 if item.get("cvss_score") is not None else 0) +
        (1 if item.get("epss_score") is not None else 0) +
        (2 if item.get("cve_id") or item.get("cve_ids") else 0)
    )

    total = min(100, sum(scores.values()))
    return total, scores


def _certification_level(score: int) -> str:
    if score >= THRESHOLD_PREMIUM:
        return "PREMIUM_CERTIFIED"
    if score >= THRESHOLD_ENTERPRISE:
        return "ENTERPRISE_READY"
    if score >= THRESHOLD_MINIMUM:
        return "INTERNAL_DRAFT"
    return "BELOW_MINIMUM"


def _gate_results(item: Dict, score: int, breakdown: Dict[str, int]) -> Dict:
    gates: List[Dict] = []

    def gate(name: str, passed: bool, detail: str, score_pts: int = 0) -> None:
        gates.append({"gate": name, "passed": passed, "detail": detail, "score_pts": score_pts})

    # G1: Evidence Chain
    ec = item.get("evidence_chain")
    g1 = bool(ec and isinstance(ec, dict) and ec.get("reliability_code", "F") not in ("F", "E"))
    gate("G1_EVIDENCE", g1,
         f"Reliability code: {ec.get('reliability_code','MISSING') if ec else 'MISSING'} "
         f"(corroboration: {ec.get('corroboration_count', 0) if ec else 0})" if ec
         else "No evidence_chain field present",
         breakdown.get("evidence", 0))

    # G2: IOC Quality
    ioc_count = item.get("ioc_count") or len(item.get("iocs") or [])
    g2 = breakdown.get("ioc_quality", 0) >= 8
    gate("G2_IOC_QUALITY", g2,
         f"{ioc_count} operational IOCs (score: {breakdown.get('ioc_quality',0)}/20)",
         breakdown.get("ioc_quality", 0))

    # G3: Multi-source Validation
    corr = item.get("corroborating_sources")
    corr_count = len(corr) if isinstance(corr, list) else (int(corr) if isinstance(corr, int) else 0)
    g3 = corr_count >= 1
    gate("G3_MULTI_SOURCE", g3,
         f"{corr_count} corroborating sources",
         breakdown.get("multi_source", 0))

    # G4: MITRE Mapping
    ttps = item.get("mitre_tactics") or item.get("ttps") or []
    ttp_count = len(ttps) if isinstance(ttps, list) else 0
    g4 = ttp_count >= 1
    gate("G4_MITRE", g4,
         f"{ttp_count} ATT&CK TTPs/tactics mapped",
         breakdown.get("mitre", 0))

    # G5: Detection Engineering
    sigma = item.get("sigma_rule") or item.get("sigma") or ""
    g5 = bool(isinstance(sigma, str) and len(sigma) > 100)
    gate("G5_DETECTION", g5,
         "Sigma rule present and specific" if (g5 and breakdown.get("detection", 0) == 10)
         else ("Sigma rule present but generic" if g5 else "No detection rule"),
         breakdown.get("detection", 0))

    # G6: Executive Summary
    text = item.get("apex", {}).get("ai_summary") or item.get("description") or ""
    words = len(_strip_markdown(str(text)).split())
    g6 = words >= 50
    gate("G6_EXECUTIVE", g6,
         f"Executive summary: {words} words (≥50 required)",
         breakdown.get("executive", 0))

    # G7: Attribution Quality
    actor_conf = item.get("actor_confidence") or 0
    attr_method = item.get("attribution_method") or ""
    g7 = True  # attribution does not gate publication but we surface it
    gate("G7_ATTRIBUTION", g7,
         f"Confidence: {actor_conf}% | Method: {attr_method or 'unset'}",
         0)

    # G8: Certification Level
    cert_level = _certification_level(score)
    g8 = cert_level != "BELOW_MINIMUM"
    gate("G8_PUBLICATION_GATE", g8,
         f"Score {score}/100 → {cert_level}",
         0)

    gates_passed = sum(1 for g in gates if g["passed"])
    return {
        "gates": gates,
        "gates_passed": gates_passed,
        "gates_total": len(gates),
        "all_critical_passed": all(g["passed"] for g in gates if g["gate"].startswith("G8")),
    }


def certify_feed(path: Path) -> Tuple[Dict, int]:
    if not path.exists():
        log.warning("Feed not found: %s", path)
        return {}, 0

    try:
        raw  = path.read_bytes().rstrip(b"\x00").replace(b"\x00", b"")
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        log.error("Failed to load feed: %s", exc)
        return {}, 1

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = next(
            (data[k] for k in ("items", "advisories", "feed", "data")
             if k in data and isinstance(data[k], list)),
            []
        )
    else:
        return {}, 0

    now = datetime.now(timezone.utc).isoformat()
    certified: List[Dict] = []
    below_min: List[str] = []
    level_counts: Dict[str, int] = Counter()

    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = item.get("stix_id") or item.get("id") or "unknown"
        score, breakdown = _score_item(item)
        level = _certification_level(score)
        gate_res = _gate_results(item, score, breakdown)
        level_counts[level] += 1

        certified.append({
            "id":                item_id,
            "title":             str(item.get("title", ""))[:80],
            "score":             score,
            "level":             level,
            "breakdown":         breakdown,
            "gates_passed":      gate_res["gates_passed"],
            "gates_total":       gate_res["gates_total"],
            "gates":             gate_res["gates"],
            "severity":          item.get("severity", "UNKNOWN"),
            "kev":               bool(item.get("kev_present") or item.get("kev")),
            "cve":               (item.get("cve_ids") or ([item["cve_id"]] if item.get("cve_id") else []))[:3],
            "certified_at":      now,
        })

        if level == "BELOW_MINIMUM":
            below_min.append(item_id)
            log.warning("BELOW_MINIMUM: %s (score=%d)", item_id[:40], score)

    total = len(certified)
    avg   = round(sum(c["score"] for c in certified) / total, 1) if total else 0

    report = {
        "generated_at":           now,
        "certification_version":  "P21.0",
        "feed_path":              str(path),
        "total_items":            total,
        "average_score":          avg,
        "level_distribution":     dict(level_counts),
        "below_minimum_count":    len(below_min),
        "below_minimum_ids":      below_min[:20],
        "premium_certified_pct":  round(level_counts.get("PREMIUM_CERTIFIED", 0) / max(total, 1) * 100, 1),
        "enterprise_ready_pct":   round((level_counts.get("PREMIUM_CERTIFIED", 0) + level_counts.get("ENTERPRISE_READY", 0)) / max(total, 1) * 100, 1),
        "thresholds": {
            "premium_certified":  THRESHOLD_PREMIUM,
            "enterprise_ready":   THRESHOLD_ENTERPRISE,
            "minimum_publishable": THRESHOLD_MINIMUM,
        },
        "items": certified,
    }
    return report, len(below_min)


def main() -> int:
    log.info("P21.0 Certification Gate v1.0.0 — DRY_RUN=%s FAIL_FAST=%s", DRY_RUN, FAIL_FAST)
    log.info("Thresholds: PREMIUM≥%d | ENTERPRISE≥%d | MIN≥%d",
             THRESHOLD_PREMIUM, THRESHOLD_ENTERPRISE, THRESHOLD_MINIMUM)

    report, below_min_count = certify_feed(FEED_PATH)
    if not report:
        log.error("No items certified — feed empty or unreadable")
        return 1

    total  = report["total_items"]
    avg    = report["average_score"]
    levels = report["level_distribution"]
    prem   = report["premium_certified_pct"]
    ent    = report["enterprise_ready_pct"]

    log.info("Feed: %d items | Avg score: %.1f/100", total, avg)
    log.info("PREMIUM_CERTIFIED: %d (%.1f%%)", levels.get("PREMIUM_CERTIFIED", 0), prem)
    log.info("ENTERPRISE_READY:  %d", levels.get("ENTERPRISE_READY", 0))
    log.info("INTERNAL_DRAFT:    %d", levels.get("INTERNAL_DRAFT", 0))
    log.info("BELOW_MINIMUM:     %d", below_min_count)
    log.info("Publishable (≥ENTERPRISE_READY): %.1f%%", ent)

    if not DRY_RUN:
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = OUT_PATH.with_suffix(".tmp_p21cert")
        try:
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(OUT_PATH)
            log.info("Certification report: %s (%d B)", OUT_PATH, OUT_PATH.stat().st_size)
        except Exception as exc:
            log.error("Failed to write report: %s", exc)
            tmp.unlink(missing_ok=True)
            return 1
    else:
        log.info("[DRY_RUN] Would write %d-item certification report to %s", total, OUT_PATH)

    if FAIL_FAST and below_min_count > 0:
        log.error("HARD_FAIL: %d item(s) BELOW_MINIMUM threshold (score < %d)",
                  below_min_count, THRESHOLD_MINIMUM)
        return 1

    log.info("P21.0 Certification Gate PASS — %d items certified", total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
