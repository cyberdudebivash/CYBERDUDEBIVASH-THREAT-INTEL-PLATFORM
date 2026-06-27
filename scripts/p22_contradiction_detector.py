#!/usr/bin/env python3
"""
scripts/p22_contradiction_detector.py
CYBERDUDEBIVASH® SENTINEL APEX — P22.3 Contradiction Detector v1.0.0
======================================================================
P22.3 — Intelligence Contradiction Detection

Scans the live feed for internal and cross-item contradictions:

INTRA-ITEM CHECKS (within a single advisory):
  C1  CVSS vs Severity mismatch  (e.g., CVSS 9.8 but severity=LOW)
  C2  KEV vs Severity mismatch   (KEV=True but severity=INFO/LOW)
  C3  KEV vs CVSS mismatch       (KEV=True but CVSS < 4.0)
  C4  EPSS vs Severity mismatch  (EPSS > 50% but severity=LOW/INFO)
  C5  Exploit status vs CVSS     (has_exploit=True but CVSS < 3.0)
  C6  Timestamp inversion        (published_at > processed_at by > 7 days)
  C7  IOC confidence vs overall  (high IOC confidence but low item confidence)

CROSS-ITEM CHECKS (same CVE referenced in multiple advisories):
  X1  CVSS mismatch across items  (delta > 1.5)
  X2  Severity mismatch           (conflicting severity string for same CVE)
  X3  KEV status conflict         (one says KEV, another says not)
  X4  Attribution conflict        (different actor IDs for same CVE)

ZERO FABRICATION — all checks derive from existing item field data.
ADDITIVE ONLY — no existing schema, API, or KV changed.

Exit codes:
  0 — no contradictions found OR FAIL_FAST=false (non-blocking by default)
  1 — contradictions found AND FAIL_FAST=true

Writes: data/quality/p22_contradiction_report.json
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] P22-CONTRA %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("p22-contra")

REPO      = Path(__file__).resolve().parent.parent
DRY_RUN   = os.environ.get("DRY_RUN",   "false").strip().lower() == "true"
FAIL_FAST = os.environ.get("FAIL_FAST", "false").strip().lower() == "true"
FEED_PATH = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
OUT_PATH  = REPO / "data" / "quality" / "p22_contradiction_report.json"

# Thresholds
CVSS_DELTA_THRESHOLD  = 1.5   # Cross-item CVSS delta to flag conflict
EPSS_HIGH_THRESHOLD   = 50.0  # EPSS % above which HIGH/CRITICAL expected
TIMESTAMP_MAX_LAG_H   = 7 * 24  # Published more than 7 days after processed
CONF_IOC_MISMATCH_GAP = 40    # Item confidence < X but IOC avg confidence > X+gap

# CVSS → expected severity bands
CVSS_SEV_BANDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW"),
]

def _expected_severity_from_cvss(cvss: float) -> str:
    for threshold, label in CVSS_SEV_BANDS:
        if cvss >= threshold:
            return label
    return "LOW"

def _parse_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


# ── Intra-item contradiction checks ──────────────────────────────────────────

def _check_intra(item: Dict) -> List[Dict]:
    contradictions: List[Dict] = []
    item_id   = item.get("stix_id") or item.get("id") or "unknown"
    title     = str(item.get("title", ""))[:80]
    cvss      = item.get("cvss_score") or item.get("cvss")
    severity  = (item.get("severity") or "").upper()
    kev       = bool(item.get("kev_present") or item.get("kev"))
    epss      = item.get("epss_score")
    has_exploit = bool(item.get("has_exploit") or item.get("exploit_available"))
    conf      = float(item.get("confidence_score") or item.get("confidence") or 0)
    ts_pub    = item.get("published_at") or item.get("published") or ""
    ts_proc   = item.get("processed_at") or item.get("timestamp") or ""

    def contra(code: str, desc: str, severity_level: str = "WARN") -> None:
        contradictions.append({
            "id":       item_id,
            "title":    title,
            "code":     code,
            "desc":     desc,
            "severity": severity_level,
        })

    # C1: CVSS vs Severity
    if cvss is not None and severity and severity not in ("UNKNOWN", "INFO", ""):
        expected = _expected_severity_from_cvss(float(cvss))
        actual   = severity
        BAND_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        exp_ord = BAND_ORDER.get(expected, -1)
        act_ord = BAND_ORDER.get(actual, -1)
        if exp_ord >= 0 and act_ord >= 0 and abs(exp_ord - act_ord) >= 2:
            contra("C1_CVSS_SEV_MISMATCH",
                   f"CVSS {float(cvss):.1f} expects {expected} but severity={actual} (gap≥2 bands)",
                   "ERROR")

    # C2: KEV vs Severity
    if kev and severity in ("LOW", "INFO", "UNKNOWN"):
        contra("C2_KEV_SEV_MISMATCH",
               f"KEV=True but severity={severity}. KEV entries require at least MEDIUM.",
               "ERROR")

    # C3: KEV vs CVSS
    if kev and cvss is not None and float(cvss) < 4.0:
        contra("C3_KEV_CVSS_MISMATCH",
               f"KEV=True but CVSS={float(cvss):.1f} (<4.0). Confirmed exploited CVEs typically score ≥4.",
               "WARN")

    # C4: EPSS vs Severity
    if epss is not None and float(epss) >= EPSS_HIGH_THRESHOLD and severity in ("LOW", "INFO"):
        contra("C4_EPSS_SEV_MISMATCH",
               f"EPSS={float(epss):.1f}% (high exploitation likelihood) but severity={severity}.",
               "WARN")

    # C5: Exploit vs CVSS
    if has_exploit and cvss is not None and float(cvss) < 3.0:
        contra("C5_EXPLOIT_CVSS_MISMATCH",
               f"has_exploit=True but CVSS={float(cvss):.1f} (<3.0). Low CVSS with confirmed exploit is unusual.",
               "WARN")

    # C6: Timestamp inversion
    dt_pub  = _parse_ts(ts_pub)
    dt_proc = _parse_ts(ts_proc)
    if dt_pub and dt_proc:
        lag_h = (dt_pub - dt_proc).total_seconds() / 3600
        if lag_h > TIMESTAMP_MAX_LAG_H:
            contra("C6_TIMESTAMP_INVERSION",
                   f"published_at ({ts_pub[:10]}) is {lag_h:.0f}h AFTER processed_at ({ts_proc[:10]}). "
                   f"Advisory may be backdated or timestamps misassigned.",
                   "WARN")

    # C7: IOC confidence vs item confidence
    iocs = item.get("iocs") or []
    op_iocs = [i for i in iocs if isinstance(i, dict) and i.get("confidence") is not None
               and not re.match(r"^CVE-", str(i.get("value", "")), re.I)]
    if op_iocs and conf > 0:
        avg_ioc_conf = sum(float(i.get("confidence", 0)) for i in op_iocs) / len(op_iocs)
        if conf < 40 and avg_ioc_conf > conf + CONF_IOC_MISMATCH_GAP:
            contra("C7_IOC_CONF_MISMATCH",
                   f"Item confidence={conf:.0f}% but IOC avg confidence={avg_ioc_conf:.0f}% "
                   f"(gap={avg_ioc_conf - conf:.0f}pp). Consider enriching item confidence.",
                   "INFO")

    return contradictions


# ── Cross-item CVE contradiction checks ───────────────────────────────────────

def _check_cross(items: List[Dict]) -> List[Dict]:
    # Index items by CVE
    cve_index: Dict[str, List[Dict]] = defaultdict(list)
    for item in items:
        if not isinstance(item, dict):
            continue
        cves = item.get("cve_ids") or ([item["cve_id"]] if item.get("cve_id") else [])
        for cve in cves:
            if cve and re.match(r"^CVE-\d{4}-\d{4,}", cve, re.I):
                cve_index[cve.upper()].append(item)

    contradictions: List[Dict] = []

    for cve, group in cve_index.items():
        if len(group) < 2:
            continue

        cvss_vals  = [(i.get("cvss_score") or i.get("cvss"), i) for i in group if (i.get("cvss_score") or i.get("cvss")) is not None]
        sev_vals   = [(str(i.get("severity") or "").upper(), i) for i in group if i.get("severity")]
        kev_vals   = [bool(i.get("kev_present") or i.get("kev")) for i in group]
        actor_vals = [(i.get("actor_id") or i.get("actor_tag") or "", i) for i in group
                      if i.get("actor_id") or i.get("actor_tag")]

        ids_str = ", ".join({(i.get("stix_id") or i.get("id") or "?")[:20] for i in group[:3]})

        # X1: CVSS mismatch
        if len(cvss_vals) >= 2:
            scores = [float(v) for v, _ in cvss_vals]
            delta  = max(scores) - min(scores)
            if delta >= CVSS_DELTA_THRESHOLD:
                contradictions.append({
                    "cve":   cve,
                    "code":  "X1_CVSS_CONFLICT",
                    "desc":  f"{cve}: CVSS range {min(scores):.1f}–{max(scores):.1f} across {len(group)} items (Δ={delta:.1f}). May indicate different CVSS versions or scoring discrepancies.",
                    "items": ids_str,
                    "severity": "WARN",
                })

        # X2: Severity mismatch
        unique_sevs = {s for s, _ in sev_vals if s not in ("UNKNOWN", "INFO", "")}
        if len(unique_sevs) >= 2:
            contradictions.append({
                "cve":   cve,
                "code":  "X2_SEVERITY_CONFLICT",
                "desc":  f"{cve}: Conflicting severity labels: {', '.join(sorted(unique_sevs))} across {len(group)} items. Verify authoritative NVD classification.",
                "items": ids_str,
                "severity": "WARN",
            })

        # X3: KEV status conflict
        if len(kev_vals) >= 2 and len(set(kev_vals)) > 1:
            contradictions.append({
                "cve":   cve,
                "code":  "X3_KEV_CONFLICT",
                "desc":  f"{cve}: Conflicting KEV status across items. One advisory marks as exploited, another does not. Verify against CISA KEV catalog.",
                "items": ids_str,
                "severity": "ERROR",
            })

        # X4: Attribution conflict
        actor_ids = {a for a, _ in actor_vals if a and a not in ("UNC-UNKNOWN", "UNC-CDB-99", "Unattributed")}
        if len(actor_ids) >= 2:
            contradictions.append({
                "cve":   cve,
                "code":  "X4_ATTRIBUTION_CONFLICT",
                "desc":  f"{cve}: Conflicting actor attribution: {', '.join(sorted(actor_ids))}. Multiple actors attributed to same CVE — may indicate coordinated campaign or attribution error.",
                "items": ids_str,
                "severity": "WARN",
            })

    return contradictions


# ── Main ──────────────────────────────────────────────────────────────────────

def run(path: Path) -> Dict:
    if not path.exists():
        log.warning("Feed not found: %s", path)
        return {}
    try:
        raw  = path.read_bytes().rstrip(b"\x00").replace(b"\x00", b"")
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        log.error("Failed to load feed: %s", exc)
        return {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = next(
            (data[k] for k in ("items", "advisories", "feed", "data")
             if k in data and isinstance(data[k], list)),
            []
        )
    else:
        return {}

    now   = datetime.now(timezone.utc).isoformat()
    intra = []
    for item in items:
        if isinstance(item, dict):
            intra.extend(_check_intra(item))

    cross  = _check_cross(items)
    total  = len(intra) + len(cross)
    errors = [c for c in intra + cross if c.get("severity") == "ERROR"]

    report = {
        "generated_at":    now,
        "version":         "P22.3",
        "feed_path":       str(path),
        "items_checked":   sum(1 for i in items if isinstance(i, dict)),
        "total_contradictions": total,
        "error_count":     len(errors),
        "warning_count":   total - len(errors),
        "intra_item":      intra,
        "cross_item":      cross,
        "error_items":     [c.get("id") or c.get("cve") or "?" for c in errors][:20],
    }

    for lvl, items_list, label in [
        ("ERROR", errors, "ERRORS"),
        ("WARN",  [c for c in intra + cross if c.get("severity") == "WARN"], "WARNINGS"),
    ]:
        log.info("%s: %d contradiction %s", label, len(items_list),
                 "found" if items_list else "detected — feed is clean")

    return report


def main() -> int:
    log.info("P22.3 Contradiction Detector v1.0.0 — DRY_RUN=%s FAIL_FAST=%s", DRY_RUN, FAIL_FAST)

    report = run(FEED_PATH)
    if not report:
        log.error("No report generated — feed empty or unreadable")
        return 1

    total  = report["total_contradictions"]
    errors = report["error_count"]

    log.info("Items checked: %d | Total contradictions: %d | Errors: %d | Warnings: %d",
             report["items_checked"], total, errors, report["warning_count"])

    if not DRY_RUN:
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = OUT_PATH.with_suffix(".tmp_p22contra")
        try:
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(OUT_PATH)
            log.info("Report written: %s", OUT_PATH)
        except Exception as exc:
            log.error("Failed to write report: %s", exc)
            tmp.unlink(missing_ok=True)
    else:
        log.info("[DRY_RUN] Would write contradiction report: %d items, %d contradictions", report["items_checked"], total)

    if FAIL_FAST and errors > 0:
        log.error("HARD_FAIL: %d ERROR-level contradictions detected", errors)
        return 1

    log.info("P22.3 Contradiction Detector PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
