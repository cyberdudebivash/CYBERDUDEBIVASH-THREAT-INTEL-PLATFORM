#!/usr/bin/env python3
"""
scripts/severity_invariant_interceptor.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Severity Invariant Interceptor  v180.0
==========================================================================
Server-side validation interceptor enforcing mandatory severity invariants.
This module is the *canonical authoritative* P0 governance layer and must be
called at every pipeline stage that commits severity to persistent storage.

INVARIANT MAP (applied in priority order):
  CRITICAL Invariant (Rule C):
    Triggers when ANY of:
      - cvss_score >= 9.0
      - active_exploitation signal detected  (structured or keyword)
      - cisa_kev flag = true
      - public_exploit_code flag = true
      - threat_class in {"rce", "auth_bypass", "remote_code_execution",
                         "authentication_bypass"}
    Action: severity → CRITICAL, priority → P1,
            threat_level → CRITICAL_SURGE,
            risk_score   → max(9.0, cvss_score)

  HIGH Floor (Rule H):
    Triggers when: 8.0 <= cvss_score < 9.0  AND  current severity == LOW
    Action: severity → HIGH, priority → P2,
            risk_score → max(7.5, cvss_score)

  MEDIUM Floor (Rule M):
    Triggers when: 7.0 <= cvss_score < 8.0  AND  current severity == LOW
    Action: severity → MEDIUM, priority → P3

KEYWORD SIGNALS (feed into Rule C active-exploitation branch):
  "actively exploiting", "under active attack", "mass exploitation",
  "exploiting in the wild", "actively exploited", "active exploitation",
  "being actively exploited", "exploited in the wild", "in the wild",
  "widespread exploitation", "zero-day exploit", "0-day exploit",
  "weaponized exploit", "ransomware deployment", "ransom deployed"

Usage (standalone):
  python3 scripts/severity_invariant_interceptor.py \\
      --feed api/feed.json [--dry-run] [--report]

Usage (inline):
  from severity_invariant_interceptor import apply_invariants, apply_invariants_to_feed
  item  = apply_invariants(item)
  items = apply_invariants_to_feed(items)

Author: SENTINEL APEX Pipeline Governance v180.0
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

log = logging.getLogger("sentinel.severity_invariant")

# ── Constants ─────────────────────────────────────────────────────────────────

VERSION = "180.0"
MODULE  = "SeverityInvariantInterceptor"

_SEV_RANK: Dict[str, int] = {
    "NONE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}
_RANK_SEV: Dict[int, str] = {0: "LOW", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

# CVSS thresholds
_CVSS_CRITICAL_FLOOR = 9.0   # Rule C: any CVSS >= 9.0 → CRITICAL
_CVSS_HIGH_FLOOR     = 8.0   # Rule H: CVSS in [8.0, 9.0) + severity LOW → HIGH
_CVSS_MEDIUM_FLOOR   = 7.0   # Rule M: CVSS in [7.0, 8.0) + severity LOW → MEDIUM

# Threat classes that mandate CRITICAL
_CRITICAL_THREAT_CLASSES = frozenset({
    "rce",
    "auth_bypass",
    "remote_code_execution",
    "authentication_bypass",
    "remote_code_exec",
    "unauthenticated_rce",
    "pre_auth_rce",
    "os_command_injection",
    "deserialization_rce",
})

# Keyword patterns that trigger the active-exploitation CRITICAL signal
_ACTIVE_EXPLOIT_KEYWORDS: List[str] = [
    "actively exploiting",
    "actively exploited",
    "active exploitation",
    "being actively exploited",
    "under active attack",
    "mass exploitation",
    "exploiting in the wild",
    "exploited in the wild",
    "in-the-wild exploitation",
    "widespread exploitation",
    "zero-day exploit",
    "0-day exploit",
    "weaponized exploit",
    "ransomware deployment",
    "ransom deployed",
    "attackers are actively",
    "threat actors exploiting",
]

# Compiled regex (faster than repeated lower-case string search over many items)
_ACTIVE_EXPLOIT_RE = re.compile(
    "|".join(re.escape(kw) for kw in _ACTIVE_EXPLOIT_KEYWORDS),
    re.IGNORECASE,
)

# CVSS field variants (probe in order; use first parseable value in [0, 10])
_CVSS_FIELDS: Tuple[str, ...] = (
    "cvss_score", "cvss", "cvss_base", "cvss_v3", "cvss3_score",
    "cvss_base_score", "base_score",
)

# KEV / active-exploitation structured field variants
_KEV_FIELDS: Tuple[str, ...] = (
    "kev", "kev_present", "in_kev", "cisa_kev",
)
_ACTIVE_EXPLOIT_STRUCT_FIELDS: Tuple[str, ...] = (
    "active_exploitation", "actively_exploited", "exploited_in_wild",
    "is_exploited", "exploited",
)
_PUBLIC_EXPLOIT_FIELDS: Tuple[str, ...] = (
    "public_exploit_code", "exploit_available", "exploit_public",
    "exploit_code", "poc_available",
)
_THREAT_CLASS_FIELDS: Tuple[str, ...] = (
    "threat_class", "threat_type", "vuln_type", "vulnerability_type",
    "attack_type",
)

# Text fields to scan for keyword signals
_TEXT_SCAN_FIELDS: Tuple[str, ...] = (
    "title", "headline", "name", "description", "summary",
    "analysis", "notes", "tags",
)

# Paywall tactical fields — these are scrubbed for non-PRO/ENTERPRISE callers
# (also enforced by the Cloudflare Worker applyTierGate; defined here as the
#  single-source-of-truth for the field list).
PAYWALL_TACTICAL_FIELDS: Tuple[str, ...] = (
    "sigma_rule", "sigma",
    "kql_query", "kql",
    "suricata_rule", "suricata",
    "yara_rule", "yara",
    "soc_playbook",
)


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _get_cvss(item: Dict[str, Any]) -> float:
    """Return the highest parseable CVSS score from the item, or 0.0."""
    for field in _CVSS_FIELDS:
        raw = item.get(field)
        if raw is None or raw in ("", "N/A", "Pending", "none", "null"):
            continue
        try:
            v = float(raw)
            if 0.0 <= v <= 10.0:
                return v
        except (TypeError, ValueError):
            pass
    return 0.0


def _is_truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    return str(val).strip().upper() in ("TRUE", "YES", "1", "T", "Y")


def _has_kev(item: Dict[str, Any]) -> bool:
    for field in _KEV_FIELDS:
        if _is_truthy(item.get(field)):
            return True
    return False


def _has_active_exploitation_struct(item: Dict[str, Any]) -> bool:
    for field in _ACTIVE_EXPLOIT_STRUCT_FIELDS:
        if _is_truthy(item.get(field)):
            return True
    return False


def _has_public_exploit(item: Dict[str, Any]) -> bool:
    for field in _PUBLIC_EXPLOIT_FIELDS:
        if _is_truthy(item.get(field)):
            return True
    return False


def _has_critical_threat_class(item: Dict[str, Any]) -> bool:
    for field in _THREAT_CLASS_FIELDS:
        val = item.get(field)
        if val is None:
            continue
        if isinstance(val, (list, tuple)):
            for v in val:
                if str(v).lower().strip() in _CRITICAL_THREAT_CLASSES:
                    return True
        else:
            if str(val).lower().strip() in _CRITICAL_THREAT_CLASSES:
                return True
    return False


def _has_active_exploit_keywords(item: Dict[str, Any]) -> bool:
    """Scan text fields for active-exploitation keyword signals."""
    combined = " ".join(
        str(item.get(f, "")) for f in _TEXT_SCAN_FIELDS
    )
    return bool(_ACTIVE_EXPLOIT_RE.search(combined))


# ── Core invariant logic ──────────────────────────────────────────────────────

class InvariantVerdict:
    """Holds the result of a single-item invariant evaluation."""
    __slots__ = (
        "rule_fired", "old_severity", "new_severity",
        "old_priority", "new_priority",
        "old_threat_level", "new_threat_level",
        "old_risk_score", "new_risk_score",
        "signals", "changed",
    )

    def __init__(self) -> None:
        self.rule_fired      = "NONE"
        self.old_severity    = ""
        self.new_severity    = ""
        self.old_priority    = ""
        self.new_priority    = ""
        self.old_threat_level = ""
        self.new_threat_level = ""
        self.old_risk_score  = 0.0
        self.new_risk_score  = 0.0
        self.signals: List[str] = []
        self.changed = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_fired":       self.rule_fired,
            "old_severity":     self.old_severity,
            "new_severity":     self.new_severity,
            "old_priority":     self.old_priority,
            "new_priority":     self.new_priority,
            "old_threat_level": self.old_threat_level,
            "new_threat_level": self.new_threat_level,
            "old_risk_score":   self.old_risk_score,
            "new_risk_score":   self.new_risk_score,
            "signals":          self.signals,
            "changed":          self.changed,
        }


def _evaluate_item(item: Dict[str, Any]) -> InvariantVerdict:
    """
    Evaluate a single intelligence item against all invariant rules.
    Returns an InvariantVerdict describing what (if anything) must change.
    Does NOT modify the item.
    """
    v = InvariantVerdict()

    cur_sev       = str(item.get("severity") or "LOW").upper().strip()
    cur_priority  = str(item.get("priority") or "").strip()
    cur_tl        = str(item.get("threat_level") or "").strip()
    cur_risk      = float(item.get("risk_score") or 0.0)
    cvss          = _get_cvss(item)

    v.old_severity    = cur_sev
    v.old_priority    = cur_priority
    v.old_threat_level = cur_tl
    v.old_risk_score  = cur_risk

    # ── Rule C: CRITICAL invariant ──────────────────────────────────────────
    # Fires when ANY critical signal is present, regardless of current severity.
    signals_c: List[str] = []
    if cvss >= _CVSS_CRITICAL_FLOOR:
        signals_c.append(f"CVSS={cvss:.1f}>={_CVSS_CRITICAL_FLOOR}")
    if _has_kev(item):
        signals_c.append("CISA_KEV=TRUE")
    if _has_active_exploitation_struct(item):
        signals_c.append("ACTIVE_EXPLOITATION_STRUCT=TRUE")
    if _has_active_exploit_keywords(item):
        signals_c.append("ACTIVE_EXPLOIT_KEYWORD_MATCH")
    if _has_public_exploit(item):
        signals_c.append("PUBLIC_EXPLOIT_CODE=TRUE")
    if _has_critical_threat_class(item):
        signals_c.append(f"THREAT_CLASS=CRITICAL")

    if signals_c:
        v.rule_fired      = "C"
        v.new_severity    = "CRITICAL"
        v.new_priority    = "P1"
        v.new_threat_level = "CRITICAL_SURGE"
        v.new_risk_score  = round(max(9.0, cvss), 4)
        v.signals         = signals_c
        v.changed = (
            cur_sev != "CRITICAL"
            or cur_priority != "P1"
            or cur_tl != "CRITICAL_SURGE"
            or cur_risk < v.new_risk_score
        )
        return v

    # ── Rule H: HIGH floor ──────────────────────────────────────────────────
    if _CVSS_HIGH_FLOOR <= cvss < _CVSS_CRITICAL_FLOOR and cur_sev == "LOW":
        v.rule_fired      = "H"
        v.new_severity    = "HIGH"
        v.new_priority    = "P2"
        v.new_threat_level = cur_tl  # preserve existing
        v.new_risk_score  = round(max(7.5, cvss), 4)
        v.signals         = [f"CVSS={cvss:.1f} in [8.0,9.0) AND severity==LOW"]
        v.changed         = True
        return v

    # ── Rule M: MEDIUM floor ─────────────────────────────────────────────────
    if _CVSS_MEDIUM_FLOOR <= cvss < _CVSS_HIGH_FLOOR and cur_sev == "LOW":
        v.rule_fired      = "M"
        v.new_severity    = "MEDIUM"
        v.new_priority    = "P3"
        v.new_threat_level = cur_tl  # preserve existing
        v.new_risk_score  = cur_risk  # no mandatory risk_score bump for MEDIUM
        v.signals         = [f"CVSS={cvss:.1f} in [7.0,8.0) AND severity==LOW"]
        v.changed         = True
        return v

    # ── No invariant triggered ───────────────────────────────────────────────
    v.rule_fired      = "NONE"
    v.new_severity    = cur_sev
    v.new_priority    = cur_priority
    v.new_threat_level = cur_tl
    v.new_risk_score  = cur_risk
    v.changed         = False
    return v


# ── Public API ────────────────────────────────────────────────────────────────

def apply_invariants(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply severity invariants to a single item dict.
    Returns a (possibly mutated copy of the) item with corrected fields.
    The original item is never modified in place — always works on a copy.

    Injected fields when a rule fires:
      item["severity"]              — corrected value
      item["priority"]              — P1 / P2 / P3
      item["threat_level"]          — CRITICAL_SURGE (Rule C only)
      item["risk_score"]            — enforced floor value
      item["_invariant_rule"]       — "C" / "H" / "M"
      item["_invariant_signals"]    — list of signal strings
      item["_invariant_version"]    — module version string
    """
    verdict = _evaluate_item(item)
    if not verdict.changed:
        return item  # fast path: no mutation needed

    out = dict(item)
    out["severity"]           = verdict.new_severity
    out["priority"]           = verdict.new_priority
    if verdict.rule_fired == "C":
        out["threat_level"]   = verdict.new_threat_level
    if verdict.new_risk_score > verdict.old_risk_score:
        out["risk_score"]     = verdict.new_risk_score
    out["_invariant_rule"]    = verdict.rule_fired
    out["_invariant_signals"] = verdict.signals
    out["_invariant_version"] = VERSION
    return out


def apply_invariants_to_feed(
    items: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Apply severity invariants to an entire feed list.
    Returns (governed_items, report_dict).

    report_dict keys:
      module, version, run_at, total_items,
      critical_enforced, high_enforced, medium_enforced, unchanged,
      violations  (list of per-item dicts for changed items)
    """
    governed: List[Dict[str, Any]] = []
    violations: List[Dict[str, Any]] = []
    counters: Dict[str, int] = {"C": 0, "H": 0, "M": 0}

    for item in items:
        verdict = _evaluate_item(item)
        if verdict.changed:
            counters[verdict.rule_fired] = counters.get(verdict.rule_fired, 0) + 1
            out = dict(item)
            out["severity"]           = verdict.new_severity
            out["priority"]           = verdict.new_priority
            if verdict.rule_fired == "C":
                out["threat_level"]   = verdict.new_threat_level
            if verdict.new_risk_score > verdict.old_risk_score:
                out["risk_score"]     = verdict.new_risk_score
            out["_invariant_rule"]    = verdict.rule_fired
            out["_invariant_signals"] = verdict.signals
            out["_invariant_version"] = VERSION
            governed.append(out)
            violations.append({
                "id":             item.get("id", item.get("title", "")[:60]),
                "rule":           verdict.rule_fired,
                "old_severity":   verdict.old_severity,
                "new_severity":   verdict.new_severity,
                "old_priority":   verdict.old_priority,
                "new_priority":   verdict.new_priority,
                "old_risk_score": verdict.old_risk_score,
                "new_risk_score": verdict.new_risk_score,
                "signals":        verdict.signals,
            })
        else:
            governed.append(item)

    report = {
        "module":           MODULE,
        "version":          VERSION,
        "run_at":           datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_items":      len(items),
        "critical_enforced": counters.get("C", 0),
        "high_enforced":    counters.get("H", 0),
        "medium_enforced":  counters.get("M", 0),
        "unchanged":        len(items) - sum(counters.values()),
        "violations":       violations,
        "status":           "PASS",
    }
    return governed, report


def apply_invariants_to_file(
    feed_path: Path | str,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Load a feed JSON file, apply invariants, atomically write back.
    Handles both list-root and dict-root (items/advisories/data keys) feeds.
    Returns the report dict.
    """
    feed_path = Path(feed_path)
    if not feed_path.exists():
        return {"status": "ERROR", "error": f"Feed file not found: {feed_path}"}

    raw = json.loads(feed_path.read_text(encoding="utf-8"))
    is_dict = isinstance(raw, dict)

    if is_dict:
        for key in ("items", "advisories", "data"):
            if key in raw and isinstance(raw[key], list):
                items = raw[key]
                items_key = key
                break
        else:
            items = []
            items_key = "items"
    else:
        items = raw
        items_key = None

    governed, report = apply_invariants_to_feed(items)
    report["feed_path"] = str(feed_path)

    if dry_run:
        report["dry_run"] = True
        return report

    if report["critical_enforced"] + report["high_enforced"] + report["medium_enforced"] > 0:
        if is_dict:
            raw[items_key] = governed
            output = raw
        else:
            output = governed

        out_json = json.dumps(output, indent=2, ensure_ascii=False)
        tmp = feed_path.with_suffix(".sii_tmp")
        tmp.write_text(out_json, encoding="utf-8")
        tmp.replace(feed_path)
        log.info(
            "[SII] %s: C=%d H=%d M=%d invariants enforced",
            feed_path.name,
            report["critical_enforced"],
            report["high_enforced"],
            report["medium_enforced"],
        )
    else:
        log.info("[SII] %s: 0 violations — all invariants satisfied", feed_path.name)

    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Severity Invariant Interceptor v" + VERSION,
    )
    parser.add_argument(
        "--feed", default="api/feed.json",
        help="Path to feed JSON (default: api/feed.json)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report violations without writing back",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Print JSON report to stdout",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
    )

    repo_root = Path(__file__).resolve().parent.parent
    feed_path = Path(args.feed) if Path(args.feed).is_absolute() else repo_root / args.feed

    report = apply_invariants_to_file(feed_path, dry_run=args.dry_run)

    if args.report or args.dry_run:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        total = report.get("critical_enforced", 0) + report.get("high_enforced", 0) + report.get("medium_enforced", 0)
        print(
            f"[SII v{VERSION}] {total} invariant(s) enforced: "
            f"C={report.get('critical_enforced',0)} "
            f"H={report.get('high_enforced',0)} "
            f"M={report.get('medium_enforced',0)}"
        )

    import sys as _sys
    _sys.exit(0)
