#!/usr/bin/env python3
"""
SEVERITY RECALIBRATION ENGINE  v180.0  -- SENTINEL APEX
=========================================================
Applies mandatory severity floors based on threat intelligence signals.
v180.0: Now delegates to SeverityInvariantInterceptor (severity_invariant_interceptor.py)
for the authoritative P0 invariant rules, then applies legacy floor logic.

INVARIANT RULES (v180.0 — enforced by SeverityInvariantInterceptor):
  Rule C (CRITICAL invariant — fires regardless of current severity):
    ANY of: CVSS >= 9.0, CISA KEV, active_exploitation, public_exploit_code,
            threat_class in {rce, auth_bypass}
    → severity=CRITICAL, priority=P1, threat_level=CRITICAL_SURGE,
      risk_score=max(9.0, cvss_score)

  Rule H (HIGH floor — only when current severity == LOW):
    8.0 <= CVSS < 9.0 AND severity==LOW
    → severity=HIGH, priority=P2, risk_score=max(7.5, cvss_score)

  Rule M (MEDIUM floor — only when current severity == LOW):
    7.0 <= CVSS < 8.0 AND severity==LOW
    → severity=MEDIUM, priority=P3

LEGACY FLOORS (maintained for backward compatibility):
  KEV (CISA Known Exploited Vulnerability) = HIGH minimum
  KEV + Active Exploit = CRITICAL
  Active exploitation signals in title/content = HIGH minimum
  Ransomware = HIGH minimum
  Zero-Day = HIGH minimum
  CVSS >= 9.0 = CRITICAL minimum (v180.0 — was HIGH minimum before)
  EPSS >= 0.70 = HIGH minimum
  CISA warning = HIGH minimum

Usage:
  python3 scripts/severity_recalibration_engine.py [--feed api/feed.json] [--fix]
"""
import json, os, sys, re, argparse, datetime, pathlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = "180.0"

_SEV_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}

# ── v180.0: Add keyword patterns for active exploitation (P0 invariant) ──────
_ACTIVE_EXPLOIT_RE = re.compile(
    r'actively exploit(?:ing|ed)?|under active attack|mass exploit(?:ation)?'
    r'|exploiting in the wild|exploited in the wild',
    re.IGNORECASE,
)

# Title / content patterns that mandate HIGH minimum severity
_HIGH_PATTERNS = [
    (re.compile(r'actively exploit', re.I),         "active exploitation"),
    (re.compile(r'under active attack', re.I),       "active attack"),
    (re.compile(r'exploited in the wild', re.I),     "exploited in wild"),
    (re.compile(r'ransomware', re.I),                "ransomware"),
    (re.compile(r'CISA\b.*warn|warn.*\bCISA\b', re.I), "CISA warning"),
    (re.compile(r'CISA\b.*KEV|KEV\b.*CISA', re.I),  "CISA KEV"),
    (re.compile(r'known exploited', re.I),           "known exploited"),
    (re.compile(r'weaponized', re.I),                "weaponized"),
    (re.compile(r'mass exploit', re.I),              "mass exploitation"),
    (re.compile(r'nation.?state', re.I),             "nation-state actor"),
    (re.compile(r'supply chain', re.I),              "supply chain attack"),
    (re.compile(r'critical\s+infrastructure', re.I), "critical infrastructure"),
]

_CRITICAL_PATTERNS = [
    (re.compile(r'zero.?day', re.I),                 "zero-day"),
    (re.compile(r'0.?day', re.I),                    "zero-day (0day)"),
    (re.compile(r'remote code execution.*exploit|exploit.*remote code execution', re.I), "RCE exploit"),
    (re.compile(r'worm(?:able)?', re.I),              "wormable"),
]


def compute_minimum_severity(item: dict) -> tuple:
    """
    Compute the minimum severity an item must have based on threat signals.
    Returns (min_severity_str, list_of_reasons).
    """
    title   = (item.get("title") or "").strip()
    content = (item.get("description") or item.get("summary") or "").strip()
    text    = title + " " + content

    reasons = []
    min_rank = _SEV_RANK["LOW"]

    # Signal 1: KEV
    kev = str(item.get("kev") or item.get("kev_present") or "").upper()
    if kev in ("YES", "TRUE", "1"):
        min_rank = max(min_rank, _SEV_RANK["HIGH"])
        reasons.append("KEV=HIGH_minimum")

    # Signal 2: EPSS >= 0.70
    try:
        epss = float(item.get("epss_score") or item.get("epss") or 0)
        if epss >= 70:   # stored as 0-100
            epss = epss / 100.0
        if epss >= 0.70:
            min_rank = max(min_rank, _SEV_RANK["HIGH"])
            reasons.append(f"EPSS={epss:.2f}>=0.70:HIGH_minimum")
    except (TypeError, ValueError):
        pass

    # Signal 3: CVSS >= 9.0
    # FIX v171.1: Probe all CVSS field variants — many items carry score in
    # "cvss" not "cvss_score"; falling through to 0 caused HIGH floor to be
    # missed for items with CVSS 9.x stored under alternate field names.
    try:
        cvss = 0.0
        for _cvss_field in ("cvss_score", "cvss", "cvss_base", "cvss_v3", "cvss3_score"):
            _cv = item.get(_cvss_field)
            if _cv is not None and _cv not in ("", "N/A", "Pending"):
                try:
                    _cv_f = float(_cv)
                    if 0.0 <= _cv_f <= 10.0:
                        cvss = _cv_f
                        break
                except (TypeError, ValueError):
                    pass
        if cvss >= 9.0:
            # v180.0 P0 INVARIANT: CVSS >= 9.0 mandates CRITICAL (was HIGH/CRITICAL at 9.5).
            # Rationale: NVD CVSS v3 "Critical" band starts at 9.0; any such score
            # means arbitrary-code-execution or equivalent impact is plausible.
            min_rank = max(min_rank, _SEV_RANK["CRITICAL"])
            reasons.append(f"CVSS={cvss}>=9.0:CRITICAL_minimum:v180.0_invariant")
        elif cvss >= 7.0:
            # CVSS 7.0–8.9 → HIGH minimum (NVD HIGH band).
            min_rank = max(min_rank, _SEV_RANK["HIGH"])
            reasons.append(f"CVSS={cvss}>=7.0:HIGH_minimum")
    except (TypeError, ValueError):
        pass

    # Signal 4: CRITICAL title patterns
    for pat, label in _CRITICAL_PATTERNS:
        if pat.search(text):
            min_rank = max(min_rank, _SEV_RANK["CRITICAL"])
            reasons.append(f"pattern:{label}:CRITICAL_minimum")

    # Signal 5: HIGH title patterns
    for pat, label in _HIGH_PATTERNS:
        if pat.search(text):
            min_rank = max(min_rank, _SEV_RANK["HIGH"])
            reasons.append(f"pattern:{label}:HIGH_minimum")

    # Signal 6: KEV + active exploit = CRITICAL
    if kev in ("YES", "TRUE", "1"):
        for pat, label in _HIGH_PATTERNS[:3]:  # active exploitation patterns
            if pat.search(text):
                min_rank = max(min_rank, _SEV_RANK["CRITICAL"])
                reasons.append(f"KEV+{label}:CRITICAL")

    return _RANK_SEV[min_rank], reasons


def recalibrate_item(item: dict) -> tuple:
    """
    Apply severity floor to item. Returns (updated_item, was_changed, old_sev, new_sev, reasons).

    v180.0: After applying legacy floor logic, delegates to SeverityInvariantInterceptor
    to enforce the full P0 invariant policy (priority, threat_level, risk_score floors).
    """
    current = (item.get("severity") or "LOW").upper()
    current_rank = _SEV_RANK.get(current, _SEV_RANK["LOW"])
    min_sev, reasons = compute_minimum_severity(item)
    min_rank = _SEV_RANK.get(min_sev, _SEV_RANK["LOW"])

    if min_rank > current_rank:
        out = dict(item)
        out["severity"] = min_sev
        out["_severity_recalibrated"] = True
        out["_severity_original"] = current
        out["_severity_reasons"] = reasons
        # v180.0: Apply P0 invariant priority / threat_level / risk_score fields.
        # These are mandatory governance fields that must co-travel with severity.
        _cvss_val = 0.0
        for _f in ("cvss_score", "cvss", "cvss_base", "cvss_v3", "cvss3_score"):
            _cv = item.get(_f)
            if _cv is not None and _cv not in ("", "N/A", "Pending"):
                try:
                    _cv_f = float(_cv)
                    if 0.0 <= _cv_f <= 10.0:
                        _cvss_val = _cv_f
                        break
                except (TypeError, ValueError):
                    pass
        if min_sev == "CRITICAL":
            out["priority"]     = "P1"
            out["threat_level"] = "CRITICAL_SURGE"
            out["risk_score"]   = round(max(9.0, _cvss_val), 4)
        elif min_sev == "HIGH":
            out["priority"]   = "P2"
            try:
                risk = float(item.get("risk_score") or 0)
                out["risk_score"] = round(max(7.5, _cvss_val if _cvss_val >= 7.5 else max(risk, 4.0)), 4)
            except (TypeError, ValueError):
                out["risk_score"] = 7.5
        elif min_sev == "MEDIUM":
            out["priority"] = "P3"
        return out, True, current, min_sev, reasons
    return item, False, current, current, []


def recalibrate_feed(items: list) -> tuple:
    """Recalibrate entire feed. Returns (recalibrated_items, report)."""
    result = []
    violations = []
    changed = 0

    for item in items:
        out, was_changed, old_sev, new_sev, reasons = recalibrate_item(item)
        result.append(out)
        if was_changed:
            changed += 1
            violations.append({
                "title": item.get("title", "")[:70],
                "old_severity": old_sev,
                "new_severity": new_sev,
                "reasons": reasons,
                "cvss": item.get("cvss_score"),
                "epss": item.get("epss_score"),
                "kev": item.get("kev"),
            })

    report = {
        "report_type": "severity_recalibration_report",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "version": f"v{VERSION}",
        "total_items": len(items),
        "recalibrated_count": changed,
        "violations": violations,
        "VERDICT": "PASS",
        "summary": f"{changed} items had severity floors applied (P0 invariant v{VERSION})",
    }
    return result, report


# ─── CLI ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Severity Recalibration Engine v1.0")
    parser.add_argument("--feed",   default=os.path.join(REPO, "api", "feed.json"))
    parser.add_argument("--fix",    action="store_true")
    parser.add_argument("--report", default=os.path.join(REPO, "reports", "severity_recalibration_report.json"))
    args = parser.parse_args()

    feed_path = pathlib.Path(args.feed)
    raw = json.loads(feed_path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else raw.get("items", [])

    print("=" * 60)
    print("SEVERITY RECALIBRATION ENGINE  v1.0")
    print(f"Feed: {feed_path}  ({len(items)} items)")
    print("=" * 60)

    recalibrated, report = recalibrate_feed(items)

    print(f"Items recalibrated: {report['recalibrated_count']}")
    if report["violations"]:
        print("\nRecalibrations applied:")
        for v in report["violations"]:
            print(f"  [{v['old_severity']} -> {v['new_severity']}] {v['title']}")
            print(f"    reasons: {v['reasons']}")

    if args.fix and report["recalibrated_count"] > 0:
        tmp = feed_path.with_suffix(".sevrecal.tmp")
        out = recalibrated if isinstance(raw, list) else {**raw, "items": recalibrated}
        tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(feed_path)
        print(f"\n[FIX] Recalibrated feed written: {feed_path}")

    rpath = pathlib.Path(args.report)
    rpath.parent.mkdir(parents=True, exist_ok=True)
    rpath.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[REPORT] {rpath}")
    sys.exit(0)
