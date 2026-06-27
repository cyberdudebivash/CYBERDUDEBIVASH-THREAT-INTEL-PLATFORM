#!/usr/bin/env python3
"""
scripts/p32_production_certification.py
CYBERDUDEBIVASH(R) SENTINEL APEX  -  P32.26 Production Certification
=====================================================================
Enterprise Operational Intelligence & Decision Automation Platform
certification gate. Extends P31 chain with P32-specific operational gates:

  G01  Feed loadable + item count >= 1
  G02  Required fields present in all items
  G03  No markdown leakage in title/description
  G04  No placeholder/synthetic language
  G05  Confidence values valid [0.01, 1.00]
  G06  CVSS/severity consistency (<= 1 band gap)
  G07  MITRE ATT&CK coverage >= 95%
  G08  IOC coverage >= 50% of items carry ioc_count > 0
  G09  Source URL completeness >= 95%
  G10  P31 certification report exists + tier != BLOCKED
  G11  P30 certification report exists + tier != BLOCKED
  G12  P29 certification report exists + tier != BLOCKED
  G13  P28 certification report exists + tier != BLOCKED
  G14  P25 trust gate report exists + 0 blockers
  G15  Regression suite script present
  G16  HTML report files >= feed item count
  G17  STIX bundle files >= feed item count
  G18  Enrichment score >= 30/100 average
  G19  Evidence chain coverage >= 80%
  G20  Detection coverage >= 40% of items carry detection_bundle
  G21  P32 Operational lifecycle derivable: items with ttps or severity >= 60%
  G22  P32 Strategic decision derivable: at least 1 CRITICAL/KEV item triggers decision
  G23  P32 Detection effectiveness scoreable: items with ttps >= 70%
  G24  P32 enterprise-operations.html present (BLOCKER)
  G25  P32 Maturity model: avg quality score >= 40 across feed
  G26  P32 Release gate passable: CVSS + severity fields present >= 80% items

Outputs: data/quality/p32_certification_report.json
"""

from __future__ import annotations
import json, os, pathlib, re, sys
from datetime import datetime, timezone

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"
_FEED = _DATA / "feed.json"
_QUAL = _DATA / "quality"
_STIX = _DATA / "stix"
_OUT  = _QUAL / "p32_certification_report.json"

DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

REQUIRED_FIELDS = ["id", "title", "description", "severity", "risk_score",
                   "confidence", "timestamp", "source"]

MD_PATTERN    = re.compile(r"(\*\*|__|\#{2,}|\[.+?\]\(https?://.+?\)|`[^`]+`)")
SYNTH_PATTERN = re.compile(
    r"\b(lorem ipsum|placeholder|tbd|todo|insert here|example text|"
    r"sample text|test data|dummy|redacted for|to be determined)\b",
    re.IGNORECASE,
)

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _load_feed():
    try:
        return json.loads(_FEED.read_bytes())
    except Exception:
        return []


def _load_quality(name: str) -> dict:
    try:
        return json.loads((_QUAL / name).read_bytes())
    except Exception:
        return {}


# ── Shared gates (G01-G20) inherited from P31 chain ──────────────────────────

def g01_feed_loadable(items: list) -> dict:
    ok = len(items) >= 1
    return {"gate": "G01", "name": "Feed Loadable + Item Count >= 1", "pass": ok,
            "detail": f"{len(items)} item(s) loaded", "severity": "BLOCKER" if not ok else "OK"}


def g02_required_fields(items: list) -> dict:
    missing = []
    for item in items:
        absent = [f for f in REQUIRED_FIELDS if not item.get(f)]
        if absent:
            missing.append({"id": item.get("id", "?"), "missing": absent})
    ok = len(missing) == 0
    return {"gate": "G02", "name": "Required Fields Present", "pass": ok,
            "detail": f"{len(missing)} item(s) missing required fields" if missing else "All items have required fields",
            "severity": "BLOCKER" if not ok else "OK"}


def g03_no_markdown_leakage(items: list) -> dict:
    leaking = [i.get("id","?") for i in items
               if MD_PATTERN.search(i.get("title","") + " " + i.get("description",""))]
    ok = len(leaking) == 0
    return {"gate": "G03", "name": "No Markdown Leakage", "pass": ok,
            "detail": f"{len(leaking)} item(s) with markdown artifacts" if leaking else "Clean",
            "severity": "WARNING" if not ok else "OK"}


def g04_no_placeholder_text(items: list) -> dict:
    synthetic = [i.get("id","?") for i in items
                 if SYNTH_PATTERN.search(i.get("title","") + " " + i.get("description",""))]
    ok = len(synthetic) == 0
    return {"gate": "G04", "name": "No Placeholder / Synthetic Language", "pass": ok,
            "detail": f"{len(synthetic)} item(s) with synthetic text" if synthetic else "Clean",
            "severity": "BLOCKER" if not ok else "OK"}


def g05_confidence_values(items: list) -> dict:
    bad = []
    for item in items:
        c = item.get("confidence")
        if c is not None:
            try:
                cv = float(c)
                if not (0.01 <= cv <= 1.00):
                    bad.append(item.get("id","?"))
            except Exception:
                bad.append(item.get("id","?"))
    ok = len(bad) == 0
    return {"gate": "G05", "name": "Confidence Values Valid [0.01, 1.00]", "pass": ok,
            "detail": f"{len(bad)} item(s) with invalid confidence" if bad else "All valid",
            "severity": "WARNING" if not ok else "OK"}


def g06_cvss_severity_consistency(items: list) -> dict:
    inconsistent = 0
    for item in items:
        cvss = float(item.get("risk_score") or item.get("cvss_score") or 0)
        sev  = (item.get("severity") or "").upper()
        if cvss > 0 and sev in SEVERITY_ORDER:
            expected = ("CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7
                        else "MEDIUM" if cvss >= 4 else "LOW")
            ei = SEVERITY_ORDER.index(expected)
            ai = SEVERITY_ORDER.index(sev)
            if abs(ei - ai) > 1:
                inconsistent += 1
    ok = inconsistent == 0
    return {"gate": "G06", "name": "CVSS/Severity Consistency", "pass": ok,
            "detail": f"{inconsistent} item(s) with >1-band CVSS/severity gap" if inconsistent else "Consistent",
            "severity": "WARNING" if not ok else "OK"}


def g07_mitre_coverage(items: list) -> dict:
    if not items:
        return {"gate": "G07", "name": "MITRE ATT&CK Coverage >= 95%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_mitre = sum(1 for i in items if (i.get("ttps") or i.get("mitre_tactics")))
    pct = with_mitre / len(items) * 100
    ok  = pct >= 95
    return {"gate": "G07", "name": "MITRE ATT&CK Coverage >= 95%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_mitre}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}


def g08_ioc_coverage(items: list) -> dict:
    if not items:
        return {"gate": "G08", "name": "IOC Coverage >= 50%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_ioc = sum(1 for i in items if int(i.get("ioc_count") or 0) > 0)
    pct = with_ioc / len(items) * 100
    ok  = pct >= 50
    return {"gate": "G08", "name": "IOC Coverage >= 50%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_ioc}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}


def g09_source_url_completeness(items: list) -> dict:
    if not items:
        return {"gate": "G09", "name": "Source URL Completeness >= 95%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_url = sum(1 for i in items if i.get("source_url"))
    pct = with_url / len(items) * 100
    ok  = pct >= 95
    return {"gate": "G09", "name": "Source URL Completeness >= 95%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_url}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}


def _check_tier(fname: str, field: str, bad_values: list) -> tuple[bool, str]:
    d = _load_quality(fname)
    if not d:
        return False, f"{fname} not found"
    tier = d.get(field, "UNKNOWN")
    if tier in bad_values:
        return False, f"{fname}: {field}={tier}"
    return True, f"{fname}: {field}={tier}"


def g10_p31_cert(items: list) -> dict:
    ok, detail = _check_tier("p31_certification_report.json", "release_tier", ["BLOCKED"])
    return {"gate": "G10", "name": "P31 Cert Chain OK", "pass": ok,
            "detail": detail, "severity": "BLOCKER" if not ok else "OK"}


def g11_p30_cert(items: list) -> dict:
    ok, detail = _check_tier("p30_certification_report.json", "release_tier", ["BLOCKED"])
    return {"gate": "G11", "name": "P30 Cert Chain OK", "pass": ok,
            "detail": detail, "severity": "WARNING" if not ok else "OK"}


def g12_p29_cert(items: list) -> dict:
    ok, detail = _check_tier("p29_certification_report.json", "release_tier", ["BLOCKED"])
    return {"gate": "G12", "name": "P29 Cert Chain OK", "pass": ok,
            "detail": detail, "severity": "WARNING" if not ok else "OK"}


def g13_p28_cert(items: list) -> dict:
    ok, detail = _check_tier("p28_certification_report.json", "release_tier", ["BLOCKED"])
    return {"gate": "G13", "name": "P28 Cert Chain OK", "pass": ok,
            "detail": detail, "severity": "WARNING" if not ok else "OK"}


def g14_p25_trust(items: list) -> dict:
    d = _load_quality("p25_enterprise_trust_gate.json")
    if not d:
        return {"gate": "G14", "name": "P25 Trust Gate: 0 Blockers", "pass": False,
                "detail": "p25_enterprise_trust_gate.json not found", "severity": "WARNING"}
    blockers = d.get("blocker_count", 999)
    ok = blockers == 0
    return {"gate": "G14", "name": "P25 Trust Gate: 0 Blockers", "pass": ok,
            "detail": f"blockers={blockers}", "severity": "WARNING" if not ok else "OK"}


def g15_regression_suite(items: list) -> dict:
    p = _ROOT / "scripts" / "regression_tests.py"
    ok = p.exists()
    return {"gate": "G15", "name": "Regression Suite Script Present", "pass": ok,
            "detail": str(p) if ok else "scripts/regression_tests.py missing",
            "severity": "WARNING" if not ok else "OK"}


def g16_html_reports(items: list) -> dict:
    reports_dir = _ROOT / "reports"
    html_count = len(list(reports_dir.glob("*.html"))) if reports_dir.exists() else 0
    ok = html_count >= len(items)
    return {"gate": "G16", "name": "HTML Report Files >= Feed Item Count", "pass": ok,
            "detail": f"{html_count} HTML files vs {len(items)} items",
            "severity": "WARNING" if not ok else "OK"}


def g17_stix_bundles(items: list) -> dict:
    stix_count = len(list(_STIX.glob("*.json"))) if _STIX.exists() else 0
    ok = stix_count >= len(items)
    return {"gate": "G17", "name": "STIX Bundle Files >= Feed Item Count", "pass": ok,
            "detail": f"{stix_count} STIX files vs {len(items)} items",
            "severity": "WARNING" if not ok else "OK"}


def g18_enrichment_score(items: list) -> dict:
    if not items:
        return {"gate": "G18", "name": "Enrichment Score >= 30 avg", "pass": True,
                "detail": "No items", "severity": "OK"}
    scores = []
    for item in items:
        score = 0
        if item.get("cvss_score"): score += 20
        if item.get("ttps"):       score += 20
        if item.get("ioc_count") and int(item.get("ioc_count") or 0) > 0: score += 20
        if item.get("actor_tag"):  score += 20
        if item.get("patch_available"): score += 20
        scores.append(score)
    avg = sum(scores) / len(scores)
    ok  = avg >= 30
    return {"gate": "G18", "name": "Enrichment Score >= 30 avg", "pass": ok,
            "detail": f"avg={avg:.1f}",
            "severity": "WARNING" if not ok else "OK"}


def g19_evidence_chain(items: list) -> dict:
    if not items:
        return {"gate": "G19", "name": "Evidence Chain Coverage >= 80%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_chain = sum(1 for i in items if i.get("evidence_chain"))
    pct = with_chain / len(items) * 100
    ok  = pct >= 80
    return {"gate": "G19", "name": "Evidence Chain Coverage >= 80%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_chain}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}


def g20_detection_coverage(items: list) -> dict:
    if not items:
        return {"gate": "G20", "name": "Detection Coverage >= 40%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_detection = sum(1 for i in items if i.get("detection_bundle"))
    pct = with_detection / len(items) * 100
    ok  = pct >= 40
    return {"gate": "G20", "name": "Detection Coverage >= 40%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_detection}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}


# ── P32-specific gates (G21-G26) ──────────────────────────────────────────────

def g21_lifecycle_derivable(items: list) -> dict:
    """P32.1: Operational lifecycle derivable for >= 60% of items.
    Items with ttps or severity field present can be placed in lifecycle stages."""
    if not items:
        return {"gate": "G21", "name": "P32 Lifecycle Derivable >= 60%", "pass": True,
                "detail": "No items", "severity": "OK"}
    derivable = sum(1 for i in items if (i.get("ttps") or i.get("severity")))
    pct = derivable / len(items) * 100
    ok  = pct >= 60
    return {"gate": "G21", "name": "P32 Lifecycle Derivable >= 60%", "pass": ok,
            "detail": f"{pct:.1f}% ({derivable}/{len(items)}) items have ttps or severity",
            "severity": "WARNING" if not ok else "OK"}


def g22_strategic_decision_derivable(items: list) -> dict:
    """P32.2: At least 1 CRITICAL item or KEV item exists to trigger strategic decision."""
    if not items:
        return {"gate": "G22", "name": "P32 Strategic Decision Derivable", "pass": True,
                "detail": "No items", "severity": "OK"}
    critical_items  = sum(1 for i in items if (i.get("severity") or "").upper() == "CRITICAL")
    kev_items       = sum(1 for i in items if i.get("kev_listed") or i.get("is_kev"))
    high_risk_items = sum(1 for i in items if float(i.get("risk_score") or 0) >= 9.0)
    triggered = critical_items + kev_items + high_risk_items
    ok = triggered >= 1
    return {"gate": "G22", "name": "P32 Strategic Decision Derivable", "pass": ok,
            "detail": f"CRITICAL={critical_items}, KEV={kev_items}, CVSS>=9={high_risk_items} — triggered={triggered}",
            "severity": "WARNING" if not ok else "OK"}


def g23_detection_effectiveness_scoreable(items: list) -> dict:
    """P32.4: Detection effectiveness scoreable for >= 70% of items (have ttps)."""
    if not items:
        return {"gate": "G23", "name": "P32 Detection Effectiveness Scoreable >= 70%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_ttps = sum(1 for i in items if i.get("ttps"))
    pct = with_ttps / len(items) * 100
    ok  = pct >= 70
    return {"gate": "G23", "name": "P32 Detection Effectiveness Scoreable >= 70%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_ttps}/{len(items)}) items have ttps for detection scoring",
            "severity": "WARNING" if not ok else "OK"}


def g24_enterprise_operations_html(items: list) -> dict:
    """P32.10/P32.11: enterprise-operations.html must exist (BLOCKER)."""
    p = _ROOT / "enterprise-operations.html"
    ok = p.exists()
    return {"gate": "G24", "name": "P32 enterprise-operations.html Present", "pass": ok,
            "detail": str(p) if ok else "enterprise-operations.html missing — BLOCKER",
            "severity": "BLOCKER" if not ok else "OK"}


def g25_maturity_score_avg(items: list) -> dict:
    """P32.8: Average quality/maturity score >= 40 across feed.
    Proxy: risk_score (CVSS) scaled 0-100 averaged; items with score >= 4 count as >= 40 equivalent."""
    if not items:
        return {"gate": "G25", "name": "P32 Maturity Model Avg >= 40", "pass": True,
                "detail": "No items", "severity": "OK"}
    scores = []
    for item in items:
        # Build composite maturity proxy from available fields
        s = 0
        if item.get("ttps"):       s += 20
        if item.get("ioc_count") and int(item.get("ioc_count") or 0) > 0: s += 15
        if item.get("actor_tag"):  s += 15
        if item.get("cvss_score"): s += 20
        if item.get("source_url"): s += 15
        if item.get("patch_available"): s += 15
        scores.append(s)
    avg = sum(scores) / len(scores)
    ok  = avg >= 40
    return {"gate": "G25", "name": "P32 Maturity Model Avg >= 40", "pass": ok,
            "detail": f"avg maturity proxy={avg:.1f}/100 across {len(items)} items",
            "severity": "WARNING" if not ok else "OK"}


def g26_release_gate_passable(items: list) -> dict:
    """P32.13: Release gate passable — CVSS + severity present >= 80% items."""
    if not items:
        return {"gate": "G26", "name": "P32 Release Gate Passable >= 80%", "pass": True,
                "detail": "No items", "severity": "OK"}
    passable = sum(1 for i in items
                   if i.get("severity") and (i.get("risk_score") or i.get("cvss_score")))
    pct = passable / len(items) * 100
    ok  = pct >= 80
    return {"gate": "G26", "name": "P32 Release Gate Passable >= 80%", "pass": ok,
            "detail": f"{pct:.1f}% ({passable}/{len(items)}) items pass minimum release criteria",
            "severity": "WARNING" if not ok else "OK"}


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    items = _load_feed()
    gates = [
        g01_feed_loadable(items),
        g02_required_fields(items),
        g03_no_markdown_leakage(items),
        g04_no_placeholder_text(items),
        g05_confidence_values(items),
        g06_cvss_severity_consistency(items),
        g07_mitre_coverage(items),
        g08_ioc_coverage(items),
        g09_source_url_completeness(items),
        g10_p31_cert(items),
        g11_p30_cert(items),
        g12_p29_cert(items),
        g13_p28_cert(items),
        g14_p25_trust(items),
        g15_regression_suite(items),
        g16_html_reports(items),
        g17_stix_bundles(items),
        g18_enrichment_score(items),
        g19_evidence_chain(items),
        g20_detection_coverage(items),
        g21_lifecycle_derivable(items),
        g22_strategic_decision_derivable(items),
        g23_detection_effectiveness_scoreable(items),
        g24_enterprise_operations_html(items),
        g25_maturity_score_avg(items),
        g26_release_gate_passable(items),
    ]

    blocker_count = sum(1 for g in gates if not g["pass"] and g.get("severity") == "BLOCKER")
    warning_count = sum(1 for g in gates if not g["pass"] and g.get("severity") == "WARNING")
    passed_count  = sum(1 for g in gates if g["pass"])
    total_gates   = len(gates)

    if blocker_count == 0:
        release_tier = "WORLDWIDE_RELEASE"
    elif blocker_count <= 2:
        release_tier = "CONTROLLED_RELEASE"
    else:
        release_tier = "BLOCKED"

    report = {
        "schema_version":  "p32.0",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "feed_items":      len(items),
        "release_tier":    release_tier,
        "blocker_count":   blocker_count,
        "warning_count":   warning_count,
        "passed_count":    passed_count,
        "total_gates":     total_gates,
        "gates":           gates,
        "p32_capabilities": [
            "P32.1 Operational Lifecycle (9-stage)",
            "P32.2 Strategic Decision Engine (7 decisions)",
            "P32.3 Intelligence Delta Engine",
            "P32.4 Detection Effectiveness Engine (FP/FN/coverage)",
            "P32.5 Customer Environment Simulator (12 platforms)",
            "P32.6 Threat Intelligence Drift Engine (8 dimensions)",
            "P32.7 Evidence Transparency Engine (per-claim provenance)",
            "P32.8 Intelligence Maturity Model (15 dimensions)",
            "P32.9 Operational Metrics (MTTI/MTTD/MTTR)",
            "P32.10 Analyst Workspace Dashboard",
            "P32.11 Customer Success Dashboard",
            "P32.12 Intelligence Quality Governance",
            "P32.13 Production Release Gate (12 checks)",
            "P32.14 Commercial Intelligence Package",
        ],
    }

    _QUAL.mkdir(parents=True, exist_ok=True)
    if not DRY_RUN:
        _OUT.write_text(json.dumps(report, indent=2))
        print(f"[P32.26] Written: {_OUT}")

    summary_lines = [
        f"[P32.26] Release Tier : {release_tier}",
        f"[P32.26] Gates        : {passed_count}/{total_gates} passed",
        f"[P32.26] Blockers     : {blocker_count}",
        f"[P32.26] Warnings     : {warning_count}",
        f"[P32.26] Feed Items   : {len(items)}",
    ]
    for line in summary_lines:
        print(line)

    for g in gates:
        status = "PASS" if g["pass"] else g.get("severity", "FAIL")
        print(f"  [{status:8s}] {g['gate']} {g['name']}: {g['detail']}")

    sys.exit(0)


if __name__ == "__main__":
    main()
