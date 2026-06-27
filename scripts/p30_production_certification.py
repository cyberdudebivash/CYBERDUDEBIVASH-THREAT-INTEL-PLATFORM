#!/usr/bin/env python3
"""
scripts/p30_production_certification.py
CYBERDUDEBIVASH(R) SENTINEL APEX  -  P30.26 Production Certification
=====================================================================
Enterprise Intelligence Accuracy & Continuous Verification Platform
certification gate. Extends P29 chain with P30-specific accuracy gates:

  G01  Feed loadable + item count >= 1
  G02  Required fields present in all items
  G03  No markdown leakage in title/description
  G04  No placeholder/synthetic language
  G05  Confidence values valid [0.01, 1.00]
  G06  CVSS/severity consistency (<= 1 band gap)
  G07  MITRE ATT&CK coverage >= 95%
  G08  IOC coverage >= 50% of items carry ioc_count > 0
  G09  Source URL completeness >= 95%
  G10  P29 certification report exists + tier != BLOCKED
  G11  P28 certification report exists + tier != BLOCKED
  G12  P27 certification report exists + tier != BLOCKED
  G13  P26 certification report exists + tier != REJECTED
  G14  P25 trust gate report exists + 0 blockers
  G15  Regression suite script present
  G16  HTML report files >= feed item count
  G17  STIX bundle files >= feed item count
  G18  Enrichment score >= 30/100 average
  G19  Evidence chain coverage >= 80%
  G20  Detection coverage >= 40% of items carry detection_bundle
  G21  Verification signal coverage >= 60% avg across items
  G22  Source URL attribution completeness >= 90%
  G23  SLA compliance: zero items with patch overdue > 180 days
  G24  enterprise-intelligence-health-dashboard.html present
  G25  IOC lifecycle derivable: items with IOCs have required timestamp fields
  G26  Change tracking: severity/CVSS consistency < 20% anomaly rate

Outputs: data/quality/p30_certification_report.json
"""

from __future__ import annotations
import json, os, pathlib, re, sys
from datetime import datetime, timezone

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"
_FEED = _DATA / "feed.json"
_QUAL = _DATA / "quality"
_STIX = _DATA / "stix"
_OUT  = _QUAL / "p30_certification_report.json"

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


def _age_hours(ts: str) -> float:
    if not ts:
        return -1
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return (datetime.utcnow() - dt).total_seconds() / 3600
    except Exception:
        return -1


# ── Gate definitions ──────────────────────────────────────────────────────────

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


def g10_p29_cert(items: list) -> dict:
    ok, detail = _check_tier("p29_certification_report.json", "release_tier", ["BLOCKED"])
    return {"gate": "G10", "name": "P29 Cert Report + tier != BLOCKED", "pass": ok,
            "detail": detail, "severity": "BLOCKER" if not ok else "OK"}


def g11_p28_cert(items: list) -> dict:
    ok, detail = _check_tier("p28_certification_report.json", "release_tier", ["BLOCKED"])
    return {"gate": "G11", "name": "P28 Cert Report + tier != BLOCKED", "pass": ok,
            "detail": detail, "severity": "BLOCKER" if not ok else "OK"}


def g12_p27_cert(items: list) -> dict:
    ok, detail = _check_tier("p27_certification_report.json", "release_tier", ["BLOCKED"])
    return {"gate": "G12", "name": "P27 Cert Report + tier != BLOCKED", "pass": ok,
            "detail": detail, "severity": "BLOCKER" if not ok else "OK"}


def g13_p26_cert(items: list) -> dict:
    ok, detail = _check_tier("p26_certification_report.json", "release_tier", ["REJECTED"])
    return {"gate": "G13", "name": "P26 Cert Report + tier != REJECTED", "pass": ok,
            "detail": detail, "severity": "WARNING" if not ok else "OK"}


def g14_p25_trust(items: list) -> dict:
    d = _load_quality("p25_enterprise_trust_gate.json")
    if not d:
        return {"gate": "G14", "name": "P25 Trust Gate + 0 blockers", "pass": False,
                "detail": "p25_enterprise_trust_gate.json not found", "severity": "BLOCKER"}
    bc = d.get("blocker_count", 0)
    ok = bc == 0
    return {"gate": "G14", "name": "P25 Trust Gate + 0 blockers", "pass": ok,
            "detail": f"blocker_count={bc}", "severity": "BLOCKER" if not ok else "OK"}


def g15_regression_present(items: list) -> dict:
    reg = _ROOT / "scripts" / "regression_tests.py"
    if not reg.exists():
        return {"gate": "G15", "name": "Regression Suite Script Present", "pass": False,
                "detail": "regression_tests.py not found", "severity": "WARNING"}
    return {"gate": "G15", "name": "Regression Suite Script Present", "pass": True,
            "detail": "regression_tests.py exists — authoritative run is Stage 5.6 in CI",
            "severity": "OK"}


def g16_html_reports(items: list) -> dict:
    html_dir = _DATA / "intelligence" / "reports"
    if not html_dir.exists():
        html_dir = _DATA / "reports"
    html_files = list(_DATA.rglob("*.html")) if not html_dir.exists() else list(html_dir.rglob("*.html"))
    n_html = len(html_files)
    n_items = len(items)
    ok = n_html >= n_items
    return {"gate": "G16", "name": "HTML Reports >= Feed Item Count", "pass": ok,
            "detail": f"{n_html} HTML files vs {n_items} items",
            "severity": "WARNING" if not ok else "OK"}


def g17_stix_bundles(items: list) -> dict:
    stix_files = list(_STIX.rglob("*.json")) if _STIX.exists() else []
    n_stix  = len(stix_files)
    n_items = len(items)
    ok = n_stix >= n_items
    return {"gate": "G17", "name": "STIX Bundles >= Feed Item Count", "pass": ok,
            "detail": f"{n_stix} STIX files vs {n_items} items",
            "severity": "WARNING" if not ok else "OK"}


def g18_enrichment_score(items: list) -> dict:
    if not items:
        return {"gate": "G18", "name": "Enrichment Score >= 30", "pass": True,
                "detail": "No items", "severity": "OK"}
    avg = sum(float(i.get("enrichment_score") or 0) for i in items) / len(items)
    ok  = avg >= 30
    return {"gate": "G18", "name": "Enrichment Score >= 30 avg", "pass": ok,
            "detail": f"avg={avg:.1f}", "severity": "WARNING" if not ok else "OK"}


def g19_evidence_chain(items: list) -> dict:
    if not items:
        return {"gate": "G19", "name": "Evidence Chain Coverage >= 80%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_ev = sum(1 for i in items if isinstance(i.get("evidence_chain"), list) and len(i["evidence_chain"]) > 0)
    pct = with_ev / len(items) * 100
    ok  = pct >= 80
    return {"gate": "G19", "name": "Evidence Chain Coverage >= 80%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_ev}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}


def g20_detection_coverage(items: list) -> dict:
    if not items:
        return {"gate": "G20", "name": "Detection Coverage >= 40%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_det = sum(1 for i in items if i.get("detection_bundle") and len(i["detection_bundle"]) > 0)
    pct = with_det / len(items) * 100
    ok  = pct >= 40
    return {"gate": "G20", "name": "Detection Coverage >= 40%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_det}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}


# ── P30-specific gates ────────────────────────────────────────────────────────

def g21_verification_signal_coverage(items: list) -> dict:
    """P30.1: avg verification signal coverage >= 60%."""
    if not items:
        return {"gate": "G21", "name": "P30.1 Verification Signal Coverage >= 60%", "pass": True,
                "detail": "No items", "severity": "OK"}
    scores = []
    for item in items:
        signals = [
            bool(item.get("nvd_url") or (item.get("apex") or {}).get("nvd_url")),
            bool(item.get("kev_present") or (item.get("apex") or {}).get("kev_listed")),
            item.get("epss_score") is not None and item.get("epss_score") != "",
            bool(item.get("risk_score") or item.get("cvss_score")),
            bool(item.get("source_url")),
            isinstance(item.get("evidence_chain"), list) and len(item["evidence_chain"]) > 0,
            isinstance(item.get("ttps"), list) and len(item["ttps"]) > 0,
            int(item.get("ioc_count") or 0) > 0,
        ]
        scores.append(sum(signals) / len(signals) * 100)
    avg = sum(scores) / len(scores)
    ok  = avg >= 60
    return {"gate": "G21", "name": "P30.1 Verification Signal Coverage >= 60%", "pass": ok,
            "detail": f"avg={avg:.1f}%",
            "severity": "WARNING" if not ok else "OK"}


def g22_source_attribution(items: list) -> dict:
    """P30: Source attribution completeness >= 90%."""
    if not items:
        return {"gate": "G22", "name": "P30 Source Attribution >= 90%", "pass": True,
                "detail": "No items", "severity": "OK"}
    with_src = sum(1 for i in items if i.get("source") and i.get("source_url"))
    pct = with_src / len(items) * 100
    ok  = pct >= 90
    return {"gate": "G22", "name": "P30 Source Attribution >= 90%", "pass": ok,
            "detail": f"{pct:.1f}% ({with_src}/{len(items)}) have both source + source_url",
            "severity": "WARNING" if not ok else "OK"}


def g23_sla_compliance(items: list) -> dict:
    """P30.7: No items with patch window overdue > 180 days."""
    PATCH_DAYS   = {"CRITICAL": 15, "HIGH": 30, "MEDIUM": 45, "LOW": 90, "INFO": 90}
    THRESHOLD_DAYS = 180
    severely_overdue = []
    for item in items:
        ts = item.get("timestamp") or item.get("published_at") or item.get("processed_at") or ""
        age_h = _age_hours(ts)
        if age_h < 0:
            continue
        sev = (item.get("severity") or "LOW").upper()
        patch_d = PATCH_DAYS.get(sev, 90)
        overdue_d = (age_h / 24) - patch_d
        if overdue_d > THRESHOLD_DAYS:
            severely_overdue.append(item.get("id", "?"))
    ok = len(severely_overdue) == 0
    return {"gate": "G23", "name": "P30.7 SLA Compliance: No Patch Overdue > 180d", "pass": ok,
            "detail": f"{len(severely_overdue)} item(s) severely overdue" if severely_overdue else "All within 180d overdue threshold",
            "severity": "WARNING" if not ok else "OK"}


def g24_health_dashboard_present(items: list) -> dict:
    """P30.9: enterprise-intelligence-health-dashboard.html must exist."""
    dash = _ROOT / "enterprise-intelligence-health-dashboard.html"
    ok = dash.exists()
    return {"gate": "G24", "name": "P30.9 Health Dashboard HTML Present", "pass": ok,
            "detail": str(dash) if ok else f"{dash} not found",
            "severity": "BLOCKER" if not ok else "OK"}


def g25_ioc_lifecycle_derivable(items: list) -> dict:
    """P30.5: Items with IOCs have at least one timestamp field for lifecycle derivation."""
    ioc_items = [i for i in items if int(i.get("ioc_count") or 0) > 0]
    if not ioc_items:
        return {"gate": "G25", "name": "P30.5 IOC Lifecycle Derivable", "pass": True,
                "detail": "No IOC-carrying items", "severity": "OK"}
    ts_fields = ["timestamp", "published_at", "processed_at", "validated_at", "generated_at"]
    derivable = sum(1 for i in ioc_items if any(i.get(f) for f in ts_fields))
    pct = derivable / len(ioc_items) * 100
    ok  = pct >= 80
    return {"gate": "G25", "name": "P30.5 IOC Lifecycle Derivable >= 80%", "pass": ok,
            "detail": f"{pct:.1f}% ({derivable}/{len(ioc_items)}) IOC items have timestamp",
            "severity": "WARNING" if not ok else "OK"}


def g26_severity_cvss_anomaly_rate(items: list) -> dict:
    """P30.3: Severity/CVSS anomaly rate < 20%."""
    if not items:
        return {"gate": "G26", "name": "P30.3 Change Anomaly Rate < 20%", "pass": True,
                "detail": "No items", "severity": "OK"}
    SORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    anomalies = 0
    for item in items:
        cvss = float(item.get("risk_score") or item.get("cvss_score") or 0)
        sev  = (item.get("severity") or "").upper()
        if cvss > 0 and sev in SORDER:
            expected = ("CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7
                        else "MEDIUM" if cvss >= 4 else "LOW")
            if abs(SORDER.index(expected) - SORDER.index(sev)) > 1:
                anomalies += 1
    pct = anomalies / len(items) * 100
    ok  = pct < 20
    return {"gate": "G26", "name": "P30.3 Change Anomaly Rate < 20%", "pass": ok,
            "detail": f"{pct:.1f}% anomaly rate ({anomalies}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}


# ── Main ──────────────────────────────────────────────────────────────────────

_GATES = [
    g01_feed_loadable, g02_required_fields, g03_no_markdown_leakage,
    g04_no_placeholder_text, g05_confidence_values, g06_cvss_severity_consistency,
    g07_mitre_coverage, g08_ioc_coverage, g09_source_url_completeness,
    g10_p29_cert, g11_p28_cert, g12_p27_cert, g13_p26_cert, g14_p25_trust,
    g15_regression_present, g16_html_reports, g17_stix_bundles,
    g18_enrichment_score, g19_evidence_chain, g20_detection_coverage,
    g21_verification_signal_coverage, g22_source_attribution,
    g23_sla_compliance, g24_health_dashboard_present,
    g25_ioc_lifecycle_derivable, g26_severity_cvss_anomaly_rate,
]


def main() -> None:
    items = _load_feed()
    results = [g(items) for g in _GATES]

    blockers = [r for r in results if not r["pass"] and r["severity"] == "BLOCKER"]
    warnings = [r for r in results if not r["pass"] and r["severity"] == "WARNING"]
    passed   = [r for r in results if r["pass"]]

    if len(blockers) == 0:
        tier = "WORLDWIDE_RELEASE"
    elif len(blockers) <= 2:
        tier = "CONTROLLED_RELEASE"
    else:
        tier = "BLOCKED"

    report = {
        "schema_version":  "p30.0",
        "generated_at":    datetime.utcnow().isoformat() + "Z",
        "dry_run":         DRY_RUN,
        "release_tier":    tier,
        "blocker_count":   len(blockers),
        "warning_count":   len(warnings),
        "passed_count":    len(passed),
        "total_gates":     len(results),
        "feed_items":      len(items),
        "gates":           results,
        "quality_summary": {
            "p30_items_checked": len(items),
        },
    }

    _QUAL.mkdir(parents=True, exist_ok=True)
    if not DRY_RUN:
        (_OUT).write_text(json.dumps(report, indent=2))
        print(f"[P30] Written: {_OUT}")

    print(f"\n{'='*60}")
    print(f"  CYBERDUDEBIVASH(R) SENTINEL APEX - P30.26 CERTIFICATION")
    print(f"{'='*60}")
    print(f"  Release Tier : {tier}")
    print(f"  Gates        : {len(passed)}/{len(results)} passed")
    print(f"  Blockers     : {len(blockers)}")
    print(f"  Warnings     : {len(warnings)}")
    print(f"  Feed Items   : {len(items)}")
    print(f"{'='*60}\n")

    for r in results:
        icon = "✓" if r["pass"] else ("✗" if r["severity"] == "BLOCKER" else "⚠")
        print(f"  {icon} [{r['gate']}] {r['name']}: {r['detail']}")

    if blockers:
        print(f"\n  BLOCKERS:")
        for b in blockers:
            print(f"    ✗ [{b['gate']}] {b['name']}: {b['detail']}")

    print(f"\n  RESULT: {tier}\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
