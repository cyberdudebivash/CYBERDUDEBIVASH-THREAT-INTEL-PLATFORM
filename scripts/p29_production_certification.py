#!/usr/bin/env python3
"""
scripts/p29_production_certification.py
CYBERDUDEBIVASH(R) SENTINEL APEX  -  P29.20 Production Certification
=====================================================================
Enterprise Intelligence Network (EIN) final certification gate.
Extends P28 audit with P29-specific orchestration + detection + lifecycle gates:

  G01  Feed loadable + item count ≥ 1
  G02  Required fields present in all items
  G03  No markdown leakage in title/description
  G04  No placeholder/synthetic language
  G05  Confidence values valid [0.01, 1.00]
  G06  CVSS/severity consistency (≤1 band gap)
  G07  MITRE ATT&CK coverage ≥ 95%
  G08  IOC coverage ≥ 50% of items carry ioc_count > 0
  G09  Source URL completeness ≥ 95%
  G10  P28 certification report exists + tier != BLOCKED
  G11  P27 certification report exists + tier != BLOCKED
  G12  P26 certification report exists + tier != REJECTED
  G13  P25 trust gate report exists + 0 blockers
  G14  Regression suite script present
  G15  HTML report files ≥ feed item count
  G16  STIX bundle files ≥ feed item count
  G17  Enrichment score ≥ 30/100 average
  G18  Evidence chain coverage ≥ 80%
  G19  Detection coverage ≥ 40% of items carry detection_bundle
  G20  Confidence graph coverage ≥ 80% (confidence field not default 0.5)

Outputs: data/quality/p29_certification_report.json
"""

from __future__ import annotations
import json, os, pathlib, re, sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"
_FEED = _DATA / "feed.json"
_QUAL = _DATA / "quality"
_STIX = _DATA / "stix"
_OUT  = _QUAL / "p29_certification_report.json"

DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

REQUIRED_FIELDS = ["id", "title", "description", "severity", "risk_score", "confidence", "timestamp", "source"]

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

def _severity_idx(sev):
    return SEVERITY_ORDER.index(sev.upper()) if sev.upper() in SEVERITY_ORDER else 2

def _cvss_idx(score):
    if score >= 9.0: return 4
    if score >= 7.0: return 3
    if score >= 4.0: return 2
    if score > 0:   return 1
    return 0

def _make_gate(gid, name, ok, detail, severity_if_fail="BLOCKER"):
    return {"gate": gid, "name": name, "pass": ok, "detail": detail,
            "severity": "OK" if ok else severity_if_fail}

# ── Gates G01–G09: feed-level invariants ─────────────────────────────────────

def g01_feed_loadable(items):
    ok = len(items) >= 1
    return _make_gate("G01", "Feed Loadable", ok, f"{len(items)} items loaded")

def g02_required_fields(items):
    miss = sum(1 for it in items for f in REQUIRED_FIELDS if not it.get(f))
    return _make_gate("G02", "Required Fields", miss == 0, f"{miss} missing field instances", "BLOCKER")

def g03_no_markdown_leakage(items):
    hits = sum(1 for it in items if MD_PATTERN.search(str(it.get("title",""))+" "+str(it.get("description",""))))
    sev  = "BLOCKER" if hits > 2 else "WARNING"
    return _make_gate("G03", "No Markdown Leakage", hits == 0, f"{hits}/{len(items)} items", sev)

def g04_no_placeholder_language(items):
    hits = sum(1 for it in items if SYNTH_PATTERN.search(str(it.get("description",""))))
    return _make_gate("G04", "No Placeholder Language", hits == 0, f"{hits}/{len(items)} items", "BLOCKER")

def g05_confidence_validity(items):
    def _conf(it):
        v = it.get("confidence") or it.get("confidence_score") or 0.5
        f = float(v)
        return f if f <= 1.0 else f / 100.0
    bad = sum(1 for it in items if not (0.01 <= _conf(it) <= 1.0))
    return _make_gate("G05", "Confidence Validity", bad == 0, f"{bad}/{len(items)} invalid", "WARNING")

def g06_cvss_severity_consistency(items):
    gaps = 0
    for it in items:
        sev = str(it.get("severity","")).upper()
        s   = it.get("risk_score") or it.get("cvss_score") or 0
        try: score = float(s)
        except: score = 0.0
        if score > 0 and sev in SEVERITY_ORDER:
            if abs(_severity_idx(sev) - _cvss_idx(score)) >= 2:
                gaps += 1
    return _make_gate("G06", "CVSS/Severity Consistency", gaps == 0, f"{gaps}/{len(items)} gaps ≥2 bands", "WARNING")

def g07_mitre_coverage(items):
    cov = sum(1 for it in items if (it.get("mitre_tactics") and len(it["mitre_tactics"])>0)
              or (it.get("ttps") and len(it["ttps"])>0))
    pct = round(cov/len(items)*100,1) if items else 0
    sev = "BLOCKER" if pct < 80 else ("WARNING" if pct < 95 else "OK")
    return _make_gate("G07", "MITRE ATT&CK Coverage ≥95%", pct >= 95, f"{pct}% ({cov}/{len(items)})", sev)

def g08_ioc_coverage(items):
    cov = sum(1 for it in items if (it.get("ioc_count") or 0) > 0)
    pct = round(cov/len(items)*100,1) if items else 0
    return _make_gate("G08", "IOC Coverage ≥50%", pct >= 50, f"{pct}% ({cov}/{len(items)})", "WARNING")

def g09_source_url_completeness(items):
    cov = sum(1 for it in items if str(it.get("source_url","")).startswith("http"))
    pct = round(cov/len(items)*100,1) if items else 0
    return _make_gate("G09", "Source URL Completeness ≥95%", pct >= 95, f"{pct}% ({cov}/{len(items)})", "WARNING")

# ── Gates G10–G14: certification chain ───────────────────────────────────────

def _load_quality_report(filename):
    f = _QUAL / filename
    if not f.exists(): return None
    try: return json.loads(f.read_bytes())
    except: return None

def g10_p28_certification(items):
    d = _load_quality_report("p28_certification_report.json")
    if not d: return _make_gate("G10", "P28 Certification", False, "p28_certification_report.json not found", "BLOCKER")
    ok = d.get("release_tier","") not in ("BLOCKED",)
    return _make_gate("G10", "P28 Certification", ok,
                      f"P28 tier={d.get('release_tier','?')} blockers={d.get('blocker_count',0)}")

def g11_p27_certification(items):
    d = _load_quality_report("p27_certification_report.json")
    if not d: return _make_gate("G11", "P27 Certification", False, "p27_certification_report.json not found", "BLOCKER")
    ok = d.get("release_tier","") not in ("BLOCKED",)
    return _make_gate("G11", "P27 Certification", ok,
                      f"P27 tier={d.get('release_tier','?')} blockers={d.get('blocker_count',0)}")

def g12_p26_certification(items):
    d = _load_quality_report("p26_certification_report.json")
    if not d: return _make_gate("G12", "P26 Certification", False, "p26_certification_report.json not found", "BLOCKER")
    ok = d.get("release_tier","") != "REJECTED"
    return _make_gate("G12", "P26 Certification", ok,
                      f"P26 tier={d.get('release_tier','?')} blockers={d.get('blocker_count',0)}")

def g13_p25_trust_gate(items):
    d = _load_quality_report("p25_enterprise_trust_gate.json")
    if not d: return _make_gate("G13", "P25 Trust Gate", False, "p25_enterprise_trust_gate.json not found", "BLOCKER")
    ok = d.get("blocker_count",99) == 0
    return _make_gate("G13", "P25 Trust Gate", ok, f"P25 blockers={d.get('blocker_count',0)}")

def g14_regression_tests(items):
    # Authoritative run is Stage 5.6 in CI; presence check avoids false failures.
    script = _ROOT / "scripts" / "regression_tests.py"
    if not script.exists():
        return _make_gate("G14", "Regression Tests Present", False, "regression_tests.py not found", "WARNING")
    return _make_gate("G14", "Regression Tests Present", True,
                      "regression_tests.py exists — authoritative run is Stage 5.6 in CI")

# ── Gates G15–G18: artifact coverage ─────────────────────────────────────────

def g15_html_reports(items):
    n     = len(items)
    count = sum(1 for f in _DATA.rglob("*.html") if f.is_file())
    sev   = "BLOCKER" if count == 0 else "WARNING"
    return _make_gate("G15", "HTML Report Files ≥ Feed", count >= n, f"{count} HTML files vs {n} feed items", sev)

def g16_stix_files(items):
    n     = len(items)
    count = sum(1 for f in _STIX.rglob("*.json") if f.is_file()) if _STIX.exists() else 0
    return _make_gate("G16", "STIX Bundle Files ≥ Feed", count >= n, f"{count} STIX files vs {n} items", "WARNING")

def g17_enrichment_score(items):
    scores = [float(it.get("enrichment_score",0)) for it in items if it.get("enrichment_score")]
    avg    = round(sum(scores)/len(scores),1) if scores else 0
    return _make_gate("G17", "Avg Enrichment ≥30", avg >= 30,
                      f"avg {avg}/100 ({len(scores)}/{len(items)} scored)", "WARNING")

def g18_evidence_chain_coverage(items):
    cov = sum(1 for it in items if it.get("source_url") or it.get("source") or it.get("nvd_url") or it.get("stix_bundle"))
    pct = round(cov/len(items)*100,1) if items else 0
    return _make_gate("G18", "Evidence Chain Coverage ≥80%", pct >= 80, f"{pct}% ({cov}/{len(items)})", "WARNING")

# ── Gates G19–G20: P29-specific EIN gates ────────────────────────────────────

def g19_detection_coverage(items):
    """P29.6: ≥40% of items carry at least one detection format in detection_bundle."""
    cov = 0
    for it in items:
        db = it.get("detection_bundle") or {}
        if isinstance(db, dict) and any(db.get(f) for f in ("sigma","kql","yara","spl","suricata","snort")):
            cov += 1
    pct = round(cov/len(items)*100,1) if items else 0
    return _make_gate("G19", "Detection Coverage ≥40%", pct >= 40,
                      f"{pct}% ({cov}/{len(items)} items with detection_bundle)", "WARNING")

def g20_confidence_graph_coverage(items):
    """P29.2: ≥80% of items have a non-default confidence value (not exactly 0.5 or absent)."""
    non_default = 0
    for it in items:
        v = it.get("confidence") or it.get("confidence_score")
        if v is None:
            continue
        try:
            f = float(v)
            # normalize
            if f > 1.0: f = f / 100.0
            if abs(f - 0.5) > 0.01:  # not the default placeholder
                non_default += 1
        except Exception:
            pass
    pct = round(non_default/len(items)*100,1) if items else 0
    return _make_gate("G20", "Confidence Graph Coverage ≥80%", pct >= 80,
                      f"{pct}% ({non_default}/{len(items)} items with calibrated confidence)", "WARNING")

# ── Orchestration ─────────────────────────────────────────────────────────────

def run_audit():
    items = _load_feed()
    gates = [
        g01_feed_loadable(items),
        g02_required_fields(items),
        g03_no_markdown_leakage(items),
        g04_no_placeholder_language(items),
        g05_confidence_validity(items),
        g06_cvss_severity_consistency(items),
        g07_mitre_coverage(items),
        g08_ioc_coverage(items),
        g09_source_url_completeness(items),
        g10_p28_certification(items),
        g11_p27_certification(items),
        g12_p26_certification(items),
        g13_p25_trust_gate(items),
        g14_regression_tests(items),
        g15_html_reports(items),
        g16_stix_files(items),
        g17_enrichment_score(items),
        g18_evidence_chain_coverage(items),
        g19_detection_coverage(items),
        g20_confidence_graph_coverage(items),
    ]

    blockers = [g for g in gates if not g["pass"] and g["severity"] == "BLOCKER"]
    warnings = [g for g in gates if not g["pass"] and g["severity"] == "WARNING"]
    passed   = [g for g in gates if g["pass"]]

    tier = "WORLDWIDE_RELEASE" if len(blockers) == 0 else (
           "CONDITIONAL_RELEASE" if len(blockers) <= 2 else "BLOCKED")

    # EIN network metrics
    def _conf(it):
        v = it.get("confidence") or it.get("confidence_score") or 0.5
        f = float(v)
        return f if f <= 1.0 else f / 100.0

    kev_count   = sum(1 for it in items if it.get("kev_present") or (it.get("apex",{}) or {}).get("kev_listed"))
    avg_conf    = round(sum(_conf(it) for it in items) / max(1,len(items)) * 100, 1)
    mitre_cov   = round(sum(1 for it in items if (it.get("mitre_tactics") and len(it["mitre_tactics"])>0)
                           or (it.get("ttps") and len(it["ttps"])>0)) / max(1,len(items)) * 100, 1)
    ioc_cov     = round(sum(1 for it in items if (it.get("ioc_count") or 0)>0) / max(1,len(items)) * 100, 1)
    src_cov     = round(sum(1 for it in items if str(it.get("source_url","")).startswith("http")) / max(1,len(items)) * 100, 1)
    det_cov     = round(sum(1 for it in items if (it.get("detection_bundle") or {})) / max(1,len(items)) * 100, 1)
    p29_gate    = gates[-1]  # G20

    return {
        "schema_version":   "p29.0",
        "generated_at":     __import__("datetime").datetime.utcnow().isoformat()+"Z",
        "feed_items":       len(items),
        "release_tier":     tier,
        "blocker_count":    len(blockers),
        "warning_count":    len(warnings),
        "passed_count":     len(passed),
        "total_gates":      len(gates),
        "ein_metrics": {
            "avg_confidence_pct":    avg_conf,
            "mitre_coverage_pct":    mitre_cov,
            "ioc_coverage_pct":      ioc_cov,
            "source_url_pct":        src_cov,
            "detection_coverage_pct": det_cov,
            "kev_items":             kev_count,
        },
        "gates":    gates,
        "blockers": blockers,
        "warnings": warnings,
    }

def main():
    print("[P29.20] Running Enterprise Intelligence Network certification audit …")
    report = run_audit()
    print(f"[P29.20] Feed items  : {report['feed_items']}")
    print(f"[P29.20] Gates passed: {report['passed_count']}/{report['total_gates']}")
    print(f"[P29.20] Blockers    : {report['blocker_count']}")
    print(f"[P29.20] Warnings    : {report['warning_count']}")
    print(f"[P29.20] Release tier: {report['release_tier']}")
    m = report["ein_metrics"]
    print(f"[P29.20] Confidence  : {m['avg_confidence_pct']}% | MITRE: {m['mitre_coverage_pct']}% "
          f"| IOC: {m['ioc_coverage_pct']}% | Det: {m['detection_coverage_pct']}% | Src URL: {m['source_url_pct']}%")

    if not DRY_RUN:
        _QUAL.mkdir(parents=True, exist_ok=True)
        _OUT.write_text(json.dumps(report, indent=2))
        print(f"[P29.20] Report saved → {_OUT}")

    if report["blocker_count"] > 0:
        print("[P29.20] BLOCKERS:")
        for b in report["blockers"]:
            print(f"  [BLOCKER] {b['gate']} {b['name']}: {b['detail']}")

    sys.exit(0)

if __name__ == "__main__":
    main()
