#!/usr/bin/env python3
"""
scripts/p28_production_certification.py
CYBERDUDEBIVASH(R) SENTINEL APEX  -  P28.12 Production Certification
=====================================================================
Final production certification gate for P28.0 Enterprise Risk Intelligence
& Customer Value Platform. Extends P27 audit with P28-specific gates:

  G01  Feed loadable + item count ≥ 1
  G02  Required fields present in all items
  G03  No markdown leakage in title/description (P28.11 commercial readiness)
  G04  No placeholder/synthetic language
  G05  Confidence values valid [0.01, 1.00]
  G06  CVSS/severity consistency (≤1 band gap)
  G07  MITRE ATT&CK coverage ≥ 95%
  G08  IOC coverage ≥ 50% of items carry ioc_count > 0
  G09  Source URL completeness ≥ 95%
  G10  P27 certification report exists + tier != BLOCKED
  G11  P26 certification report exists + tier != REJECTED
  G12  P25 trust gate report exists + 0 blockers
  G13  Regression suite 21/21 PASS
  G14  HTML report files ≥ feed item count (commercial readiness)
  G15  STIX bundle files ≥ feed item count
  G16  Enrichment score ≥ 30/100 average (operational usefulness)
  G17  Evidence chain coverage ≥ 80% (items with source_url or source)

Outputs: data/quality/p28_certification_report.json
"""

from __future__ import annotations
import json, os, pathlib, re, subprocess, sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"
_FEED = _DATA / "feed.json"
_QUAL = _DATA / "quality"
_STIX = _DATA / "stix"
_OUT  = _QUAL / "p28_certification_report.json"

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

# ── Individual gates ──────────────────────────────────────────────────────────

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
    bad = sum(1 for it in items if not (0.01 <= float(it.get("confidence") or it.get("confidence_score") or 0.5) <= 1.0))
    return _make_gate("G05", "Confidence Validity", bad == 0, f"{bad}/{len(items)} invalid", "WARNING")

def g06_cvss_severity_consistency(items):
    gaps = 0
    for it in items:
        sev  = str(it.get("severity","")).upper()
        s    = it.get("risk_score") or it.get("cvss_score") or 0
        try: score = float(s)
        except: score = 0.0
        if score > 0 and sev in SEVERITY_ORDER:
            if abs(_severity_idx(sev) - _cvss_idx(score)) >= 2:
                gaps += 1
    return _make_gate("G06", "CVSS/Severity Consistency", gaps == 0, f"{gaps}/{len(items)} gaps ≥2 bands", "WARNING")

def g07_mitre_coverage(items):
    cov = sum(1 for it in items if (it.get("mitre_tactics") and len(it["mitre_tactics"])>0) or (it.get("ttps") and len(it["ttps"])>0))
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

def _load_quality_report(filename):
    f = _QUAL / filename
    if not f.exists(): return None
    try: return json.loads(f.read_bytes())
    except: return None

def g10_p27_certification(items):
    d = _load_quality_report("p27_certification_report.json")
    if not d: return _make_gate("G10", "P27 Certification", False, "p27_certification_report.json not found", "BLOCKER")
    ok = d.get("release_tier","") != "BLOCKED"
    return _make_gate("G10", "P27 Certification", ok, f"P27 tier={d.get('release_tier','?')} blockers={d.get('blocker_count',0)}")

def g11_p26_certification(items):
    d = _load_quality_report("p26_certification_report.json")
    if not d: return _make_gate("G11", "P26 Certification", False, "p26_certification_report.json not found", "BLOCKER")
    ok = d.get("release_tier","") != "REJECTED"
    return _make_gate("G11", "P26 Certification", ok, f"P26 tier={d.get('release_tier','?')} blockers={d.get('blocker_count',0)}")

def g12_p25_trust_gate(items):
    d = _load_quality_report("p25_enterprise_trust_gate.json")
    if not d: return _make_gate("G12", "P25 Trust Gate", False, "p25_enterprise_trust_gate.json not found", "BLOCKER")
    ok = d.get("blocker_count",99) == 0
    return _make_gate("G12", "P25 Trust Gate", ok, f"P25 blockers={d.get('blocker_count',0)}")

def g13_regression_tests(items):
    script = _ROOT / "scripts" / "regression_tests.py"
    if not script.exists():
        return _make_gate("G13", "Regression Tests", False, "regression_tests.py not found", "BLOCKER")
    try:
        r = subprocess.run(["python3", str(script)], capture_output=True, text=True, timeout=120, cwd=_ROOT)
        out = r.stdout + r.stderr
        m = re.search(r"Results:\s+(\d+)\s+PASS,\s+(\d+)\s+FAIL", out)
        if m:
            passed, failed = int(m.group(1)), int(m.group(2))
        else:
            passed = out.count("[PASS]")
            failed = out.count("[FAIL]")
        ok = failed == 0 and passed >= 21
        return _make_gate("G13", "Regression Tests 21/21", ok, f"{passed} PASS / {failed} FAIL")
    except subprocess.TimeoutExpired:
        return _make_gate("G13", "Regression Tests 21/21", False, "Timed out", "BLOCKER")
    except Exception as e:
        return _make_gate("G13", "Regression Tests 21/21", False, str(e), "BLOCKER")

def g14_html_reports(items):
    n = len(items)
    count = sum(1 for f in _DATA.rglob("*.html") if f.is_file())
    sev = "BLOCKER" if count == 0 else "WARNING"
    return _make_gate("G14", "HTML Report Files ≥ Feed", count >= n, f"{count} HTML files vs {n} feed items", sev)

def g15_stix_files(items):
    n = len(items)
    count = sum(1 for f in _STIX.rglob("*.json") if f.is_file()) if _STIX.exists() else 0
    return _make_gate("G15", "STIX Bundle Files ≥ Feed", count >= n, f"{count} STIX files vs {n} items", "WARNING")

def g16_enrichment_score(items):
    scores = [float(it.get("enrichment_score",0)) for it in items if it.get("enrichment_score")]
    avg = round(sum(scores)/len(scores),1) if scores else 0
    return _make_gate("G16", "Avg Enrichment ≥30", avg >= 30, f"avg {avg}/100 ({len(scores)}/{len(items)} scored)", "WARNING")

def g17_evidence_chain_coverage(items):
    cov = sum(1 for it in items if it.get("source_url") or it.get("source") or it.get("nvd_url") or it.get("stix_bundle"))
    pct = round(cov/len(items)*100,1) if items else 0
    return _make_gate("G17", "Evidence Chain Coverage ≥80%", pct >= 80, f"{pct}% ({cov}/{len(items)})", "WARNING")

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
        g10_p27_certification(items),
        g11_p26_certification(items),
        g12_p25_trust_gate(items),
        g13_regression_tests(items),
        g14_html_reports(items),
        g15_stix_files(items),
        g16_enrichment_score(items),
        g17_evidence_chain_coverage(items),
    ]
    blockers  = [g for g in gates if not g["pass"] and g["severity"] == "BLOCKER"]
    warnings  = [g for g in gates if not g["pass"] and g["severity"] == "WARNING"]
    passed    = [g for g in gates if g["pass"]]

    # compute commercial readiness pct from key metrics
    kev_count = sum(1 for it in items if it.get("kev_present") or (it.get("apex",{}) or {}).get("kev_listed"))
    def _conf(it):
        v = it.get("confidence") or it.get("confidence_score") or 0.5
        f = float(v)
        return f if f <= 1.0 else f / 100.0  # normalize: feed uses 0-1 or 0-100
    avg_conf  = round(sum(_conf(it) for it in items) / max(1,len(items)) * 100, 1)
    mitre_cov = round(sum(1 for it in items if (it.get("mitre_tactics") and len(it["mitre_tactics"])>0) or (it.get("ttps") and len(it["ttps"])>0)) / max(1,len(items)) * 100, 1)
    ioc_cov   = round(sum(1 for it in items if (it.get("ioc_count") or 0)>0) / max(1,len(items)) * 100, 1)
    src_cov   = round(sum(1 for it in items if str(it.get("source_url","")).startswith("http")) / max(1,len(items)) * 100, 1)

    tier = "WORLDWIDE_RELEASE" if len(blockers)==0 else ("CONDITIONAL_RELEASE" if len(blockers)<=2 else "BLOCKED")

    return {
        "schema_version":  "p28.0",
        "generated_at":    __import__("datetime").datetime.utcnow().isoformat()+"Z",
        "feed_items":      len(items),
        "release_tier":    tier,
        "blocker_count":   len(blockers),
        "warning_count":   len(warnings),
        "passed_count":    len(passed),
        "total_gates":     len(gates),
        "commercial_readiness": {
            "avg_confidence_pct": avg_conf,
            "mitre_coverage_pct": mitre_cov,
            "ioc_coverage_pct":   ioc_cov,
            "source_url_pct":     src_cov,
            "kev_items":          kev_count,
        },
        "gates":    gates,
        "blockers": blockers,
        "warnings": warnings,
    }

def main():
    print("[P28.12] Running production certification audit …")
    report = run_audit()
    print(f"[P28.12] Feed items  : {report['feed_items']}")
    print(f"[P28.12] Gates passed: {report['passed_count']}/{report['total_gates']}")
    print(f"[P28.12] Blockers    : {report['blocker_count']}")
    print(f"[P28.12] Warnings    : {report['warning_count']}")
    print(f"[P28.12] Release tier: {report['release_tier']}")
    cr = report["commercial_readiness"]
    print(f"[P28.12] Confidence  : {cr['avg_confidence_pct']}% | MITRE: {cr['mitre_coverage_pct']}% | IOC: {cr['ioc_coverage_pct']}% | Src URL: {cr['source_url_pct']}%")

    if not DRY_RUN:
        _QUAL.mkdir(parents=True, exist_ok=True)
        _OUT.write_text(json.dumps(report, indent=2))
        print(f"[P28.12] Report saved → {_OUT}")

    if report["blocker_count"] > 0:
        print("[P28.12] BLOCKERS:")
        for b in report["blockers"]:
            print(f"  [BLOCKER] {b['gate']} {b['name']}: {b['detail']}")
    sys.exit(0)

if __name__ == "__main__":
    main()
