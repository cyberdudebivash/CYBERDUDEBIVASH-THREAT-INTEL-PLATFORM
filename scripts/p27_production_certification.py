#!/usr/bin/env python3
"""
scripts/p27_production_certification.py
CYBERDUDEBIVASH(R) SENTINEL APEX - P27.12 Production Certification
===================================================================
Extends P26's 13-dimension audit with P27-specific structural and
operational certification checks. Outputs p27_certification_report.json.

Gate list (14 gates):
  G01  Feed JSON loadable + item count ≥ 1
  G02  Required fields present in all items
  G03  No markdown leakage in title/description
  G04  No placeholder/synthetic language in description
  G05  Confidence values in [0.01, 1.00]
  G06  Severity consistent with CVSS (no >2 band gap when score present)
  G07  MITRE ATT&CK coverage ≥ 95 %
  G08  STIX bundle files = feed item count
  G09  HTML report files ≥ feed item count
  G10  P26 certification report exists + tier != REJECTED
  G11  P25 trust gate report exists + blockers == 0
  G12  Regression test suite passes (21/21)
  G13  IOC coverage ≥ 50 % of feed items carry ioc_count > 0
  G14  Source URL completeness ≥ 95 %
"""

from __future__ import annotations
import json, os, pathlib, re, subprocess, sys

_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_DATA   = _ROOT / "data"
_FEED   = _DATA / "feed.json"
_QUAL   = _DATA / "quality"
_STIX   = _DATA / "stix"
_HTML   = _DATA  # search recursively under data/
_OUT    = _QUAL / "p27_certification_report.json"

DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

REQUIRED_FIELDS = [
    "id", "title", "description", "severity", "risk_score",
    "confidence", "timestamp", "source",
]

SEVERITY_CVSS_BANDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0,  8.9),
    "MEDIUM":   (4.0,  6.9),
    "LOW":      (0.1,  3.9),
    "INFO":     (0.0,  0.0),
}

MD_PATTERN   = re.compile(r"(\*\*|__|\#{2,}|\[.+?\]\(https?://.+?\)|`[^`]+`)")
SYNTH_PATTERN = re.compile(
    r"\b(lorem ipsum|placeholder|tbd|todo|insert here|example text|"
    r"sample text|test data|dummy|redacted for|to be determined)\b",
    re.IGNORECASE,
)

# ── helpers ────────────────────────────────────────────────────────────────────

def _load_feed() -> list[dict]:
    try:
        return json.loads(_FEED.read_bytes())
    except Exception:
        return []

def _severity_band(sev: str) -> tuple[float, float]:
    return SEVERITY_CVSS_BANDS.get(str(sev).upper(), (0.0, 10.0))

def _cvss_band(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"

def _band_gap(sev: str, cvss: float) -> int:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    a = order.index(str(sev).upper()) if str(sev).upper() in order else 2
    b = order.index(_cvss_band(cvss))
    return abs(a - b)

# ── gates ─────────────────────────────────────────────────────────────────────

def g01_feed_loadable(items: list) -> dict:
    ok = len(items) >= 1
    return {"gate": "G01", "name": "Feed Loadable", "pass": ok,
            "detail": f"{len(items)} items loaded from feed.json",
            "severity": "BLOCKER" if not ok else "OK"}

def g02_required_fields(items: list) -> dict:
    missing_total = 0
    for item in items:
        for f in REQUIRED_FIELDS:
            if f not in item or item[f] is None or item[f] == "":
                missing_total += 1
    ok = missing_total == 0
    return {"gate": "G02", "name": "Required Fields", "pass": ok,
            "detail": f"{missing_total} missing field instances across {len(items)} items",
            "severity": "BLOCKER" if not ok else "OK"}

def g03_no_markdown_leakage(items: list) -> dict:
    hits = sum(
        1 for item in items
        if MD_PATTERN.search(str(item.get("title", "")))
        or MD_PATTERN.search(str(item.get("description", "")))
    )
    ok = hits == 0
    return {"gate": "G03", "name": "No Markdown Leakage", "pass": ok,
            "detail": f"{hits}/{len(items)} items contain markdown leakage",
            "severity": "BLOCKER" if hits > 2 else ("WARNING" if hits > 0 else "OK")}

def g04_no_placeholder_language(items: list) -> dict:
    hits = sum(
        1 for item in items
        if SYNTH_PATTERN.search(str(item.get("description", "")))
    )
    ok = hits == 0
    return {"gate": "G04", "name": "No Placeholder Language", "pass": ok,
            "detail": f"{hits}/{len(items)} items contain placeholder language",
            "severity": "BLOCKER" if hits > 0 else "OK"}

def g05_confidence_validity(items: list) -> dict:
    bad = sum(
        1 for item in items
        if not (0.01 <= float(item.get("confidence", 0.5) or 0.5) <= 1.0)
    )
    ok = bad == 0
    return {"gate": "G05", "name": "Confidence Validity", "pass": ok,
            "detail": f"{bad}/{len(items)} items have invalid confidence values",
            "severity": "WARNING" if bad > 0 else "OK"}

def g06_cvss_severity_consistency(items: list) -> dict:
    gap_items = 0
    for item in items:
        sev = str(item.get("severity", "")).upper()
        score_raw = item.get("risk_score") or item.get("_score_details", {}).get("cvss", 0)
        try:
            score = float(score_raw) if score_raw else 0.0
        except (TypeError, ValueError):
            score = 0.0
        if score > 0 and sev in SEVERITY_CVSS_BANDS:
            if _band_gap(sev, score) >= 2:
                gap_items += 1
    ok = gap_items == 0
    return {"gate": "G06", "name": "CVSS/Severity Consistency", "pass": ok,
            "detail": f"{gap_items}/{len(items)} items have ≥2 band gap",
            "severity": "WARNING" if gap_items > 0 else "OK"}

def g07_mitre_coverage(items: list) -> dict:
    covered = sum(
        1 for item in items
        if (item.get("mitre_tactics") and len(item["mitre_tactics"]) > 0)
        or (item.get("ttps") and len(item["ttps"]) > 0)
    )
    pct = round(covered / len(items) * 100, 1) if items else 0
    ok = pct >= 95.0
    return {"gate": "G07", "name": "MITRE ATT&CK Coverage", "pass": ok,
            "detail": f"{pct}% MITRE coverage ({covered}/{len(items)})",
            "severity": "BLOCKER" if pct < 80 else ("WARNING" if not ok else "OK")}

def g08_stix_files(items: list) -> dict:
    n = len(items)
    count = 0
    if _STIX.exists():
        count = sum(1 for f in _STIX.iterdir() if f.suffix == ".json")
    ok = count >= n
    return {"gate": "G08", "name": "STIX Bundle Files", "pass": ok,
            "detail": f"{count} STIX files vs {n} feed items",
            "severity": "WARNING" if not ok else "OK"}

def g09_html_report_files(items: list) -> dict:
    n = len(items)
    count = 0
    if _HTML.exists():
        count = sum(1 for f in _HTML.rglob("*.html") if f.is_file())
    ok = count >= n
    return {"gate": "G09", "name": "HTML Report Files", "pass": ok,
            "detail": f"{count} HTML report files vs {n} feed items",
            "severity": "BLOCKER" if count == 0 else ("WARNING" if not ok else "OK")}

def g10_p26_certification(items: list) -> dict:
    p26_file = _QUAL / "p26_certification_report.json"
    if not p26_file.exists():
        return {"gate": "G10", "name": "P26 Certification", "pass": False,
                "detail": "p26_certification_report.json not found",
                "severity": "BLOCKER"}
    try:
        d = json.loads(p26_file.read_bytes())
        tier = d.get("release_tier", "UNKNOWN")
        blockers = d.get("blocker_count", 99)
        ok = tier != "REJECTED"
        return {"gate": "G10", "name": "P26 Certification", "pass": ok,
                "detail": f"P26 tier={tier} blockers={blockers}",
                "severity": "BLOCKER" if not ok else "OK"}
    except Exception as e:
        return {"gate": "G10", "name": "P26 Certification", "pass": False,
                "detail": str(e), "severity": "BLOCKER"}

def g11_p25_trust_gate(items: list) -> dict:
    p25_file = _QUAL / "p25_enterprise_trust_gate.json"
    if not p25_file.exists():
        return {"gate": "G11", "name": "P25 Trust Gate", "pass": False,
                "detail": "p25_enterprise_trust_gate.json not found",
                "severity": "BLOCKER"}
    try:
        d = json.loads(p25_file.read_bytes())
        blockers = d.get("blocker_count", 99)
        ok = blockers == 0
        return {"gate": "G11", "name": "P25 Trust Gate", "pass": ok,
                "detail": f"P25 blockers={blockers}",
                "severity": "BLOCKER" if not ok else "OK"}
    except Exception as e:
        return {"gate": "G11", "name": "P25 Trust Gate", "pass": False,
                "detail": str(e), "severity": "BLOCKER"}

def g12_regression_tests(items: list) -> dict:
    reg_script = _ROOT / "scripts" / "regression_tests.py"
    if not reg_script.exists():
        return {"gate": "G12", "name": "Regression Tests", "pass": False,
                "detail": "regression_tests.py not found", "severity": "BLOCKER"}
    try:
        result = subprocess.run(
            ["python3", str(reg_script)],
            capture_output=True, text=True, timeout=120, cwd=_ROOT,
        )
        output = result.stdout + result.stderr
        # parse summary line: "Results: N PASS, M FAIL of P tests"
        import re as _re
        m = _re.search(r"Results:\s+(\d+)\s+PASS,\s+(\d+)\s+FAIL", output)
        if m:
            passed, failed = int(m.group(1)), int(m.group(2))
        else:
            passed = output.count("[PASS]")
            failed = output.count("[FAIL]")
        ok = failed == 0 and passed >= 21
        return {"gate": "G12", "name": "Regression Tests", "pass": ok,
                "detail": f"{passed} PASS / {failed} FAIL",
                "severity": "BLOCKER" if not ok else "OK"}
    except subprocess.TimeoutExpired:
        return {"gate": "G12", "name": "Regression Tests", "pass": False,
                "detail": "Regression tests timed out", "severity": "BLOCKER"}
    except Exception as e:
        return {"gate": "G12", "name": "Regression Tests", "pass": False,
                "detail": str(e), "severity": "BLOCKER"}

def g13_ioc_coverage(items: list) -> dict:
    with_ioc = sum(1 for item in items if (item.get("ioc_count") or 0) > 0)
    pct = round(with_ioc / len(items) * 100, 1) if items else 0
    ok = pct >= 50.0
    return {"gate": "G13", "name": "IOC Coverage", "pass": ok,
            "detail": f"{pct}% items carry ioc_count > 0 ({with_ioc}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}

def g14_source_url_completeness(items: list) -> dict:
    with_url = sum(
        1 for item in items
        if str(item.get("source_url") or "").startswith("http")
    )
    pct = round(with_url / len(items) * 100, 1) if items else 0
    ok = pct >= 95.0
    return {"gate": "G14", "name": "Source URL Completeness", "pass": ok,
            "detail": f"{pct}% items have source_url ({with_url}/{len(items)})",
            "severity": "WARNING" if not ok else "OK"}

# ── orchestration ──────────────────────────────────────────────────────────────

def run_audit() -> dict:
    items = _load_feed()
    gates = [
        g01_feed_loadable(items),
        g02_required_fields(items),
        g03_no_markdown_leakage(items),
        g04_no_placeholder_language(items),
        g05_confidence_validity(items),
        g06_cvss_severity_consistency(items),
        g07_mitre_coverage(items),
        g08_stix_files(items),
        g09_html_report_files(items),
        g10_p26_certification(items),
        g11_p25_trust_gate(items),
        g12_regression_tests(items),
        g13_ioc_coverage(items),
        g14_source_url_completeness(items),
    ]
    blockers  = [g for g in gates if not g["pass"] and g["severity"] == "BLOCKER"]
    warnings  = [g for g in gates if not g["pass"] and g["severity"] == "WARNING"]
    passed    = [g for g in gates if g["pass"]]

    if len(blockers) == 0:
        tier = "WORLDWIDE_RELEASE"
    elif len(blockers) <= 2:
        tier = "CONDITIONAL_RELEASE"
    else:
        tier = "BLOCKED"

    report = {
        "schema_version":   "p27.0",
        "generated_at":     __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "feed_items":       len(items),
        "release_tier":     tier,
        "blocker_count":    len(blockers),
        "warning_count":    len(warnings),
        "passed_count":     len(passed),
        "total_gates":      len(gates),
        "gates":            gates,
        "blockers":         blockers,
        "warnings":         warnings,
    }
    return report

def main() -> None:
    print("[P27.12] Running production certification audit …")
    report = run_audit()
    print(f"[P27.12] Feed items  : {report['feed_items']}")
    print(f"[P27.12] Gates passed: {report['passed_count']}/{report['total_gates']}")
    print(f"[P27.12] Blockers    : {report['blocker_count']}")
    print(f"[P27.12] Warnings    : {report['warning_count']}")
    print(f"[P27.12] Release tier: {report['release_tier']}")

    if not DRY_RUN:
        _QUAL.mkdir(parents=True, exist_ok=True)
        _OUT.write_text(json.dumps(report, indent=2))
        print(f"[P27.12] Report saved → {_OUT}")

    if report["blocker_count"] > 0:
        print("[P27.12] BLOCKERS DETECTED:")
        for b in report["blockers"]:
            print(f"  [BLOCKER] {b['gate']} {b['name']}: {b['detail']}")

    sys.exit(0)

if __name__ == "__main__":
    main()
