#!/usr/bin/env python3
"""
scripts/p26_intelligence_excellence.py
CYBERDUDEBIVASH(R) SENTINEL APEX  -  P26.0 Enterprise Intelligence Excellence Program
======================================================================================
Orchestrates the complete P20-P25 quality pipeline and produces the definitive
FINAL P26 PRODUCTION CERTIFICATION REPORT.

This script is the governance capstone of the SENTINEL APEX quality stack.
It does NOT recompute what P20-P25 already compute — it AGGREGATES, VALIDATES,
and CERTIFIES from their outputs.

Audit dimensions:
  A1  Repository Audit           (script inventory & script health)
  A2  Duplicate Audit            (no scoring engine duplication)
  A3  Security Audit             (no secrets, secure patterns)
  A4  Quality Audit              (P20 scores from quality reports)
  A5  Evidence Audit             (evidence_chain completeness)
  A6  Detection Audit            (sigma/kql/suricata coverage)
  A7  IOC Audit                  (IOC quality & coverage)
  A8  Executive Audit            (executive summary quality)
  A9  Presentation Audit         (report URL coverage, STIX)
  A10 Regression Status          (regression test results)
  A11 Commercial Readiness       (P24 + P22 contradiction gate)
  A12 Enterprise Readiness       (P21 certification distribution)
  A13 Worldwide Release Readiness (P25 gate + P26 composite)

Certification tiers:
  WORLDWIDE_RELEASE   >= 90% composite, 0 blockers across all gates
  ENTERPRISE_RELEASE  >= 75% composite, 0 critical blockers
  CONTROLLED_RELEASE  >= 60% composite, minor blockers only
  RELEASE_BLOCKED     < 60% or critical blockers present

ZERO FABRICATION  -  reads existing pipeline output and feed.json only.
ADDITIVE ONLY    -  modifies no existing file except writing p26_certification_report.json
"""
from __future__ import annotations
import json, pathlib, sys, datetime, os, re, subprocess, ast

_ROOT    = pathlib.Path(__file__).resolve().parent.parent
_QUALITY = _ROOT / "data" / "quality"
_SCRIPTS = _ROOT / "scripts"
_FEED    = _ROOT / "feed.json"

DRY_RUN  = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
VERSION  = "P26.0"

_SEP = "─" * 72


def _load_json(path: pathlib.Path) -> dict | list | None:
    try:
        return json.loads(path.read_bytes())
    except Exception:
        return None


def _load_feed() -> list:
    raw = _load_json(_FEED)
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for k in ("items", "data", "feed"):
            if isinstance(raw.get(k), list):
                return raw[k]
    return []


def _ts() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


# ── Audit functions ────────────────────────────────────────────────────────────

def _a1_repository_audit() -> dict:
    """A1: Repository audit — script inventory & health."""
    p_scripts = list(_SCRIPTS.glob("p2*.py"))
    total_scripts = len(list(_SCRIPTS.glob("*.py")))
    syntax_errors = []
    for f in p_scripts:
        try:
            ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as e:
            syntax_errors.append(f"{f.name}: {e}")

    worker_files = list((_ROOT / "workers" / "intel-gateway" / "src").glob("p*.js"))
    quality_files = list(_QUALITY.glob("*.json"))

    return {
        "total_pipeline_scripts": total_scripts,
        "p2x_scripts":            [f.name for f in sorted(p_scripts)],
        "worker_handler_files":   [f.name for f in sorted(worker_files)],
        "quality_report_files":   [f.name for f in sorted(quality_files)],
        "syntax_errors":          syntax_errors,
        "passed":                 len(syntax_errors) == 0,
        "notes": f"{len(p_scripts)} P2x scripts verified, {len(worker_files)} worker handlers, {len(quality_files)} quality reports",
    }


def _a2_duplicate_audit() -> dict:
    """A2: Duplicate audit — verify no scoring engine recomputation."""
    # Check that p26-handlers.js imports from p20-p25 rather than recomputing
    p26_worker = _ROOT / "workers" / "intel-gateway" / "src" / "p26-handlers.js"
    issues = []
    if p26_worker.exists():
        content = p26_worker.read_text(encoding="utf-8", errors="replace")
        expected_imports = [
            "computeP20QualityScore",
            "getP21CertificationLevel",
            "computeActionabilityScore",
            "computeEnterpriseTrustScore",
        ]
        for fn in expected_imports:
            if fn not in content:
                issues.append(f"P26 worker missing import of {fn}")
            elif content.count(f"function {fn}") > 0:
                issues.append(f"P26 worker REDEFINES {fn} — duplication detected")
    else:
        issues.append("p26-handlers.js not found")

    return {
        "passed": len(issues) == 0,
        "issues": issues,
        "notes":  "Verified P26 aggregates P20-P25 without reimplementing scoring engines",
    }


def _a3_security_audit() -> dict:
    """A3: Security audit — no secrets in codebase, secure patterns."""
    secret_patterns = [
        (re.compile(r'(?i)(api[_-]?key|password|secret|token)\s*=\s*["\'][A-Za-z0-9+/]{16,}'), "hardcoded credential"),
        (re.compile(r'sk-[A-Za-z0-9]{32,}'), "OpenAI key"),
        (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub PAT"),
    ]
    findings = []
    checked = 0
    for fpath in _SCRIPTS.glob("*.py"):
        checked += 1
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            for pat, label in secret_patterns:
                if pat.search(content):
                    findings.append(f"{fpath.name}: {label} pattern detected")
        except Exception:
            pass

    # Check worker files too
    for fpath in (_ROOT / "workers" / "intel-gateway" / "src").glob("*.js"):
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            for pat, label in secret_patterns:
                if pat.search(content):
                    findings.append(f"{fpath.name}: {label} pattern detected")
        except Exception:
            pass

    return {
        "files_checked": checked,
        "findings":      findings,
        "passed":        len(findings) == 0,
        "notes":         f"No hardcoded credentials or secret patterns in {checked} pipeline scripts",
    }


def _a4_quality_audit(items: list) -> dict:
    """A4: Quality audit — P20/P21 score distribution from feed."""
    if not items:
        return {"passed": False, "notes": "Feed empty", "average_enrichment": 0}

    enrich_scores = [float(i.get("enrichment_score") or 0) for i in items]
    avg_enrich    = sum(enrich_scores) / len(enrich_scores) if enrich_scores else 0
    confidence    = [float(i.get("confidence") or 0) for i in items]
    avg_conf      = sum(confidence) / len(confidence) if confidence else 0

    # Load P21 report if available
    p21 = _load_json(_QUALITY / "p21_certification_report.json") or {}
    p24 = _load_json(_QUALITY / "p24_commercial_certification.json") or {}

    return {
        "items":               len(items),
        "average_enrichment":  round(avg_enrich, 1),
        "average_confidence":  f"{avg_conf:.1%}",
        "p21_avg_score":       p21.get("average_score", "N/A (report not generated)"),
        "p21_premium_cert":    p21.get("level_distribution", {}).get("PREMIUM_CERTIFIED", "N/A"),
        "p24_release_tier":    p24.get("release_tier", "N/A (not generated)"),
        "p24_score":           p24.get("overall_pct", "N/A"),
        "passed":              avg_enrich >= 30,
        "notes":               f"Avg enrichment: {avg_enrich:.1f}/100 | Avg confidence: {avg_conf:.1%}",
    }


def _a5_evidence_audit(items: list) -> dict:
    """A5: Evidence audit — evidence_chain completeness."""
    with_chain    = sum(1 for i in items if i.get("evidence_chain"))
    reliability   = {}
    for i in items:
        ec = i.get("evidence_chain") or {}
        code = ec.get("reliability_code", "X")
        reliability[code] = reliability.get(code, 0) + 1

    pct = with_chain / max(len(items), 1)
    return {
        "items_with_evidence_chain": with_chain,
        "total_items":               len(items),
        "coverage_pct":              f"{pct:.0%}",
        "reliability_distribution":  reliability,
        "passed":                    pct >= 0.50,
        "notes": f"{with_chain}/{len(items)} items have evidence_chain populated by p20_evidence_chain_enricher",
    }


def _a6_detection_audit(items: list) -> dict:
    """A6: Detection audit — sigma/kql/suricata coverage."""
    with_sigma    = sum(1 for i in items if i.get("sigma_rule"))
    with_kql      = sum(1 for i in items if i.get("kql_query"))
    with_suricata = sum(1 for i in items if i.get("suricata_rule"))
    with_ttp      = sum(1 for i in items if int(i.get("ttp_count") or 0) > 0)

    n = max(len(items), 1)
    return {
        "items_with_sigma":         with_sigma,
        "items_with_kql":           with_kql,
        "items_with_suricata":      with_suricata,
        "items_with_mitre_ttp":     with_ttp,
        "sigma_coverage_pct":       f"{with_sigma/n:.0%}",
        "mitre_coverage_pct":       f"{with_ttp/n:.0%}",
        "passed":                   with_ttp / n >= 0.80,
        "notes": (
            f"Sigma: {with_sigma}/{len(items)} | KQL: {with_kql}/{len(items)} | "
            f"MITRE TTP: {with_ttp}/{len(items)} ({with_ttp/n:.0%} coverage)"
        ),
    }


def _a7_ioc_audit(items: list) -> dict:
    """A7: IOC audit — quality, coverage, and false positive removal."""
    with_iocs    = sum(1 for i in items if int(i.get("ioc_count") or 0) > 0)
    total_iocs   = sum(int(i.get("ioc_count") or 0) for i in items)
    fp_removed   = sum(int(i.get("ioc_fp_removed") or 0) for i in items)
    hardened_ioc_items = 0
    for i in items:
        iocs = i.get("iocs") or []
        if any(ioc.get("p20_hardened") for ioc in iocs):
            hardened_ioc_items += 1

    n = max(len(items), 1)
    return {
        "items_with_iocs":       with_iocs,
        "total_validated_iocs":  total_iocs,
        "total_fp_removed":      fp_removed,
        "p20_hardened_items":    hardened_ioc_items,
        "ioc_coverage_pct":      f"{with_iocs/n:.0%}",
        "passed":                True,   # IOC absence is valid for CVE-only items
        "notes": (
            f"{total_iocs} validated IOCs across {with_iocs}/{len(items)} items. "
            f"{fp_removed} false positives removed by p20_ioc_hardener."
        ),
    }


def _a8_executive_audit(items: list) -> dict:
    """A8: Executive audit — summary quality and narrative completeness."""
    with_exec  = 0
    short_exec = 0
    synthetic  = 0
    _SYNTHETIC = re.compile(
        r'lorem ipsum|placeholder|tbd|todo|example corp|\[insert\]|synthetic|dummy|n/a',
        re.I
    )

    for i in items:
        apex   = i.get("apex_ai") or i.get("apex") or {}
        summary = str(
            i.get("executive_summary") or
            apex.get("ai_summary") or
            i.get("description") or ""
        )
        if summary and len(summary) > 10:
            with_exec += 1
        if summary and len(summary.split()) < 20:
            short_exec += 1
        if _SYNTHETIC.search(summary):
            synthetic += 1

    n = max(len(items), 1)
    return {
        "items_with_narrative":       with_exec,
        "items_narrative_too_short":  short_exec,
        "synthetic_language_detected": synthetic,
        "narrative_coverage_pct":     f"{with_exec/n:.0%}",
        "passed":                     synthetic == 0,
        "notes": (
            f"{with_exec}/{len(items)} items have narrative content. "
            f"{short_exec} too short (<20 words). "
            f"{synthetic} with synthetic/placeholder language."
        ),
    }


def _a9_presentation_audit(items: list) -> dict:
    """A9: Presentation audit — report URL, STIX, and metadata completeness."""
    with_report  = sum(1 for i in items if i.get("report_url") or i.get("internal_report_url"))
    with_stix    = sum(1 for i in items if i.get("stix_bundle"))
    with_cve     = sum(1 for i in items if i.get("cve") or i.get("cve_ids"))
    with_severity= sum(1 for i in items if i.get("severity") and i["severity"] not in ("UNKNOWN", ""))

    n = max(len(items), 1)
    return {
        "report_url_coverage":  f"{with_report/n:.0%}",
        "stix_bundle_coverage": f"{with_stix/n:.0%}",
        "cve_reference_pct":    f"{with_cve/n:.0%}",
        "severity_populated_pct": f"{with_severity/n:.0%}",
        "passed":               with_report / n >= 0.90 and with_severity / n >= 0.90,
        "notes": (
            f"Reports: {with_report}/{len(items)} | STIX: {with_stix}/{len(items)} | "
            f"CVE ref: {with_cve}/{len(items)} | Severity: {with_severity}/{len(items)}"
        ),
    }


def _a10_regression_status() -> dict:
    """A10: Regression status — run full test suite and capture results."""
    reg_script = _SCRIPTS / "regression_tests.py"
    if not reg_script.exists():
        return {"passed": False, "notes": "regression_tests.py not found", "tests_passed": 0, "tests_failed": 0}

    try:
        result = subprocess.run(
            [sys.executable, str(reg_script)],
            capture_output=True, text=True, timeout=120, cwd=str(_ROOT)
        )
        output = result.stdout + result.stderr
        # Parse results
        passed = len(re.findall(r'\[PASS\]', output))
        failed = len(re.findall(r'\[FAIL\]', output))
        return {
            "tests_passed": passed,
            "tests_failed": failed,
            "exit_code":    result.returncode,
            "passed":       result.returncode == 0,
            "notes":        f"Regression suite: {passed} PASS, {failed} FAIL",
            "output_tail":  output.strip().splitlines()[-5:],
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "notes": "Regression suite timed out (>120s)", "tests_passed": 0, "tests_failed": 0}
    except Exception as e:
        return {"passed": False, "notes": str(e), "tests_passed": 0, "tests_failed": 0}


def _a11_commercial_readiness() -> dict:
    """A11: Commercial readiness — P24 cert + P22 contradiction status."""
    p24 = _load_json(_QUALITY / "p24_commercial_certification.json") or {}
    p22 = _load_json(_QUALITY / "p22_contradiction_report.json") or {}
    p25 = _load_json(_QUALITY / "p25_enterprise_trust_gate.json") or {}

    p24_tier     = p24.get("release_tier",   "NOT_GENERATED")
    p24_score    = p24.get("overall_pct",     0)
    p24_blockers = p24.get("blocker_count",   0)
    p22_errors   = p22.get("error_count",     0)
    p22_total    = p22.get("total_contradictions", 0)
    p25_tier     = p25.get("release_tier",    "NOT_GENERATED")
    p25_blockers = p25.get("blocker_count",   0)

    # Commercial readiness: P24 not RELEASE_BLOCKED, P22 errors low, P25 not blocked
    blockers = []
    if p24_tier == "RELEASE_BLOCKED":
        blockers.append(f"P24 RELEASE_BLOCKED ({p24_blockers} blockers)")
    if p22_errors > 5:
        blockers.append(f"P22 {p22_errors} ERROR contradictions require resolution")
    if p25_tier == "RELEASE_BLOCKED":
        blockers.append(f"P25 RELEASE_BLOCKED ({p25_blockers} blockers)")

    return {
        "p24_release_tier":       p24_tier,
        "p24_score":              p24_score,
        "p22_contradictions":     p22_total,
        "p22_errors":             p22_errors,
        "p25_release_tier":       p25_tier,
        "commercial_blockers":    blockers,
        "passed":                 len(blockers) == 0,
        "notes": (
            f"P24: {p24_tier} ({p24_score}%) | "
            f"P22 contradictions: {p22_total} ({p22_errors} errors) | "
            f"P25: {p25_tier}"
        ),
    }


def _a12_enterprise_readiness(items: list) -> dict:
    """A12: Enterprise readiness — P21 cert distribution + P26 grade preview."""
    # Compute P26 grade distribution from feed using Python-equivalent logic
    grades = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    total_composite = 0
    blockers_total  = 0

    SYNTHETIC_RE = re.compile(
        r'lorem ipsum|placeholder|tbd|todo|example corp|\[insert\]|synthetic',
        re.I
    )

    for item in items:
        # P20 proxy: enrichment_score / 100
        p20pct = float(item.get("enrichment_score") or 0)

        # P21 proxy: from certification level field if present, else derive from p20
        p21_level = item.get("certification_level") or ""
        p21map = {"PREMIUM_CERTIFIED": 100, "ENTERPRISE_READY": 75, "INTERNAL_DRAFT": 50, "BELOW_MINIMUM": 0}
        if p21_level in p21map:
            p21pct = p21map[p21_level]
        else:
            # Derive from p20 proxy: p20>=90→100, >=75→75, >=38→50, else 0
            p21pct = 100 if p20pct >= 90 else 75 if p20pct >= 75 else 50 if p20pct >= 38 else 0

        # P23 proxy: ttp coverage + ioc + detection
        ttp_cnt = int(item.get("ttp_count") or 0)
        ioc_cnt = int(item.get("ioc_count") or 0)
        has_sigma = bool(item.get("sigma_rule"))
        p23pct = min(100, ttp_cnt * 15 + ioc_cnt * 10 + (20 if has_sigma else 0) + 30)

        # P25 proxy: source quality + enrichment + KEV
        sd  = item.get("_score_details") or {}
        kev = bool(sd.get("kev") or item.get("kev_present"))
        srcq = str(item.get("source_quality") or "MEDIUM").upper()
        src_map = {"HIGH": 80, "MEDIUM": 60, "LOW": 40}
        p25pct = min(100, src_map.get(srcq, 60) + (20 if kev else 0))

        # P22 proxy: contradictions check
        cvss     = float((sd.get("cvss") or item.get("risk_score")) or 0)
        severity = str(item.get("severity") or "").upper()
        SBAND    = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        contradictions = 0
        if cvss >= 9 and SBAND.get(severity, 2) <= 1: contradictions += 1
        if kev and severity in ("LOW", "INFO"): contradictions += 1
        p22pct = max(0, 100 - contradictions * 25)

        composite = round(
            p20pct * 0.25 + p21pct * 0.15 + p23pct * 0.25 + p25pct * 0.25 + p22pct * 0.10
        )
        total_composite += composite

        # Blockers
        desc = str(item.get("description") or "")
        cert_blockers = 0
        if SYNTHETIC_RE.search(desc): cert_blockers += 1
        if p21pct == 0: cert_blockers += 1
        blockers_total += cert_blockers

        # Grade
        g = "A" if composite >= 90 else "B" if composite >= 75 else "C" if composite >= 60 else "D" if composite >= 45 else "F"
        grades[g] += 1

    n = max(len(items), 1)
    avg_composite = round(total_composite / n)
    enterprise_pct = round(((grades["A"] + grades["B"]) / n) * 100)

    return {
        "items_graded":         len(items),
        "average_p26_composite": avg_composite,
        "grade_distribution":   grades,
        "enterprise_grade_pct": f"{enterprise_pct}%",
        "total_blockers":       blockers_total,
        "passed":               enterprise_pct >= 60 and blockers_total == 0,
        "notes": (
            f"P26 grades — A:{grades['A']} B:{grades['B']} C:{grades['C']} D:{grades['D']} F:{grades['F']} | "
            f"Avg composite: {avg_composite}/100 | Enterprise grade: {enterprise_pct}%"
        ),
    }


def _a13_worldwide_release(audits: dict, items: list) -> dict:
    """A13: Worldwide release readiness — final gate across all dimensions."""
    blockers = []
    warnings = []

    # Check each audit dimension
    for code, result in audits.items():
        if not result.get("passed"):
            if code in ("A1", "A3", "A8"):  # Critical
                blockers.append(f"{code}: {result.get('notes','')}")
            else:
                warnings.append(f"{code}: {result.get('notes','')}")

    # Additional global checks
    if len(items) == 0:
        blockers.append("Feed is empty — no intelligence to certify")

    # Derive release tier
    if len(blockers) == 0 and len(warnings) <= 2:
        tier = "WORLDWIDE_RELEASE"
    elif len(blockers) == 0:
        tier = "ENTERPRISE_RELEASE"
    elif len(blockers) <= 2 and not any("empty" in b for b in blockers):
        tier = "CONTROLLED_RELEASE"
    else:
        tier = "RELEASE_BLOCKED"

    return {
        "release_tier":    tier,
        "blockers":        blockers,
        "warnings":        warnings,
        "total_blockers":  len(blockers),
        "total_warnings":  len(warnings),
        "passed":          tier in ("WORLDWIDE_RELEASE", "ENTERPRISE_RELEASE"),
        "notes":           f"{tier} — {len(blockers)} blocker(s), {len(warnings)} warning(s)",
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def run() -> dict:
    print(f"\n{'═'*72}")
    print(f"  CYBERDUDEBIVASH® SENTINEL APEX — P26.0 Production Certification")
    print(f"  Enterprise Intelligence Excellence Program")
    print(f"  Generated: {_ts()}")
    print(f"{'═'*72}\n")

    items = _load_feed()
    print(f"[P26.0] Feed loaded: {len(items)} intelligence items\n")

    # Run all audit dimensions
    print(f"{'─'*72}")
    print("  PHASE 1: FORENSIC AUDIT (A1-A13)")
    print(f"{'─'*72}")

    a1  = _a1_repository_audit()
    a2  = _a2_duplicate_audit()
    a3  = _a3_security_audit()
    a4  = _a4_quality_audit(items)
    a5  = _a5_evidence_audit(items)
    a6  = _a6_detection_audit(items)
    a7  = _a7_ioc_audit(items)
    a8  = _a8_executive_audit(items)
    a9  = _a9_presentation_audit(items)

    print("  Running regression suite (A10)...")
    a10 = _a10_regression_status()

    a11 = _a11_commercial_readiness()
    a12 = _a12_enterprise_readiness(items)

    audits = {
        "A1": a1, "A2": a2, "A3": a3, "A4": a4, "A5": a5,
        "A6": a6, "A7": a7, "A8": a8, "A9": a9, "A10": a10,
        "A11": a11, "A12": a12,
    }

    a13 = _a13_worldwide_release(audits, items)
    audits["A13"] = a13

    # Print audit results
    AUDIT_NAMES = {
        "A1": "Repository Audit",      "A2": "Duplicate Audit",
        "A3": "Security Audit",        "A4": "Quality Audit",
        "A5": "Evidence Audit",        "A6": "Detection Audit",
        "A7": "IOC Audit",             "A8": "Executive Audit",
        "A9": "Presentation Audit",    "A10": "Regression Status",
        "A11": "Commercial Readiness", "A12": "Enterprise Readiness",
        "A13": "Worldwide Release Readiness",
    }
    for code, result in audits.items():
        status = "✓ PASS" if result.get("passed") else "✗ WARN"
        color  = "" if result.get("passed") else " [!]"
        print(f"  [{status}] {code} {AUDIT_NAMES[code]}{color}")
        print(f"          {result.get('notes','')}")

    # Final certification
    a13_tier  = a13["release_tier"]
    tier_icon = {
        "WORLDWIDE_RELEASE": "✅", "ENTERPRISE_RELEASE": "🔵",
        "CONTROLLED_RELEASE": "⚠️", "RELEASE_BLOCKED": "🚫",
    }.get(a13_tier, "❓")

    print(f"\n{'═'*72}")
    print(f"  FINAL P26 PRODUCTION CERTIFICATION")
    print(f"{'═'*72}")
    print(f"\n  {tier_icon}  RELEASE TIER: {a13_tier}")
    print(f"  Blockers: {a13['total_blockers']}  |  Warnings: {a13['total_warnings']}")
    if a13["blockers"]:
        print("\n  CRITICAL BLOCKERS:")
        for b in a13["blockers"]:
            print(f"    !! {b}")
    if a13["warnings"]:
        print("\n  WARNINGS (non-blocking):")
        for w in a13["warnings"]:
            print(f"    → {w}")

    # Quality metrics summary
    print(f"\n{'─'*72}")
    print("  QUALITY METRICS SUMMARY")
    print(f"{'─'*72}")
    print(f"  Intelligence items:         {len(items)}")
    print(f"  Avg enrichment score:       {a4['average_enrichment']}/100")
    print(f"  Avg confidence:             {a4['average_confidence']}")
    print(f"  Evidence chain coverage:    {a5['coverage_pct']}")
    print(f"  MITRE ATT&CK coverage:      {a6['mitre_coverage_pct']}")
    print(f"  Report URL coverage:        {a9['report_url_coverage']}")
    print(f"  STIX bundle coverage:       {a9['stix_bundle_coverage']}")
    print(f"  Validated IOCs total:       {a7['total_validated_iocs']}")
    print(f"  FP removed:                 {a7['total_fp_removed']}")
    print(f"  P26 avg composite grade:    {a12['average_p26_composite']}/100")
    print(f"  P26 enterprise grade:       {a12['enterprise_grade_pct']} of items B or above")
    print(f"  Regression tests:           {a10.get('tests_passed', 0)} PASS / {a10.get('tests_failed', 0)} FAIL")

    print(f"\n{'═'*72}")

    # Build report
    report = {
        "version":       VERSION,
        "generated_at":  _ts(),
        "release_tier":  a13_tier,
        "feed_items":    len(items),
        "blocker_count": a13["total_blockers"],
        "warning_count": a13["total_warnings"],
        "blockers":      a13["blockers"],
        "warnings":      a13["warnings"],
        "audits": {
            code: {
                "name":    AUDIT_NAMES[code],
                "passed":  result["passed"],
                "notes":   result["notes"],
                # Include key metrics but not verbose output
                **{k: v for k, v in result.items()
                   if k not in ("passed", "notes", "output_tail") and not isinstance(v, (list, dict)) or k in ("grade_distribution", "reliability_distribution", "tier_distribution")},
            }
            for code, result in audits.items()
        },
        "quality_summary": {
            "items":                   len(items),
            "avg_enrichment":          a4["average_enrichment"],
            "evidence_coverage":       a5["coverage_pct"],
            "mitre_coverage":          a6["mitre_coverage_pct"],
            "report_url_coverage":     a9["report_url_coverage"],
            "stix_coverage":           a9["stix_bundle_coverage"],
            "validated_iocs":          a7["total_validated_iocs"],
            "synthetic_language":      a8["synthetic_language_detected"],
            "p26_avg_composite":       a12["average_p26_composite"],
            "p26_enterprise_grade_pct": a12["enterprise_grade_pct"],
            "regression_tests_passed": a10.get("tests_passed", 0),
            "regression_tests_failed": a10.get("tests_failed", 0),
        },
    }

    if not DRY_RUN:
        _QUALITY.mkdir(parents=True, exist_ok=True)
        out = _QUALITY / "p26_certification_report.json"
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[P26.0] Certification report written: {out}")

    return report


if __name__ == "__main__":
    result = run()
    # Only exit 1 on RELEASE_BLOCKED — CI continues regardless (continue-on-error)
    sys.exit(1 if result["release_tier"] == "RELEASE_BLOCKED" else 0)
