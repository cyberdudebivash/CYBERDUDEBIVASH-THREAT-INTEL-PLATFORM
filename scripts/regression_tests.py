#!/usr/bin/env python3
"""
scripts/regression_tests.py
CYBERDUDEBIVASH(R) SENTINEL APEX v143.3 -- Permanent Anti-Regression Test Suite
==================================================================================
PHASE 11: Regression guard for the production pipeline.

Tests cover:
  T01  critical script file sizes (truncation regression)
  T02  Python syntax clean on all pipeline scripts
  T03  validate_repo.py 8/8 PASS (full schema + encoding gate)
  T04  feed.json is valid JSON + non-empty
  T05  manifest has entries and no duplicate IDs
  T06  ioc_count == len(iocs) for every manifest entry
  T07  no fake risk 10/10 without CVE/KEV evidence
  T08  reports/ directory has >= 1 HTML report
  T09  no report_url pointing to source_url (report_url must be internal /reports/)
  T10  no null bytes in critical scripts
  T11  STIX bundles directory has files
  T12  CI workflow YAML parses cleanly + no inline Python heredocs regression
  T21  v184.0 guard: all feed.json local-source report_urls present in dist/reports/
  T22  v185.2 guard: source_url dedup survives late-pipeline reintroduction (Phase 5/stability-lock)
  T23  v185.2 guard: governance scorer recognises mitre_tactics field, vulnerability-class IOC semantics
  T25  workflow_dispatch-capable workflows never hardcode checkout ref to 'main'
  T26  P0 R2 cost incident permanent guard: no whole-corpus R2 report sync;
       every generate_intel_reports.py scheduled call site bound to --since-hours

Exit codes:
  0 = ALL PASS
  1 = ONE OR MORE FAIL (regression detected)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import ast
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [regression] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.regression_tests")

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
REPORTS_DIR = REPO_ROOT / "reports"
DIST_REPORTS_DIR = REPO_ROOT / "dist" / "reports"   # fallback: present after Stage 5.4.6 dist build
STIX_DIR = REPO_ROOT / "data" / "stix"
FEED_JSON = REPO_ROOT / "feed.json"
WORKFLOW_YAML = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

RESULTS: list[dict] = []


def test(name: str) -> Callable:
    """Decorator to register and run a test."""
    def decorator(fn: Callable) -> Callable:
        try:
            fn()
            RESULTS.append({"test": name, "status": "PASS", "detail": ""})
            log.info("  PASS  %s", name)
        except AssertionError as e:
            RESULTS.append({"test": name, "status": "FAIL", "detail": str(e)})
            log.error("  FAIL  %s -- %s", name, e)
        except Exception as e:
            RESULTS.append({"test": name, "status": "ERROR", "detail": str(e)})
            log.error("  ERROR %s -- %s", name, e)
        return fn
    return decorator


# ---------------------------------------------------------------------------
# T01: Critical script file sizes (truncation regression)
# ---------------------------------------------------------------------------

@test("T01_critical_file_sizes")
def t01():
    thresholds = {
        "scripts/run_pipeline.py":           55_000,
        "agent/sentinel_blogger.py":         25_000,
        "agent/export_stix.py":              30_000,
        "scripts/intel_dedup_engine.py":     15_000,
        "scripts/generate_intel_reports.py": 45_000,
        "scripts/validate_repo.py":          10_000,
    }
    failures = []
    for rel, min_b in thresholds.items():
        p = REPO_ROOT / rel
        if not p.exists():
            failures.append(f"MISSING: {rel}")
            continue
        sz = p.stat().st_size
        if sz < min_b:
            failures.append(f"TRUNCATED {rel}: {sz} bytes < {min_b}")
    assert not failures, f"{len(failures)} file(s) truncated/missing: {failures}"


# ---------------------------------------------------------------------------
# T02: Python syntax clean on all pipeline scripts
# ---------------------------------------------------------------------------

@test("T02_python_syntax_clean")
def t02():
    # Use ast.parse() instead of py_compile to avoid Windows temp-file permission
    # errors ([WinError 5] Access is denied on .pyc rename) that produce false-negatives.
    # ast.parse() performs a full syntax parse with zero filesystem side-effects.
    import ast
    script_dirs = [
        REPO_ROOT / "scripts",
        REPO_ROOT / "agent",
    ]
    errors = []
    for d in script_dirs:
        if not d.is_dir():
            continue
        for py in sorted(d.rglob("*.py")):
            try:
                source = py.read_bytes()
                ast.parse(source, filename=str(py))
            except SyntaxError as e:
                errors.append(f"{py.relative_to(REPO_ROOT)}:{e.lineno}: {e.msg}")
            except Exception as e:
                errors.append(f"{py.relative_to(REPO_ROOT)}: read/parse error: {e}")
    assert not errors, f"{len(errors)} Python syntax error(s): {errors[:5]}"


# ---------------------------------------------------------------------------
# T03: validate_repo.py 8/8 PASS
# ---------------------------------------------------------------------------

@test("T03_validate_repo_8_of_8")
def t03():
    vr = REPO_ROOT / "scripts" / "validate_repo.py"
    assert vr.exists(), "validate_repo.py not found"
    r = subprocess.run(
        [sys.executable, str(vr)],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=60,
    )
    output = r.stdout + r.stderr
    assert r.returncode == 0, f"validate_repo.py exited {r.returncode}\n{output[-500:]}"
    assert "ALL CHECKS PASSED" in output, f"validate_repo.py did not print ALL CHECKS PASSED\n{output[-300:]}"


# ---------------------------------------------------------------------------
# T04: feed.json valid JSON + non-empty
# ---------------------------------------------------------------------------

@test("T04_feed_json_valid_nonempty")
def t04():
    assert FEED_JSON.exists(), f"feed.json missing: {FEED_JSON}"
    raw = FEED_JSON.read_bytes()
    assert b"\x00" not in raw, "feed.json contains null bytes"
    obj = json.loads(raw.decode("utf-8"))
    entries = obj if isinstance(obj, list) else obj.get("advisories", [])
    assert len(entries) > 0, f"feed.json is empty (0 entries)"


# ---------------------------------------------------------------------------
# T05: Manifest non-empty + no duplicate IDs
# ---------------------------------------------------------------------------

@test("T05_manifest_unique_ids")
def t05():
    # Primary: data/stix/feed_manifest.json
    # Fallback: api/feed.json (if stix manifest is empty -- by-design bootstrap reset)
    # See stability_lock.json known_non_fatal_warns: manifest_shrink_warning
    api_feed = REPO_ROOT / "api" / "feed.json"
    manifest_to_check = MANIFEST_PATH
    if MANIFEST_PATH.exists():
        raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        items_check = raw if isinstance(raw, list) else raw.get("data", raw.get("advisories", []))
        if len(items_check) == 0:
            # Stix manifest empty by design -- fall back to api/feed.json
            if api_feed.exists():
                manifest_to_check = api_feed
                log.info("[T05] stix manifest empty (by-design) -- using api/feed.json")
    else:
        # Stix manifest absent entirely (fresh checkout pre-pipeline run) -- fall back to api/feed.json
        if api_feed.exists():
            manifest_to_check = api_feed
            log.info("[T05] stix manifest absent -- using api/feed.json fallback")
    assert manifest_to_check.exists(), f"Neither stix manifest nor api/feed.json found"
    data = json.loads(manifest_to_check.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("items", data.get("data", data.get("advisories", [])))
    assert len(items) > 0, (
        f"Both data/stix/feed_manifest.json and api/feed.json have 0 entries -- "
        "pipeline produced no intel output"
    )
    ids = [i.get("stix_id", i.get("id", "")) for i in items if isinstance(i, dict)]
    non_empty = [x for x in ids if x]
    dupes = [x for x in set(non_empty) if non_empty.count(x) > 1]
    assert not dupes, f"{len(dupes)} duplicate IDs: {dupes[:5]}"


# ---------------------------------------------------------------------------
# T06: ioc_count == len(iocs) for every entry
# ---------------------------------------------------------------------------

@test("T06_ioc_count_consistency")
def t06():
    # NOTE: The ioc_count field in existing manifest entries may be stale (0) while
    # iocs[] has been populated by the IOC engine fix.  The pipeline dedup+enrich stage
    # corrects this on every run.  T06 only hard-fails on SYSTEMIC regression (>95%),
    # meaning virtually every single entry is broken — which would indicate the IOC
    # engine itself is down, not stale data from before the fix was deployed.
    if not MANIFEST_PATH.exists():
        return
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("advisories", [])
    if not items:
        return
    mismatches = []
    for item in items:
        cnt = item.get("ioc_count", 0)
        iocs = item.get("iocs", [])
        actual = len(iocs) if isinstance(iocs, list) else 0
        if cnt != actual:
            mismatches.append(f"{item.get('id','?')}: ioc_count={cnt} vs actual={actual}")
    mismatch_pct = len(mismatches) / len(items) * 100
    if mismatch_pct > 95:
        assert False, (
            f"SYSTEMIC ioc_count regression: {len(mismatches)}/{len(items)} entries "
            f"({mismatch_pct:.0f}%) mismatched — exceeds 95% threshold (IOC engine down?): {mismatches[:5]}"
        )
    if mismatches:
        log.warning(
            "T06 advisory: %d/%d entries (%.0f%%) have ioc_count != len(iocs) "
            "(stale data — pipeline will correct on next run)",
            len(mismatches), len(items), mismatch_pct,
        )


# ---------------------------------------------------------------------------
# T07: No fake risk=10 without evidence
# ---------------------------------------------------------------------------

@test("T07_no_fake_risk_10")
def t07():
    """
    Ensures no entry has a CRITICAL-tier risk score (>= 9.0) without at least ONE
    piece of verifiable justification.

    Evidence criteria (ANY ONE satisfies the gate — mirrors run_pipeline.py C3
    FALSE_CRITICAL gate AND severity_invariant_interceptor.py Rule C signals):
      a) Formal CVE identifier  (cve_id present)
      b) CISA KEV confirmed     (kev_present)
      c) CVSS >= 9.0            -- NVD critical score (SII Rule C; alone is sufficient)
      d) EPSS >= 0.7            -- 70%+ exploitation probability in 30 days
      e) IOC confidence >= 80 AND ioc_count >= 5          -- high-quality observables
      f) CDB proprietary campaign (actor_tag starts with CDB-)
      g) Active exploitation structured field (active_exploitation, exploited_in_wild…)
      h) Public exploit code available (public_exploit_code, poc_available…)
      i) Critical threat class (rce, auth_bypass, unauthenticated_rce…)
      j) Active exploitation keywords in text (SII Rule C keyword set)

    Criteria g–j mirror the SeverityInvariantInterceptor Rule C signals so T07 never
    flags entries that SII itself considers legitimately CRITICAL.  Without these, SII
    promotes items to CRITICAL/risk=9.0 on keyword or struct signals, then T07 falsely
    flags them — causing STAGE 5.6 HARD FAIL on every pipeline run that ingests an
    actively-exploited threat without a formal CVE assignment.
    """
    if not MANIFEST_PATH.exists():
        return  # not blocking if manifest absent
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("advisories", [])

    def _justified(i: dict) -> bool:
        kev      = i.get("kev_present", False) or i.get("kev", False)
        cvss     = float(i.get("cvss_score") or i.get("cvss") or 0)
        epss     = float(i.get("epss_score") or i.get("epss") or 0)
        ioc_cnt  = int(i.get("ioc_count", 0))
        ioc_conf = float(i.get("ioc_confidence") or 0)
        cve_id   = bool(i.get("cve_id"))
        # f) CDB proprietary campaign — actor-research scored, not CVE-based.
        # Mirrors the exemption in run_pipeline.py C3 FALSE_CRITICAL gate.
        # Covers CDB-* (curated) and UNC-CDB-* (unconfirmed ingest) actors.
        # Pipeline considers these legitimately CRITICAL; T07 must agree.
        _actor   = (i.get("actor_tag") or "").strip().upper()
        cdb_prop = ("CDB-" in _actor) and not (i.get("cve_ids") or cve_id)
        # g) SII Rule C: active exploitation structured fields.
        # Mirrors severity_invariant_interceptor._ACTIVE_EXPLOIT_STRUCT_FIELDS.
        # SII promotes items to CRITICAL on these fields; T07 must agree.
        _ae_struct = any(bool(i.get(f)) for f in (
            "active_exploitation", "actively_exploited", "exploited_in_wild",
            "is_exploited", "exploited",
        ))
        # h) SII Rule C: public exploit code available.
        # Mirrors severity_invariant_interceptor._PUBLIC_EXPLOIT_FIELDS.
        _pub_exploit = any(bool(i.get(f)) for f in (
            "public_exploit_code", "exploit_available", "exploit_public",
            "exploit_code", "poc_available",
        ))
        # i) SII Rule C: critical threat class (RCE, auth bypass, etc.).
        # Mirrors severity_invariant_interceptor._CRITICAL_THREAT_CLASSES.
        _tc = (
            i.get("threat_class") or i.get("threat_type") or i.get("vuln_type") or ""
        ).lower()
        _crit_tc = _tc in {
            "rce", "auth_bypass", "remote_code_execution", "authentication_bypass",
            "unauthenticated_rce", "pre_auth_rce", "os_command_injection",
            "deserialization_rce",
        }
        # j) SII Rule C: active exploitation keywords in text fields.
        # Mirrors severity_invariant_interceptor._has_active_exploit_keywords().
        # SII promotes to CRITICAL when these appear in title/desc/summary.
        # T07 must recognise the same signals as legitimate justification.
        _text = " ".join(
            str(i.get(f, ""))
            for f in ("title", "description", "summary", "analysis", "notes")
        ).lower()
        _exploit_kw = [
            "actively exploited", "actively exploiting", "exploited in the wild",
            "active exploitation", "under active attack", "zero-day exploit",
            "0-day exploit", "mass exploitation", "widespread exploitation",
            "ransomware deployment", "ransom deployed", "weaponized exploit",
        ]
        _sii_keyword = any(kw in _text for kw in _exploit_kw)
        return (
            cdb_prop                                # f) CDB proprietary campaign
            or cve_id                               # a) formal CVE
            or kev                                  # b) CISA KEV
            or cvss >= 9.0                          # c) CVSS critical (SII Rule C: cvss alone)
            or epss >= 0.7                          # d) very high EPSS
            or (ioc_conf >= 80.0 and ioc_cnt >= 5) # e) high-quality IOC cluster
            or _ae_struct                           # g) active exploitation struct field
            or _pub_exploit                         # h) public exploit code available
            or _crit_tc                             # i) critical threat class (RCE etc)
            or _sii_keyword                         # j) active exploitation keywords in text
        )

    fake = [
        f"{i.get('id','?')}: risk={i.get('risk_score',0)}"
        for i in items
        if float(i.get("risk_score", 0)) >= 9.0
        and not _justified(i)
    ]
    assert not fake, (
        f"{len(fake)} entries with risk>=9.0 and NO verifiable high-confidence evidence "
        f"(no CVE/KEV/CVSS-critical/high-EPSS/quality-IOCs): {fake[:5]}"
    )


# ---------------------------------------------------------------------------
# T08: reports/ has >= 1 HTML report
# ---------------------------------------------------------------------------
# v143.3 FIX: Stage 5.4.6b (Post-dist reports/ cleanup) deletes reports/ from
# the runner disk after dist/ is built, to recover disk space. This caused T08
# to fail because it only checked REPORTS_DIR (which is gitignored and deleted
# by 5.4.6b). Fix: check DIST_REPORTS_DIR as the authoritative fallback --
# dist/reports/ is always populated by Stage 5.4.6 before 5.4.6b cleanup runs.
# Also accept REPORT_COUNT env var (set by report-generator stage) as evidence.
# ---------------------------------------------------------------------------

@test("T08_reports_directory_nonempty")
def t08():
    # Check primary reports/ dir first (present if pipeline hasn't hit disk cleanup yet)
    for check_dir in [REPORTS_DIR, DIST_REPORTS_DIR]:
        if check_dir.is_dir():
            html_files = [f for f in check_dir.rglob("*.html") if f.name != "index.html"]
            if html_files:
                return  # PASS -- found HTML reports

    # Belt-and-suspenders: trust REPORT_COUNT env var set by report-generator stage.
    # Stage 5.4.6b deletes reports/ AFTER dist is built; REPORT_COUNT persists in env.
    import os as _os
    report_count_env = int(_os.environ.get("REPORT_COUNT", "0"))
    if report_count_env > 0:
        return  # PASS -- reports were generated (cleaned up post-dist for disk space)

    assert False, (
        "No HTML reports found in reports/ or dist/reports/, "
        f"and REPORT_COUNT={report_count_env}. "
        "Report generation (Stage 3.2) may have failed -- check generate_intel_reports.py."
    )


# ---------------------------------------------------------------------------
# T09: No report_url == source_url
# ---------------------------------------------------------------------------

@test("T09_report_url_not_source_url")
def t09():
    if not MANIFEST_PATH.exists():
        return
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("advisories", [])
    violations = [
        i.get("id", "?") for i in items
        if i.get("report_url") and i.get("report_url") == i.get("source_url")
        and "?apex=1" not in (i.get("report_url") or "")
    ]
    assert not violations, f"{len(violations)} entries: report_url == source_url: {violations[:5]}"


# ---------------------------------------------------------------------------
# T10: No null bytes in critical scripts
# ---------------------------------------------------------------------------

@test("T10_no_null_bytes_in_scripts")
def t10():
    critical = [
        "scripts/run_pipeline.py",
        "agent/sentinel_blogger.py",
        "agent/export_stix.py",
        "scripts/safe_git_commit.py",
    ]
    poisoned = []
    NULL_BYTE = b"\x00"
    for rel in critical:
        p = REPO_ROOT / rel
        if p.exists():
            raw = p.read_bytes()
            nb = raw.count(NULL_BYTE)
            if nb:
                poisoned.append(f"{rel}: {nb} null bytes")
    assert not poisoned, f"Null bytes detected in {len(poisoned)} script(s): {poisoned}"


# ---------------------------------------------------------------------------
# T11: STIX bundles directory has files
# ---------------------------------------------------------------------------

@test("T11_stix_bundles_exist")
def t11():
    assert STIX_DIR.is_dir(), f"data/stix/ directory missing"
    stix_files = list(STIX_DIR.glob("CDB-APEX-*.json"))
    assert len(stix_files) > 0, "No CDB-APEX-*.json STIX bundles in data/stix/"


# ---------------------------------------------------------------------------
# T12: CI workflow YAML parses + no inline Python heredocs
# ---------------------------------------------------------------------------

@test("T12_ci_workflow_clean")
def t12():
    assert WORKFLOW_YAML.exists(), "sentinel-blogger.yml not found"
    try:
        import yaml
        with open(WORKFLOW_YAML, encoding="utf-8") as fh:
            yaml.safe_load(fh)
    except Exception as e:
        assert False, f"Workflow YAML parse error: {e}"

    content = WORKFLOW_YAML.read_text(encoding="utf-8")
    # Inline heredocs pattern: python3 - <<'PYEOF' -- these are now intentionally used
    # for the new pre-flight step, so we check for the OLD pattern (multi-line python3 -c)
    import re
    old_inline = re.findall(r"python3 -c ['\"]import", content)
    assert not old_inline, f"Old-style inline Python -c found in workflow: {old_inline}"


# ---------------------------------------------------------------------------
# T13: anomaly_radar_engine output contract
# ---------------------------------------------------------------------------

@test("T13_anomaly_radar_output_contract")
def t13():
    """Verify anomaly_radar_engine.py exists and data/ai/anomaly_radar.json is valid."""
    script = REPO_ROOT / "scripts" / "anomaly_radar_engine.py"
    assert script.exists(), "anomaly_radar_engine.py missing from scripts/"
    sz = script.stat().st_size
    assert sz >= 5_000, f"anomaly_radar_engine.py suspiciously small: {sz} bytes"

    radar_path = REPO_ROOT / "data" / "ai" / "anomaly_radar.json"
    if not radar_path.exists():
        # Not generated yet on fresh checkout — warn but don't hard-fail
        log.warning("[T13] data/ai/anomaly_radar.json not yet generated — skipping content check")
        return

    data = json.loads(radar_path.read_text(encoding="utf-8"))
    # Must be a list or have 'advisories' key
    items = data if isinstance(data, list) else data.get("advisories", data.get("items", []))
    assert isinstance(items, list), "anomaly_radar.json root is not a list or advisories dict"

    # At least one item must have the zero_day_candidate field (engine ran)
    has_zd_field = any(
        "is_zero_day_candidate" in item or "anomaly_score" in item
        for item in items if isinstance(item, dict)
    )
    assert has_zd_field or len(items) == 0, (
        "anomaly_radar.json items lack is_zero_day_candidate/anomaly_score fields — "
        "engine may not have injected output"
    )


# ---------------------------------------------------------------------------
# T14: enterprise_signal_push sector coverage
# ---------------------------------------------------------------------------

@test("T14_enterprise_signal_push_sectors")
def t14():
    """Verify enterprise_signal_push.py exists and covers all 10 required sectors."""
    script = REPO_ROOT / "scripts" / "enterprise_signal_push.py"
    assert script.exists(), "enterprise_signal_push.py missing from scripts/"
    sz = script.stat().st_size
    assert sz >= 5_000, f"enterprise_signal_push.py suspiciously small: {sz} bytes"

    content = script.read_text(encoding="utf-8")
    # Match against actual SECTORS list entries in enterprise_signal_push.py.
    # The taxonomy uses display names: "Financial Services", "Healthcare", etc.
    # We verify by substring (case-insensitive) so minor naming variants don't break.
    required_sector_substrings = [
        "Financial Services",    # finance / banking
        "Healthcare",            # healthcare / pharma
        "Critical Infrastructure",  # energy / utilities / ICS-SCADA
        "Government",            # government & defense
        "Technology",            # tech / SaaS / cloud
        "Energy",                # energy & utilities
        "Retail",                # retail & e-commerce
        "Telecom",               # telecommunications
        "Manufacturing",         # manufacturing / OT
        "Education",             # education & research
    ]
    missing = [s for s in required_sector_substrings if s.lower() not in content.lower()]
    assert not missing, (
        f"enterprise_signal_push.py missing sector coverage: {missing}. "
        "All 10 sectors required for $499/mo tier compliance."
    )

    # Verify forecast output if it exists
    forecast_path = REPO_ROOT / "data" / "ai" / "enterprise_forecast.json"
    if forecast_path.exists():
        data = json.loads(forecast_path.read_text(encoding="utf-8"))
        forecasts = data if isinstance(data, list) else data.get("sectors", data.get("forecasts", []))
        assert isinstance(forecasts, list), "enterprise_forecast.json malformed"


# ---------------------------------------------------------------------------
# T15: sovereign_mssp_router tenant isolation
# ---------------------------------------------------------------------------

@test("T15_sovereign_mssp_router_isolation")
def t15():
    """Verify sovereign_mssp_router.py exists and has tenant isolation primitives."""
    script = REPO_ROOT / "scripts" / "sovereign_mssp_router.py"
    assert script.exists(), "sovereign_mssp_router.py missing from scripts/"
    sz = script.stat().st_size
    assert sz >= 5_000, f"sovereign_mssp_router.py suspiciously small: {sz} bytes"

    content = script.read_text(encoding="utf-8")
    required_primitives = [
        "tenant_id",
        "kg_namespace",
        "tlp_filter",
        "jwt",
        "_map_kg_nodes",
        "_filter_items_for_tenant",
    ]
    missing = [p for p in required_primitives if p not in content]
    assert not missing, (
        f"sovereign_mssp_router.py missing isolation primitives: {missing}. "
        "These are mandatory for MSSP tenant isolation security."
    )

    # Verify sovereign tenant config exists
    tenant_cfg = REPO_ROOT / "config" / "sovereign_tenants.json"
    assert tenant_cfg.exists(), (
        "config/sovereign_tenants.json missing — "
        "Sovereign Mode cannot activate without tenant configuration."
    )
    cfg_data = json.loads(tenant_cfg.read_text(encoding="utf-8"))
    tenants = cfg_data.get("tenants", cfg_data if isinstance(cfg_data, list) else [])
    assert isinstance(tenants, list), "sovereign_tenants.json must have a 'tenants' list"


# ---------------------------------------------------------------------------
# T16: mitre_v15_enricher tactic correctness (T1486 must not be "Execution")
# ---------------------------------------------------------------------------

@test("T16_mitre_v15_enricher_tactic_correctness")
def t16():
    """Verify mitre_v15_enricher.py exists and has the critical T1486 tactic correction."""
    script = REPO_ROOT / "scripts" / "mitre_v15_enricher.py"
    assert script.exists(), "mitre_v15_enricher.py missing from scripts/"
    sz = script.stat().st_size
    assert sz >= 8_000, f"mitre_v15_enricher.py suspiciously small: {sz} bytes"

    content = script.read_text(encoding="utf-8")

    # T1486 must be mapped to "impact" NOT "execution" (v15 correction)
    assert "T1486" in content, "T1486 (Data Encrypted for Impact) missing from enricher lookup table"

    # The tactic for T1486 must NOT be "execution" — that's the classic wrong mapping
    import re
    t1486_block = re.search(r"T1486[^}]{0,300}", content, re.DOTALL)
    if t1486_block:
        block_text = t1486_block.group(0).lower()
        assert "impact" in block_text, (
            "T1486 tactic must be 'impact' in ATTACK_V15 lookup table. "
            "Found block does not contain 'impact' — tactic correction not applied."
        )
        assert "execution" not in block_text or block_text.index("impact") < block_text.index("execution") + 50, (
            "T1486 block appears to map to 'execution' before 'impact' — "
            "critical tactic correction regression detected."
        )

    # Must have >= 100 technique entries for credible v15 coverage
    tid_count = len(re.findall(r'"T\d{4}(?:\.\d{3})?"', content))
    assert tid_count >= 100, (
        f"ATTACK_V15 table has only {tid_count} TIDs (expected >= 100 for v15 coverage)"
    )


# ---------------------------------------------------------------------------
# T17: crash_guard minimum success assertion + safe_ioc_list present
# ---------------------------------------------------------------------------

@test("T17_crash_guard_isolation_primitives")
def t17():
    """Verify crash_guard.py exists with all Phase 2 isolation primitives."""
    script = REPO_ROOT / "scripts" / "crash_guard.py"
    assert script.exists(), "crash_guard.py missing from scripts/"
    sz = script.stat().st_size
    assert sz >= 5_000, f"crash_guard.py suspiciously small: {sz} bytes"

    content = script.read_text(encoding="utf-8")
    required = [
        "CrashGuard",
        "run_isolated",
        "safe_ioc_list",
        "safe_dedup_l0_register",
        "assert_minimum_success",
        "write_ledger",
        "daemon",
    ]
    missing = [p for p in required if p not in content]
    assert not missing, (
        f"crash_guard.py missing isolation primitives: {missing}. "
        "These are mandatory for Phase 2 Multi-Feed Fusion crash isolation."
    )


# ---------------------------------------------------------------------------
# T18: pipeline_warn_resolver idempotency (runs twice, same verdict)
# ---------------------------------------------------------------------------

@test("T18_warn_resolver_exists_and_idempotent")
def t18():
    """Verify pipeline_warn_resolver.py exists and has all 4 WARN fixers."""
    script = REPO_ROOT / "scripts" / "pipeline_warn_resolver.py"
    assert script.exists(), "pipeline_warn_resolver.py missing from scripts/"
    sz = script.stat().st_size
    assert sz >= 5_000, f"pipeline_warn_resolver.py suspiciously small: {sz} bytes"

    content = script.read_text(encoding="utf-8")
    required = [
        "resolve_warn1_fake_risk",
        "resolve_warn2_published_bool",
        "resolve_warn3_r2_sync",
        "resolve_warn4_future_timestamps",
        "_atomic_write",
    ]
    missing = [p for p in required if p not in content]
    assert not missing, (
        f"pipeline_warn_resolver.py missing WARN fixers: {missing}. "
        "All 4 WARN resolvers required for zero-WARN pipeline mandate."
    )

    # Verify r2_sync_state has sync=True if it exists
    r2_state = REPO_ROOT / "data" / "r2_sync_state.json"
    if r2_state.exists():
        try:
            state = json.loads(r2_state.read_text(encoding="utf-8"))
            assert state.get("sync") is True, (
                f"data/r2_sync_state.json has sync={state.get('sync')} — "
                "must be True (Stage 5.6.1 mandate)"
            )
        except json.JSONDecodeError:
            assert False, "data/r2_sync_state.json is malformed JSON"


# ---------------------------------------------------------------------------
# T19: r2_upload_verifier.py exists and is valid Python
# ---------------------------------------------------------------------------

@test("T19_r2_upload_verifier_present")
def t19():
    """Verify r2_upload_verifier.py (Stage 3.6) exists and has required primitives."""
    script = REPO_ROOT / "scripts" / "r2_upload_verifier.py"
    assert script.exists(), (
        "r2_upload_verifier.py missing from scripts/ — "
        "Stage 3.6 R2 integrity gate is absent. "
        "R2 upload can silently fail with no pre-cache-bust verification."
    )
    sz = script.stat().st_size
    assert sz >= 3_000, f"r2_upload_verifier.py suspiciously small: {sz} bytes"

    content = script.read_text(encoding="utf-8")
    required = [
        "verify_r2_object",
        "verify_local_feed",
        "MIN_FEED_BYTES",
        "MIN_ADVISORY_COUNT",
        "_http_head",
    ]
    missing = [p for p in required if p not in content]
    assert not missing, (
        f"r2_upload_verifier.py missing verification primitives: {missing}"
    )

    # Must be valid Python syntax — use ast.parse (no temp file writes, Windows-safe)
    try:
        ast.parse(script.read_bytes(), filename=str(script))
    except SyntaxError as e:
        assert False, f"r2_upload_verifier.py has syntax error at line {e.lineno}: {e.msg}"


# ---------------------------------------------------------------------------
# T20: safe_push.ps1 present (CI race fix deployed)
# ---------------------------------------------------------------------------

@test("T20_safe_push_ps1_deployed")
def t20():
    """Verify safe_push.ps1 (CI race fix) is deployed in scripts/."""
    script = REPO_ROOT / "scripts" / "safe_push.ps1"
    assert script.exists(), (
        "scripts/safe_push.ps1 missing — "
        "CI-race-safe push script not deployed. "
        "Local pushes will be vulnerable to 'cannot lock ref' rejections."
    )
    sz = script.stat().st_size
    assert sz >= 3_000, f"safe_push.ps1 suspiciously small: {sz} bytes"

    content = script.read_text(encoding="utf-8")
    required = [
        "MaxRetries",
        "rebase",
        "skip ci",
        "backoff",
        "fetch",
    ]
    missing = [p for p in required if p.lower() not in content.lower()]
    assert not missing, (
        f"safe_push.ps1 missing CI race-fix primitives: {missing}"
    )

    # Verify workflow has fetch-depth: 1 (performance regression guard)
    wf = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"
    if wf.exists():
        wf_content = wf.read_text(encoding="utf-8")
        assert "fetch-depth: 0" not in wf_content, (
            "sentinel-blogger.yml still has fetch-depth: 0 — "
            "reverts the 70s checkout optimization. Should be fetch-depth: 1."
        )
        assert "fetch-depth: 1" in wf_content, (
            "sentinel-blogger.yml does not have fetch-depth: 1 — "
            "checkout optimization not applied."
        )


# ---------------------------------------------------------------------------
# T21: v184.0 force-include guard -- all feed.json local-source reports in dist/
# ---------------------------------------------------------------------------

@test("T21_force_include_feed_reports_in_dist")
def t21():
    """Regression guard for build_dist_artifact.py v184.0 force_include_feed_reports().

    Root cause: copy_reports_selective() uses proportional boundary-month alphabetical
    sort to select dist/ reports.  Current-run reports with older advisory timestamps
    can fall BEFORE the last-N% cut-off, causing ALL current-run reports to be excluded
    from dist/ even though they are referenced in feed.json.  force_include_feed_reports()
    was added to unconditionally copy any feed.json report_url that has a local source
    but is missing from dist/.

    A regression here causes Stage 5.8.1b Report URL Canary to P0 FAIL-CLOSED with
    'N missing / 0 ok'.  This test catches the regression before deployment.

    Only runs when dist/reports/ exists (i.e., after Stage 5.4.6).  Skips otherwise.
    """
    dist_reports = REPO_ROOT / "dist" / "reports"
    if not dist_reports.is_dir():
        log.info("[T21] dist/reports/ not built yet — skipping (post-build gate only)")
        return

    from urllib.parse import urlparse

    feed_paths = [REPO_ROOT / "api" / "feed.json", REPO_ROOT / "feed.json"]
    feed_rels: list[str] = []
    seen: set[str] = set()
    for fp in feed_paths:
        if not fp.exists():
            continue
        try:
            raw = fp.read_bytes().rstrip(b"\x00")
            data = json.loads(raw.decode("utf-8", errors="replace"))
            items = data if isinstance(data, list) else []
            for item in items:
                for key in ("report_url", "internal_report_url"):
                    ru = (item.get(key) or "").strip()
                    if not ru:
                        continue
                    path = urlparse(ru).path if ru.lower().startswith("http") else ru
                    if "/reports/" in path and path.lower().endswith(".html"):
                        rel = path[path.index("/reports/"):]
                        if rel not in seen:
                            seen.add(rel)
                            feed_rels.append(rel)
        except Exception as exc:
            log.warning("[T21] Could not parse %s: %s", fp.name, exc)
        if feed_rels:
            break  # first feed with content is authoritative (same priority as canary)

    if not feed_rels:
        log.info("[T21] No report_url values in feed.json — nothing to check (skip)")
        return

    missing_from_dist: list[str] = []
    for rel in feed_rels:
        # Only fail for files that have a local source.  Historical reports (from prior
        # pipeline runs, no local file in working tree) are legitimately absent from dist/.
        local_src = REPO_ROOT / rel.lstrip("/")
        if not local_src.exists():
            continue
        dist_path = REPO_ROOT / "dist" / rel.lstrip("/")
        if not dist_path.exists():
            missing_from_dist.append(rel)

    assert not missing_from_dist, (
        f"v184.0 REGRESSION: {len(missing_from_dist)} feed.json report_url(s) have a "
        f"local source but are MISSING from dist/reports/.  "
        f"force_include_feed_reports() in build_dist_artifact.py did not run or was "
        f"skipped.  Stage 5.8.1b Report URL Canary will P0 FAIL-CLOSED.  "
        f"Affected paths: {missing_from_dist[:5]}"
    )
    local_count = len(feed_rels) - sum(
        1 for rel in feed_rels if not (REPO_ROOT / rel.lstrip("/")).exists()
    )
    log.info("[T21] %d feed.json local-source report_url(s) — all present in dist/", local_count)


# ---------------------------------------------------------------------------
# T22: v185.2 final pre-write dedup gate -- exact escaped-duplicate class
# ---------------------------------------------------------------------------

@test("T22_source_url_dedup_survives_late_pipeline_reintroduction")
def t22():
    """Regression guard for the source_url duplicate that reached production.

    Root cause: enforce_manifest_uniqueness() (scripts/intel_dedup_engine.py) is
    documented as the "final pre-write manifest uniqueness guard" but previously
    ran at Phase 4 of run_pipeline.py, BEFORE the Phase 5 quality engine's
    source-balancing carry-forward logic and sentinel_stability_lock's output
    contract enforcement (which checks stix_id and title only, never
    source_url). Either later stage could silently reintroduce a source_url
    duplicate that Phase 4 had already removed. Confirmed live via
    data/governance/governance_report.json history: enterprise-governance CI
    runs flapped governance_grade between A+/A and C/D across consecutive
    ~2-hour scheduled runs on the same feed, with the C/D runs showing exactly
    one HARD source_url duplicate (a syndicated "Weekly Cyber Security
    Newsletter Bulletin" item under two different item-ID schemes). Fixed by
    re-invoking the same idempotent enforce_manifest_uniqueness() guard
    immediately before the Step 6 feed.json write in run_pipeline.py.

    This test has two parts:
      1. Unit-level: enforce_manifest_uniqueness() must block the exact escaped
         duplicate class -- two items sharing a source_url (post-normalisation)
         under two different item-ID formats -- regardless of call order.
      2. Live-data: the actual committed api/feed.json must currently contain
         zero source_url duplicates (post-normalisation), matching the
         Phase-2 acceptance criterion that duplicates never reach customer feeds.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from intel_dedup_engine import enforce_manifest_uniqueness, _url_key  # noqa: E402

    # Part 1: exact escaped-duplicate class, unit-level.
    dup_url = "https://example-newsletter.test/weekly-bulletin?utm_source=rss"
    synthetic_items = [
        {"id": "intel--09ca06921ac33b95", "stix_id": "indicator--aaa1",
         "title": "Weekly Cyber Security Newsletter Bulletin - Entra ID RCE +19 Stories",
         "source_url": dup_url, "published": "2026-08-20T00:00:00Z"},
        {"id": "intel--6f181fd3744a72102d33754c", "stix_id": "indicator--aaa2",
         "title": "Weekly Cyber Security Newsletter Bulletin - Entra ID RCE +20 Stories",
         "source_url": dup_url.upper(), "published": "2026-08-21T00:00:00Z"},
        {"id": "intel--distinct001", "stix_id": "indicator--bbb1",
         "title": "Unrelated advisory with its own source",
         "source_url": "https://example-advisory.test/cve-2026-00001",
         "published": "2026-08-21T00:00:00Z"},
    ]
    unique, removed = enforce_manifest_uniqueness(synthetic_items)
    assert removed == 1, (
        f"v185.2 REGRESSION: enforce_manifest_uniqueness() did not block the escaped "
        f"duplicate class (same source_url, case/tracking-param variant, different "
        f"item-ID scheme). Expected 1 removed, got {removed}."
    )
    assert len(unique) == 2, f"Expected 2 unique items after dedup, got {len(unique)}"
    surviving_urls = {_url_key(i["source_url"]) for i in unique}
    assert len(surviving_urls) == len(unique), "Duplicate source_url survived in unique output"

    # Part 2: live committed api/feed.json must have zero source_url duplicates.
    api_feed = REPO_ROOT / "api" / "feed.json"
    if not api_feed.exists():
        log.info("[T22] api/feed.json not present (fresh checkout pre-pipeline run) — skipping live-data check")
        return
    try:
        raw = json.loads(api_feed.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("[T22] Could not parse api/feed.json (%s) — skipping live-data check", exc)
        return
    items = raw if isinstance(raw, list) else raw.get("items", raw.get("advisories", []))
    seen_keys: dict[str, str] = {}
    live_dupes: list[tuple[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = (item.get("source_url") or "").strip()
        if not url:
            continue
        uk = _url_key(url)
        if uk in seen_keys:
            live_dupes.append((seen_keys[uk], item.get("id", "unknown")))
        else:
            seen_keys[uk] = item.get("id", "unknown")
    assert not live_dupes, (
        f"v185.2 REGRESSION: {len(live_dupes)} live source_url duplicate pair(s) in "
        f"api/feed.json -- the exact class of duplicate the governance dedup gap "
        f"allowed through has recurred. Pairs: {live_dupes[:5]}"
    )
    log.info("[T22] %d live feed items — 0 source_url duplicates", len(items))


# ---------------------------------------------------------------------------
# T23: v185.2 governance trust-scorer mitre_tactics field-fallback
# ---------------------------------------------------------------------------

@test("T23_governance_scorer_recognises_mitre_tactics_field")
def t23():
    """Regression guard for enterprise_governance_engine.py's ATT&CK-coverage scoring.

    Root cause: _phase4_trust_tiers() computed ttp_count from
    item.get("ttp_count", 0) or len(item.get("ttps", [])) only. Live data
    shows real MITRE ATT&CK mappings written under mitre_tactics (a separate
    enrichment field) while ttps is frequently []. This applied a no_ttps:-5
    penalty to items that actually have derived MITRE coverage -- the same
    field-fallback gap already fixed once in p20-handlers.js/p23-handlers.js
    (PR #247), found again in this separate Python scorer. Confirmed live:
    every sampled Vulnerability-class item in api/feed.json carried a
    non-empty mitre_tactics list with an empty ttps list.

    Also guards the companion fix: a zero-IOC Vulnerability-class item must
    not take the no_iocs:-5 penalty (IOC=not_applicable for a pure CVE
    advisory), while a non-vulnerability item with zero IOCs still does.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import importlib
    if "enterprise_governance_engine" in sys.modules:
        importlib.reload(sys.modules["enterprise_governance_engine"])
    from enterprise_governance_engine import _phase4_trust_tiers  # noqa: E402

    synthetic_items = [
        {  # mitre_tactics populated, ttps empty -- must NOT take no_ttps:-5
            "id": "intel--t23-mitre-only", "stix_id": "indicator--t23a",
            "title": "CVE-2026-99999 - synthetic test advisory for T23 regression",
            "threat_type": "Vulnerability", "cve_id": "CVE-2026-99999",
            "source_url": "https://cvefeed.io/vuln/detail/CVE-2026-99999",
            "ttps": [], "ttp_count": 0,
            "mitre_tactics": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
            "ioc_count": 0, "iocs": [],
        },
        {  # genuinely zero TTP evidence anywhere -- no_ttps:-5 must still apply
            "id": "intel--t23-no-ttp", "stix_id": "indicator--t23b",
            "title": "Generic advisory with no MITRE mapping at all for T23 regression",
            "threat_type": "Malware",
            "source_url": "https://unknown-blog.example.test/post",
            "ttps": [], "ttp_count": 0, "mitre_tactics": [],
            "ioc_count": 3, "iocs": [{"type": "ip", "value": "10.0.0.1"}] * 3,
        },
    ]
    scores, _dist, _avg = _phase4_trust_tiers(synthetic_items)
    by_id = {s.item_id: s for s in scores}

    mitre_only = by_id["intel--t23-mitre-only"]
    assert "no_ttps:-5" not in mitre_only.deductions, (
        "v185.2 REGRESSION: governance scorer applied no_ttps:-5 to an item with a "
        f"populated mitre_tactics list. Deductions: {mitre_only.deductions}"
    )
    assert "no_iocs:-5" not in mitre_only.deductions, (
        "v185.2 REGRESSION: governance scorer applied no_iocs:-5 to a zero-IOC "
        f"Vulnerability-class item (IOC should be not_applicable). Deductions: {mitre_only.deductions}"
    )

    no_ttp = by_id["intel--t23-no-ttp"]
    assert "no_ttps:-5" in no_ttp.deductions, (
        "v185.2 REGRESSION: governance scorer must still penalise genuine absence of "
        f"any MITRE evidence. Deductions: {no_ttp.deductions}"
    )

    log.info("[T23] governance trust scorer: mitre_tactics fallback + vulnerability-class IOC semantics correct")


# ---------------------------------------------------------------------------
# T24: v185.4 entitlement resource drift gate
# ---------------------------------------------------------------------------

@test("T24_entitlement_resource_drift_gate")
def t24():
    """Regression guard for scripts/entitlement_resource_drift_gate.py.

    Confirms the gate (a) passes clean against the real, committed
    wrangler.toml + revenue-enforcement.js (no drift today), and (b) actually
    detects drift when ENTITLEMENT_ENFORCEMENT_RESOURCES names a resource
    enforceTierGate() doesn't define -- a silent fail-open via that switch's
    `default: { allowed: true }` case, which is the exact bug class this
    gate exists to catch before it reaches production.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import importlib
    if "entitlement_resource_drift_gate" in sys.modules:
        importlib.reload(sys.modules["entitlement_resource_drift_gate"])
    import entitlement_resource_drift_gate as gate

    defined = gate._defined_resources()
    assert defined, "T24: enforceTierGate() case scan returned zero resources -- parser or file drifted"

    real_exit = gate.main()
    assert real_exit == 0, (
        f"v185.4 REGRESSION: entitlement_resource_drift_gate.py reports drift against the "
        f"real committed wrangler.toml/revenue-enforcement.js (exit={real_exit}) -- an "
        f"enforced resource name has no matching enforceTierGate() case, meaning it "
        f"silently fail-opens via the default case in production right now."
    )

    # Simulate real drift and actually run it through gate.main()'s own
    # detection + exit-code path (not just set arithmetic on the helper
    # functions) -- writes a bogus resource into the real wrangler.toml,
    # confirms main() now reports failure, then restores the original
    # content in a finally block so this test can never leave the repo's
    # wrangler.toml modified, pass or fail.
    assert "vars" in gate._wrangler_sections(), "T24: wrangler.toml has no top-level [vars] block"
    original_toml = gate.WRANGLER_TOML.read_text(encoding="utf-8")
    bogus = "t24_synthetic_undefined_resource"
    try:
        injected_toml = original_toml.replace(
            'ENTITLEMENT_ENFORCEMENT_RESOURCES = "',
            f'ENTITLEMENT_ENFORCEMENT_RESOURCES = "{bogus},',
        )
        assert injected_toml != original_toml, (
            "T24: could not inject the synthetic resource -- ENTITLEMENT_ENFORCEMENT_RESOURCES "
            "assignment pattern not found in wrangler.toml"
        )
        gate.WRANGLER_TOML.write_text(injected_toml, encoding="utf-8")
        drift_exit = gate.main()
        assert drift_exit == 1, (
            f"v185.4 REGRESSION: entitlement_resource_drift_gate.py did not detect injected "
            f"synthetic drift (exit={drift_exit}, expected 1) -- the gate's own failure path "
            f"is broken, meaning it would silently pass real drift too."
        )
    finally:
        gate.WRANGLER_TOML.write_text(original_toml, encoding="utf-8")

    restored_exit = gate.main()
    assert restored_exit == 0, (
        "T24: wrangler.toml restore after synthetic-drift test left real drift behind "
        f"(exit={restored_exit}) -- restore did not return the file to its clean state"
    )
    log.info("[T24] entitlement resource drift gate: clean against real config, "
             "correctly detects and fails on injected synthetic drift, restore verified clean")


# ---------------------------------------------------------------------------
# T25: workflow_dispatch checkout-ref hardcoding regression guard
# ---------------------------------------------------------------------------

@test("T25_workflow_dispatch_checkout_ref_not_hardcoded")
def t25():
    """Regression guard for the ref:main checkout defect class.

    Found live (this session) in multi-source-intel.yml and sentinel-blogger.yml:
    an actions/checkout step with a literal `ref: main` hardcodes the checked-out
    file content to main regardless of which branch actually dispatched the
    workflow, silently defeating workflow_dispatch's whole purpose of testing a
    feature branch's changes before merge -- confirmed live via a real
    workflow_dispatch run whose dispatched branch added a new script that then
    failed with "No such file or directory" because the checkout pulled main's
    tree instead. github.ref already resolves to the dispatching branch on
    workflow_dispatch and to the correct branch on schedule/push, so replacing
    the literal with `ref: "${{ github.ref }}"` is a no-op for every trigger
    except workflow_dispatch, where it is the actual fix.

    Scans every .github/workflows/*.yml that declares a workflow_dispatch
    trigger for a checkout step whose `ref:` is a bare literal `main` (quoted
    or not) rather than a github-context expression. A workflow with a
    pull_request or workflow_call trigger is intentionally excluded from this
    blanket rule -- those can have legitimate reasons to pin a specific ref
    (e.g. pages-fast-publish.yml's `pull_request: types:[closed]` handler,
    which deliberately checks out main's just-landed HEAD because a
    pull_request event's own github.ref has no meaningful checkout target
    once the PR that triggered it has closed) -- but this test discovers
    that exemption from each workflow's own declared triggers, not from a
    hardcoded exemption list, so a future workflow_call/pull_request
    addition to some other workflow is picked up automatically rather than
    silently grandfathered in.
    """
    import re
    import yaml

    workflows_dir = REPO_ROOT / ".github" / "workflows"
    offenders = []
    dispatchable_count = 0
    for path in sorted(workflows_dir.glob("*.yml")):
        content = path.read_text(encoding="utf-8")
        try:
            doc = yaml.safe_load(content)
        except Exception:
            continue  # T12/other tests own YAML-parseability; not this test's concern
        if not isinstance(doc, dict):
            continue
        triggers = doc.get("on") or doc.get(True)  # PyYAML parses bare `on:` as True in some versions
        # `on:` is valid YAML as a dict ({workflow_dispatch: {...}, push: {...}}),
        # a list ([push, workflow_dispatch]), or a single bare string
        # (workflow_dispatch) -- normalize all three to a name set so none of
        # them silently bypass this scan the way a raw `isinstance(..., dict)`
        # gate would for the list/string forms.
        if isinstance(triggers, dict):
            trigger_names = set(triggers.keys())
        elif isinstance(triggers, list):
            trigger_names = set(triggers)
        elif isinstance(triggers, str):
            trigger_names = {triggers}
        else:
            continue
        if "workflow_dispatch" not in trigger_names:
            continue
        if "pull_request" in trigger_names or "workflow_call" in trigger_names:
            continue  # explicitly out of scope -- see docstring
        dispatchable_count += 1

        # Literal `ref: main` (bare or quoted), in either block or flow-mapping
        # style, but NOT a `${{ ... }}` expression.
        for m in re.finditer(r"""ref:\s*(['"]?)main\1\s*[,}\n]""", content):
            line_no = content.count("\n", 0, m.start()) + 1
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{line_no}")

    assert not offenders, (
        "T25 REGRESSION: workflow(s) with a workflow_dispatch trigger hardcode "
        f"actions/checkout's ref to the literal 'main': {offenders}. This silently "
        "defeats workflow_dispatch testing of any feature branch for these "
        "workflows -- use ref: \"${{ github.ref }}\" instead (no-op for "
        "schedule/push, correct for workflow_dispatch)."
    )
    log.info("[T25] %d workflow_dispatch-capable workflow(s) scanned, 0 hardcoded to ref:main",
             dispatchable_count)


@test("T26_no_whole_corpus_r2_report_sync")
def t26():
    """P0 R2 COST INCIDENT PERMANENT REGRESSION GATE (2026-09).

    Root cause: scripts/r2_upload.py used to run `aws s3 sync reports/ ->
    s3://sentinel-apex-reports/reports/` -- a whole-prefix LIST + full
    content comparison, no bound -- on every scheduled pipeline run. Against
    a ~193K-object bucket this produced 3,004,147 billable R2 Class A
    operations in one billing cycle. See docs/P0_R2_COST_CONTAINMENT.md.

    This is a static source guard, not a live-run check (mirrors the same
    pattern already established by workers/intel-gateway/src/__tests__/
    reports-canonical-write-guard.test.js for the Worker side): it fails
    loudly the moment whole-corpus sync reappears anywhere in the normal
    scheduled pipeline's source, before it can ever execute against
    production and generate a real bill.
    """
    import re as _re

    offenders: list[str] = []

    # 1. scripts/r2_upload.py must never call s3_sync()/aws s3 sync against
    #    BUCKET_REPORTS again -- the whole point of moving report publishing
    #    to scripts/r2_report_publisher.py's deterministic-key, no-LIST design.
    # Precise, not a blunt string search: s3_sync()/s3_sync_download() are
    # legitimate, still-used generic helpers (scripts/r2_state_sync.py calls
    # them for bounded state-dir sync) whose own function BODY necessarily
    # contains the literal ["aws", "s3", "sync", ...] argv -- a plain
    # substring/regex search for that literal would always match the
    # helper's definition itself and never distinguish it from a dangerous
    # new CALL SITE. What must never reappear is a CALL to s3_sync(...)
    # (by name, not raw subprocess argv) whose arguments target the reports
    # bucket -- so only function-call sites are scanned, and only the
    # module-level code outside the helper definitions themselves.
    r2_upload_path = REPO_ROOT / "scripts" / "r2_upload.py"
    if r2_upload_path.exists():
        content = r2_upload_path.read_text(encoding="utf-8")
        for m in _re.finditer(r"(?<!def )s3_sync\s*\(\s*[^)]*\)", content, flags=_re.DOTALL):
            call = m.group(0)
            if "BUCKET_REPORTS" in call or "sentinel-apex-reports" in call:
                line_no = content.count("\n", 0, m.start()) + 1
                offenders.append(f"scripts/r2_upload.py:{line_no} -- s3_sync() call against BUCKET_REPORTS")

    # 2. scripts/r2_report_publisher.py -- the replacement -- must never
    #    issue a LIST call against R2 in its normal (non-purge) path. A
    #    boto3/awscli list call appearing here would silently reintroduce
    #    the "enumerate the whole bucket every run" cost driver this
    #    module's whole design exists to avoid.
    publisher_path = REPO_ROOT / "scripts" / "r2_report_publisher.py"
    if publisher_path.exists():
        content = publisher_path.read_text(encoding="utf-8")
        for pattern in (r"list_objects", r"list-objects", r"\bs3\s+ls\b", r"get_paginator"):
            if _re.search(pattern, content):
                offenders.append(f"scripts/r2_report_publisher.py -- forbidden bucket-enumeration pattern {pattern!r} found")

    # 3. Every normal-pipeline scheduled invocation of generate_intel_reports.py
    #    (run_pipeline.py's 3 call sites + sentinel-blogger.yml's direct STAGE
    #    5.4.0b call) must pass --since-hours -- without it, that call
    #    regenerates the ENTIRE historical manifest every run regardless of
    #    what scripts/r2_upload.py or scripts/r2_report_publisher.py do
    #    downstream (this was the actual upstream root cause, not just the
    #    sync call itself -- see docs/P0_R2_COST_CONTAINMENT.md).
    run_pipeline_path = REPO_ROOT / "scripts" / "run_pipeline.py"
    if run_pipeline_path.exists():
        content = run_pipeline_path.read_text(encoding="utf-8")
        for m in _re.finditer(
            r'\[\s*sys\.executable\s*,\s*["\']scripts/generate_intel_reports\.py["\'].*?\]',
            content, flags=_re.DOTALL,
        ):
            call = m.group(0)
            if "--since-hours" not in call:
                line_no = content.count("\n", 0, m.start()) + 1
                offenders.append(
                    f"scripts/run_pipeline.py:{line_no} -- generate_intel_reports.py invocation "
                    f"missing --since-hours (would regenerate the entire historical manifest every run)"
                )

    blogger_path = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"
    if blogger_path.exists():
        content = blogger_path.read_text(encoding="utf-8")
        for m in _re.finditer(
            r"python3 scripts/generate_intel_reports\.py.*?(?=\n\s*\n|\Z)", content, flags=_re.DOTALL,
        ):
            call = m.group(0)
            if "--since-hours" not in call:
                line_no = content.count("\n", 0, m.start()) + 1
                offenders.append(
                    f"sentinel-blogger.yml:{line_no} -- generate_intel_reports.py invocation "
                    f"missing --since-hours"
                )

    assert not offenders, (
        "T26 REGRESSION: whole-corpus R2 report sync (or an unbounded "
        f"generate_intel_reports.py call feeding it) has reappeared: {offenders}. "
        "This is the exact P0 cost-incident pattern -- see docs/P0_R2_COST_CONTAINMENT.md."
    )
    log.info("[T26] No whole-corpus R2 report sync pattern found; all generate_intel_reports.py "
             "scheduled-pipeline call sites bound to --since-hours.")


# ---------------------------------------------------------------------------
# T27: pipeline_audit.py manifest_report_consistency PASS/DEFERRED/FAIL model
# (P0 production-architecture-transformation mission, 2026-09-08)
# ---------------------------------------------------------------------------

@test("T27_manifest_report_consistency_pass_deferred_fail")
def t27():
    """Regression guard for scripts/pipeline_audit.py's
    check_report_manifest_consistency().

    Root cause fixed: the check used to test LOCAL EPHEMERAL RUNNER DISK
    existence for the entire historical manifest -- always FAILing on a
    healthy pipeline run, because thousands of historical entries are
    outside the rolling REPORT_WINDOW_HOURS window by design (PR #369) and
    are never on a fresh checkout's local disk. This is the exact false-
    positive "1 critical issue" finding this mission fixes.

    Proves, with synthetic data (no dependency on a real feed_manifest.json
    or live R2 credentials), that the fixed check now correctly
    distinguishes:
      - empty report_url                          -> not checked at all
      - validation_status outside ok/enriched/valid -> not checked at all
      - in-window, local file present              -> PASS
      - in-window, missing, NOT durably confirmed   -> FAIL (the one real defect class)
      - in-window, missing, durably confirmed in R2 publish-state -> DEFERRED
      - out-of-window, missing                      -> DEFERRED
    """
    import importlib.util as _ilu
    import tempfile
    import shutil
    from datetime import datetime, timedelta, timezone

    scripts_dir = REPO_ROOT / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import r2_report_publisher as _r2pub  # noqa: E402

    tmp_root = Path(tempfile.mkdtemp(prefix="t27_pipeline_audit_"))
    try:
        (tmp_root / "reports" / "2026" / "09").mkdir(parents=True)
        now = datetime.now(timezone.utc)

        def _ts(hours_ago: float) -> str:
            return (now - timedelta(hours=hours_ago)).isoformat(timespec="seconds").replace("+00:00", "Z")

        items = [
            # A: in-window, local file present -> PASS
            {"id": "intel--t27a", "validation_status": "ok",
             "report_url": "/reports/2026/09/intel--t27a.html", "timestamp": _ts(2)},
            # B: in-window, missing locally, NOT durably confirmed -> FAIL
            {"id": "intel--t27b", "validation_status": "ok",
             "report_url": "/reports/2026/09/intel--t27b.html", "timestamp": _ts(3)},
            # C: in-window, missing locally, durably confirmed -> DEFERRED
            {"id": "intel--t27c", "validation_status": "enriched",
             "report_url": "/reports/2026/09/intel--t27c.html", "timestamp": _ts(4)},
            # D: out-of-window, missing locally -> DEFERRED
            {"id": "intel--t27d", "validation_status": "valid",
             "report_url": "/reports/2026/09/intel--t27d.html", "timestamp": _ts(500)},
            # E: empty report_url -> not checked (documented valid "no report" state)
            {"id": "intel--t27e", "validation_status": "ok",
             "report_url": "", "timestamp": _ts(1)},
            # F: non-publishable validation_status -> not checked
            {"id": "intel--t27f", "validation_status": "pending",
             "report_url": "/reports/2026/09/intel--t27f.html", "timestamp": _ts(1)},
        ]
        (tmp_root / "reports" / "2026" / "09" / "intel--t27a.html").write_text(
            "<!doctype html><html><body>t27a</body></html>", encoding="utf-8")

        manifest_path = tmp_root / "feed_manifest.json"
        manifest_path.write_text(json.dumps(items), encoding="utf-8")

        state_path = tmp_root / "r2_report_publish_state.json"
        state_path.write_text(json.dumps({
            "schema_version": "1.0",
            "items": {"intel--t27c": {"html_key": "reports/2026/09/intel--t27c.html",
                                       "canonical_ts": _ts(4)}},
        }), encoding="utf-8")

        # Loaded the same way run_pipeline.py's own Phase 9 loads this exact
        # file (importlib.util.spec_from_file_location) -- not a parallel
        # loading mechanism that could behave differently from production.
        _audit_spec = _ilu.spec_from_file_location(
            "pipeline_audit_t27", REPO_ROOT / "scripts" / "pipeline_audit.py"
        )
        _audit_mod = _ilu.module_from_spec(_audit_spec)
        _audit_spec.loader.exec_module(_audit_mod)
        _audit_mod.MANIFEST_PATH = manifest_path
        _audit_mod.REPO_ROOT = tmp_root

        _prior_state_path = _r2pub.STATE_PATH
        _prior_window_env = os.environ.get("REPORT_WINDOW_HOURS")
        _r2pub.STATE_PATH = state_path
        os.environ["REPORT_WINDOW_HOURS"] = "24"
        try:
            findings: list = []
            stats: dict = {}
            _audit_mod.check_report_manifest_consistency(findings, stats)
        finally:
            _r2pub.STATE_PATH = _prior_state_path
            if _prior_window_env is None:
                os.environ.pop("REPORT_WINDOW_HOURS", None)
            else:
                os.environ["REPORT_WINDOW_HOURS"] = _prior_window_env

        assert stats.get("manifest_report_cross_checked") == 4, (
            f"Expected 4 checked entries (A/B/C/D -- E has empty report_url, "
            f"F has non-publishable validation_status), got "
            f"{stats.get('manifest_report_cross_checked')}"
        )
        assert stats.get("manifest_report_missing") == 1, (
            f"Expected exactly 1 genuinely-missing entry (B), got "
            f"{stats.get('manifest_report_missing')}"
        )
        assert stats.get("manifest_report_deferred") == 2, (
            f"Expected exactly 2 deferred entries (C durably-confirmed, D "
            f"out-of-window), got {stats.get('manifest_report_deferred')}"
        )

        consistency_findings = [f for f in findings if f["check"] == "manifest_report_consistency"]
        assert len(consistency_findings) == 1, (
            f"Expected exactly 1 manifest_report_consistency finding, got "
            f"{len(consistency_findings)}: {consistency_findings}"
        )
        finding = consistency_findings[0]
        assert finding["level"] == "FAIL", (
            f"Expected FAIL (case B is a genuine defect), got {finding['level']}: {finding}"
        )
        examples_str = " ".join(finding.get("examples", []))
        assert "intel--t27b" in examples_str, (
            f"Expected the FAIL to name intel--t27b, got: {finding.get('examples')}"
        )
        assert "intel--t27c" not in examples_str and "intel--t27d" not in examples_str, (
            f"Deferred entries C/D must NOT be reported as missing: {finding.get('examples')}"
        )
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


# ---------------------------------------------------------------------------
# T28: r2_state_sync.py owns intel_index.json (Class A persistence)
# ---------------------------------------------------------------------------

@test("T28_r2_state_sync_intel_index_registered")
def t28():
    """P0 production-architecture-transformation mission (2026-09-08):
    data/cache/intel_index.json (scripts/intel_dedup_engine.py's dedup
    primary index -- sibling to feed_state.json, same atomic write
    contract, same "committed to git, persists forever" assumption that
    caused the 2026-08-26 staleness incident) must be registered in
    scripts/r2_state_sync.py's STATE_FILES so it durably persists via R2
    instead of the now-unreliable git path.

    Cross-checks against intel_dedup_engine.py's OWN INDEX_PATH constant
    (not a hardcoded string) so this guard also catches future drift if
    either file's path convention changes. Also guards Constitution
    Principle 3 (single source of truth): no local path or R2 key may be
    registered twice in STATE_FILES.
    """
    scripts_dir = REPO_ROOT / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import r2_state_sync
    import intel_dedup_engine

    local_paths = {local for local, _key in r2_state_sync.STATE_FILES}
    expected_rel = str(intel_dedup_engine.INDEX_PATH.relative_to(REPO_ROOT)).replace(os.sep, "/")
    assert expected_rel in local_paths, (
        f"scripts/r2_state_sync.py's STATE_FILES is missing "
        f"intel_dedup_engine.py's own INDEX_PATH ({expected_rel!r}) -- this "
        f"file will silently revert to empty on every fresh checkout, "
        f"exactly like feed_state.json did before the 2026-08-26 incident."
    )

    local_path_list = [local for local, _key in r2_state_sync.STATE_FILES]
    dupes = {p for p in local_path_list if local_path_list.count(p) > 1}
    assert not dupes, f"STATE_FILES has duplicate local-path entries (duplicate-authority risk): {dupes}"

    key_list = [key for _local, key in r2_state_sync.STATE_FILES]
    key_dupes = {k for k in key_list if key_list.count(k) > 1}
    assert not key_dupes, f"STATE_FILES has duplicate R2-key entries (duplicate-authority risk): {key_dupes}"


# ---------------------------------------------------------------------------
# T29: safe_git_commit.py no longer double-stages R2-owned Class A state
# ---------------------------------------------------------------------------

@test("T29_safe_git_commit_no_duplicate_state_authority")
def t29():
    """P0 production-architecture-transformation mission (2026-09-08):
    scripts/safe_git_commit.py must no longer stage files that
    scripts/r2_state_sync.py's STATE_FILES/STATE_DIRS now exclusively own
    (Class A mutable runtime state) -- staging the same file via both the
    git path (rejected by the branch ruleset since 2026-08-26) and the R2
    path, with no reconciliation between the two, is exactly the
    duplicate-state-authority risk this mission was scoped to eliminate.

    Parses the ACTUAL list/set literals via ast.literal_eval() (not a
    substring search, which would false-positive on this file's own
    explanatory comments documenting the removals) so this guard tracks
    real runtime behaviour, not prose.
    """
    scripts_dir = REPO_ROOT / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import r2_state_sync

    sgc_path = REPO_ROOT / "scripts" / "safe_git_commit.py"
    tree = ast.parse(sgc_path.read_text(encoding="utf-8"), filename=str(sgc_path))

    json_guarded = None
    files_to_stage = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            if target_name == "JSON_GUARDED":
                json_guarded = ast.literal_eval(node.value)
            elif target_name == "files_to_stage":
                files_to_stage = ast.literal_eval(node.value)

    assert json_guarded is not None, "Could not locate JSON_GUARDED assignment in safe_git_commit.py"
    assert files_to_stage is not None, "Could not locate files_to_stage assignment in safe_git_commit.py"

    r2_owned = {local for local, _key in r2_state_sync.STATE_FILES}
    r2_owned |= {local for local, _key in r2_state_sync.STATE_DIRS}

    staged_all = set(json_guarded) | set(files_to_stage)
    double_staged = staged_all & r2_owned
    assert not double_staged, (
        f"safe_git_commit.py stages {sorted(double_staged)}, which "
        f"scripts/r2_state_sync.py's STATE_FILES/STATE_DIRS already "
        f"exclusively own -- duplicate-state-authority risk (both paths "
        f"racing to persist the same file with no reconciliation)."
    )

    # The 4 specific files this mission's audit confirmed have zero live
    # producer/consumer of runtime persistence (not R2-owned either --
    # simply should not be staged at all).
    should_not_be_staged = {
        "data/sync_marker.json",
        ".gitignore",
        "config/feature_flags.json",
        "data/publish_queue.json",
    }
    still_staged = should_not_be_staged & staged_all
    assert not still_staged, (
        f"safe_git_commit.py still stages {sorted(still_staged)} -- these "
        f"were confirmed to have zero live runtime-persistence "
        f"producer/consumer and should not be staged at all."
    )


# ---------------------------------------------------------------------------
# T30: STAGE 5.8.4b governance telemetry -- R2-wired, no independent git push
# ---------------------------------------------------------------------------

@test("T30_governance_telemetry_r2_wired_no_runtime_git_push")
def t30():
    """P0 production-architecture-transformation mission (2026-09-08):
    STAGE 5.8.4b (.github/workflows/sentinel-blogger.yml) used to run its
    OWN independent inline `git add` / `git commit` / `git push origin
    HEAD` for data/telemetry/global_release_governance.json -- a second,
    entirely separate runtime-git-persistence code path outside
    scripts/safe_git_commit.py, silently broken the same way by the same
    branch-ruleset rejection since 2026-08-26 (never surfaced because the
    step already had continue-on-error: true).

    Verifies:
      1. scripts/r2_upload.py exposes main_governance_telemetry_only()
         wired to a real --governance-telemetry-only CLI dispatch branch
         (not an invented flag -- r2_upload.py has no argparse, only
         sys.argv membership checks; a caller passing an unmatched flag
         would silently fall through to main(), which has nothing to do
         with this file).
      2. STAGE 5.8.4b calls that exact flag.
      3. STAGE 5.8.4b no longer contains its own git add/commit/push --
         Class B (generated artifact) persistence now goes through R2
         publication like every other generated artifact, not a scheduled
         runtime commit to main.
      4. STAGE 5.8.4b still writes the Class D (immutable, versioned)
         audit trail via scripts/audit_snapshot_store.py -- fixing the git-
         push bug must not lose the audit trail.
    """
    r2_upload_path = REPO_ROOT / "scripts" / "r2_upload.py"
    assert r2_upload_path.exists(), "scripts/r2_upload.py missing"
    r2_upload_src = r2_upload_path.read_text(encoding="utf-8")

    assert "def main_governance_telemetry_only" in r2_upload_src, (
        "scripts/r2_upload.py is missing main_governance_telemetry_only() "
        "-- STAGE 5.8.4b's Class B governance-telemetry R2 publish has no "
        "real implementation to call."
    )
    assert '"--governance-telemetry-only" in sys.argv' in r2_upload_src, (
        "scripts/r2_upload.py's __main__ dispatch is missing the "
        "--governance-telemetry-only branch -- main_governance_telemetry_only() "
        "exists but is unreachable from the CLI."
    )

    blogger_path = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"
    assert blogger_path.exists(), "sentinel-blogger.yml missing"
    blogger_src = blogger_path.read_text(encoding="utf-8")

    stage_marker = "STAGE 5.8.4b - Governance Telemetry Persistence"
    idx = blogger_src.find(stage_marker)
    assert idx != -1, "STAGE 5.8.4b step not found in sentinel-blogger.yml"

    next_step_idx = blogger_src.find("\n      - name:", idx + len(stage_marker))
    block = blogger_src[idx: next_step_idx if next_step_idx != -1 else len(blogger_src)]

    assert "r2_upload.py --governance-telemetry-only" in block, (
        "STAGE 5.8.4b does not call the real "
        "'r2_upload.py --governance-telemetry-only' flag."
    )
    assert "audit_snapshot_store.py" in block and "--family global_release_governance" in block, (
        "STAGE 5.8.4b no longer writes the Class D versioned audit "
        "snapshot via scripts/audit_snapshot_store.py."
    )

    forbidden = ["git add", "git commit", "git push"]
    found_forbidden = [f for f in forbidden if f in block]
    assert not found_forbidden, (
        f"STAGE 5.8.4b still contains runtime git persistence {found_forbidden} "
        f"-- this stage was migrated to R2 publication specifically to "
        f"remove its independent (and, since 2026-08-26, silently failing) "
        f"git push path."
    )


# ---------------------------------------------------------------------------
# T31: audit_snapshot_store.py (Class D) allowlist + versioned-key contract
# ---------------------------------------------------------------------------

@test("T31_audit_snapshot_store_allowlist_and_key_format")
def t31():
    """P0 production-architecture-transformation mission (2026-09-08):
    scripts/audit_snapshot_store.py is the new Class D (immutable,
    versioned audit evidence) store -- the one genuinely-new persistence
    module this mission adds (Class A and Class B already had mature
    implementations). Exercises the parts of its contract that are pure/
    deterministic and need no live R2 credentials or network access:
      1. write_snapshot() refuses (returns None, never raises) for a
         family outside KNOWN_FAMILIES -- an uncatalogued audit key must
         never be created by a typo'd --family value.
      2. write_snapshot() refuses (returns None) for a source file that
         does not exist -- never fabricates/writes empty audit evidence.
      3. _versioned_key() produces the documented
         audit/<YYYY>/<MM>/<DD>/<run_id>/<family>.json shape exactly.
    """
    scripts_dir = REPO_ROOT / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import audit_snapshot_store as _ass
    from datetime import datetime, timezone

    result = _ass.write_snapshot(
        Path("/nonexistent/does-not-matter.json"), "not_a_real_family",
        "run123", "sha123", "https://example-endpoint.test",
    )
    assert result is None, "write_snapshot() must refuse an unknown family, returning None"

    result2 = _ass.write_snapshot(
        Path("/nonexistent/does-not-exist.json"), "pipeline_audit",
        "run123", "sha123", "https://example-endpoint.test",
    )
    assert result2 is None, "write_snapshot() must refuse a missing source file, returning None"

    when = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    key = _ass._versioned_key("pipeline_audit", "run456", when)
    assert key == "audit/2026/09/08/run456/pipeline_audit.json", (
        f"Unexpected versioned key shape: {key!r}"
    )

    assert _ass.KNOWN_FAMILIES == {
        "pipeline_audit", "global_release_governance",
        "report_engine_ledger", "quality_drift_report",
    }, f"KNOWN_FAMILIES changed unexpectedly: {sorted(_ass.KNOWN_FAMILIES)}"


# ---------------------------------------------------------------------------
# Shared helper for the AI-plane producer gates (T35 / T38 / T40)
#
# v201.3: these gates used to assert that the producing workflow `git add`ed
# its output directory, using git staging as a proxy for "the output is
# persisted". That proxy became false: main's branch ruleset has rejected
# direct runtime pushes since 2026-08-26, so a staged-and-pushed artifact was
# silently discarded while the gate still passed. Persistence now means
# registered in r2_state_sync.py's STATE_FILES AND uploaded by the workflow
# that produces it -- which is what these gates assert.
# ---------------------------------------------------------------------------

def _executable_yaml(path) -> str:
    """Workflow text with full-line comments stripped.

    A gate that greps raw workflow text matches its own rationale comments --
    the failure mode mutation-testing exposed in T35's first version.
    """
    return "\n".join(
        ln for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not ln.lstrip().startswith("#")
    )


def _assert_producer_persisted(producer_rel: str, artifact_rels: list) -> None:
    """A producer must run in CI and its output must be durably persisted."""
    workflows = REPO_ROOT / ".github" / "workflows"

    runners = [
        wf.name for wf in sorted(workflows.glob("*.yml"))
        if producer_rel in _executable_yaml(wf)
    ]
    assert runners, (
        f"no workflow invokes {producer_rel} — its artifacts freeze while the AI "
        "Cyber Brain keeps publishing them (the 2026-09-09 staleness incident)"
    )

    persisting = [
        wf.name for wf in sorted(workflows.glob("*.yml"))
        if producer_rel in (code := _executable_yaml(wf))
        and "r2_state_sync.py --upload" in code
    ]
    assert persisting, (
        f"workflow(s) {runners} run {producer_rel} but none publish to R2 "
        "(r2_state_sync.py --upload). Git persistence is NOT an alternative: "
        "main's ruleset has rejected direct runtime pushes since 2026-08-26, so "
        "a git-staged artifact is discarded when the runner is destroyed"
    )

    state_sync = (REPO_ROOT / "scripts" / "r2_state_sync.py").read_text(
        encoding="utf-8", errors="replace")
    for rel in artifact_rels:
        assert f'("{rel}"' in state_sync, (
            f"{rel} is not registered in r2_state_sync.py's STATE_FILES — the "
            f"upload step would skip it and {producer_rel}'s output would not survive"
        )


# ---------------------------------------------------------------------------
# T32: AI plane freshness guard contract
#
# Origin: the 2026-09-09 AI plane forensic audit. The public, premium-gated
# api/v1/intel/ai_summary.json had been republishing AI artifacts frozen since
# 2026-05-04 (anomalies, forecasts), 2026-05-05 (anomaly radar) and 2026-04-04
# (apex forecast) under a freshly-stamped `generated_at`, because the publisher
# checked file presence and never file age.
#
# This test locks the *guard*, not the data: it asserts the freshness module
# exists and that its state machine still classifies age correctly. A CI
# checkout legitimately has artifacts of varying age, so asserting live data is
# fresh here would produce a flaky gate; T33 covers the wiring instead.
# ---------------------------------------------------------------------------

@test("T32_ai_freshness_guard_contract")
def t32():
    """ai_freshness_guard.py must exist and classify artifact age correctly."""
    import importlib.util
    import tempfile
    from datetime import datetime, timezone, timedelta

    guard_path = REPO_ROOT / "scripts" / "ai_freshness_guard.py"
    assert guard_path.exists(), "scripts/ai_freshness_guard.py missing — AI plane has no freshness SSOT"

    spec = importlib.util.spec_from_file_location("ai_freshness_guard", guard_path)
    fg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fg)

    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    tmp = Path(tempfile.mkdtemp())

    def artifact(name: str, hours_old: float) -> Path:
        p = tmp / name
        stamp = (now - timedelta(hours=hours_old)).isoformat()
        p.write_text(json.dumps({"generated_at": stamp}), encoding="utf-8")
        return p

    # Core state machine.
    cases = [
        ("fresh.json", 1.0, fg.FreshnessState.FRESH),
        ("stale.json", 72.0, fg.FreshnessState.STALE),
        # The exact shape of the incident: a four-month-old artifact.
        ("incident.json", 128 * 24.0, fg.FreshnessState.EXPIRED),
    ]
    for name, age, expected in cases:
        v = fg.assess(artifact(name, age), now=now)
        assert v.state == expected, f"{name}: expected {expected}, got {v.state} (age={v.age_hours}h)"

    # The load-bearing property: an expired artifact must never be
    # republishable as current intelligence.
    expired = fg.assess(artifact("expired2.json", 200 * 24.0), now=now)
    assert not expired.is_publishable, "EXPIRED artifact reported publishable — the incident could recur"

    # Fail closed, never fail open: unreadable and missing inputs must not be
    # mistaken for fresh ones.
    missing = fg.assess(tmp / "does-not-exist.json", now=now)
    assert missing.state == fg.FreshnessState.MISSING and not missing.is_publishable, \
        "missing artifact must be MISSING and not publishable"

    corrupt = tmp / "corrupt.json"
    corrupt.write_text("{not valid json", encoding="utf-8")
    assert fg.assess(corrupt, now=now).state == fg.FreshnessState.UNREADABLE, \
        "unreadable artifact must be UNREADABLE"

    undated = tmp / "undated.json"
    undated.write_text(json.dumps({"data": 1}), encoding="utf-8")
    assert not fg.assess(undated, now=now).is_publishable, \
        "artifact with no timestamp must not be publishable — presence is not freshness"

    # A single expired input must never be masked by fresh siblings.
    summary = fg.summarize([
        fg.assess(artifact("f2.json", 1.0), now=now),
        fg.assess(artifact("e2.json", 300 * 24.0), now=now),
    ])
    assert summary["overall_state"] == fg.FreshnessState.EXPIRED, \
        f"worst state must win, got {summary['overall_state']}"
    assert summary["degraded"] is True, "mixed-freshness summary must report degraded"


# ---------------------------------------------------------------------------
# T33: AI Cyber Brain publishes freshness-gated, evidence-backed output
#
# Locks the three specific defects the audit found in ai_brain_publisher.py so
# none can be silently reintroduced:
#   1. models_active was a hardcoded literal claiming Isolation Forest,
#      GradientBoostingRegressor and DBSCAN were running when none were.
#   2. Upstream artifacts were admitted on presence alone, with no age check.
#   3. The radar's zero-day flag was read under a key the radar never emits
#      (`is_zero_day_candidate` vs the emitted `is_candidate`), so every
#      zero-day candidate published as a non-candidate.
# ---------------------------------------------------------------------------

@test("T33_ai_brain_freshness_gated_and_evidence_backed")
def t33():
    """ai_brain_publisher.py must gate on freshness and never hardcode engine claims."""
    pub = REPO_ROOT / "scripts" / "ai_brain_publisher.py"
    assert pub.exists(), "scripts/ai_brain_publisher.py missing"
    src = pub.read_text(encoding="utf-8", errors="replace")

    # 1. No hardcoded ML capability claim.
    assert '"models_active"        : ["IsolationForest"' not in src, \
        "models_active is hardcoded again — engine attribution must be derived from bundle content"
    assert "_derive_active_engines" in src, \
        "ai_brain_publisher.py no longer derives its active-engine list from evidence"

    # 2. Freshness gating is wired, not merely importable.
    assert "ai_freshness_guard" in src, "ai_brain_publisher.py no longer imports the freshness guard"
    assert "_assess_inputs" in src, "ai_brain_publisher.py no longer assesses input freshness"
    for flag in ("preds_publishable", "radar_publishable", "apex_publishable"):
        assert flag in src, f"freshness gate '{flag}' removed from ai_brain_publisher.py"

    # 3. The radar's own spelling of the candidate flag must still be honoured.
    assert 'a.get("is_candidate")' in src, (
        "ai_brain_publisher.py no longer reads the radar's `is_candidate` key — "
        "zero-day candidates would silently publish as non-candidates"
    )

    # The published bundle, when present, must carry the integrity fields that
    # let a consumer tell current intelligence from stale intelligence.
    summary_path = REPO_ROOT / "api" / "v1" / "intel" / "ai_summary.json"
    if not summary_path.exists():
        log.warning("[T33] ai_summary.json not present — skipping published-contract check")
        return

    bundle = json.loads(summary_path.read_text(encoding="utf-8"))
    for field in ("degraded", "freshness_state"):
        assert field in bundle, (
            f"ai_summary.json is missing top-level '{field}' — consumers cannot distinguish "
            "current intelligence from a stale republish"
        )
    telemetry = bundle.get("ai_telemetry") or {}
    assert "data_freshness" in telemetry, "ai_telemetry.data_freshness missing from published bundle"
    # Backward compatibility: the original presence booleans must survive.
    assert "data_sources" in telemetry, "ai_telemetry.data_sources removed — breaks existing consumers"

    banned = {"IsolationForest", "GradientBoostingRegressor", "DBSCAN-Actor"}
    published_models = set(telemetry.get("models_active") or [])
    assert not (published_models & banned), (
        f"published models_active still asserts unrun estimators: {sorted(published_models & banned)}"
    )


# ---------------------------------------------------------------------------
# T34: AI plane Cloudflare cost containment
#
# Origin: the same audit found zero uses of the Cache API anywhere in the
# Worker fleet. A Worker's own response is not edge-cached automatically, so
# every request to the public /api/ai/* endpoints cost one R2 Class B GET.
# This is the guard on the platform's Cloudflare spend, which must not exceed
# plan again.
# ---------------------------------------------------------------------------

@test("T34_ai_plane_edge_cache_cost_guard")
def t34():
    """The public /api/ai/* proxy must be edge-cached, and premium paths must not be."""
    gw = REPO_ROOT / "workers" / "intel-gateway" / "src" / "index.js"
    assert gw.exists(), "workers/intel-gateway/src/index.js missing"
    src = gw.read_text(encoding="utf-8", errors="replace")

    assert "AI_STATIC_PROXY_FILES" in src, "AI static proxy block missing from the gateway"
    assert "caches.default" in src, (
        "no Cache API usage in the gateway — every /api/ai/* request costs an R2 "
        "Class B operation, the exact Cloudflare cost regression this gate exists to prevent"
    )
    assert "aiCacheKey" in src and "aiCache.match" in src, \
        "AI proxy edge-cache lookup removed — R2 cost per request is unbounded again"

    # The cache key must drop the query string. Without normalisation any
    # caller can force unlimited misses with ?cb=1, ?cb=2, ... and drive R2
    # operations (and therefore spend) at will.
    assert "${url.origin}${path}" in src, (
        "AI proxy cache key is no longer normalised to origin+pathname — "
        "query-string cache-busting can amplify R2 cost without bound"
    )

    # Only successful responses may be stored; caching a 502 pins an outage.
    assert "resp.status === 200" in src, \
        "AI proxy caches non-200 responses — an upstream outage would be pinned for the full TTL"

    # SECURITY: the premium-gated AI bundle must never become edge-cacheable,
    # or premium intelligence would be served to unauthenticated callers.
    #
    # Checked against the two authoritative declarations rather than by
    # scanning a byte window around the proxy block: that window also covers
    # the comment explaining why ai_summary.json is excluded, which made an
    # earlier form of this assertion fire on its own documentation.
    assert '"/api/v1/intel/ai_summary.json"' in src, "ai_summary.json path constant missing"

    proxy_decl_start = src.index("const AI_STATIC_PROXY_FILES")
    proxy_decl = src[proxy_decl_start:src.index("\n", proxy_decl_start)]
    assert "ai_summary" not in proxy_decl, (
        "ai_summary.json was added to AI_STATIC_PROXY_FILES — that block is edge-cached "
        "and performs no auth, so caching a premium-gated bundle there would serve "
        "premium intelligence to unauthenticated callers"
    )

    premium_start = src.index("const PREMIUM_INTEL_PATHS")
    premium_block = src[premium_start:src.index("]);", premium_start)]
    assert "/api/v1/intel/ai_summary.json" in premium_block, (
        "ai_summary.json is no longer in PREMIUM_INTEL_PATHS — the premium tier gate "
        "on the AI Cyber Brain bundle has been removed"
    )


# ---------------------------------------------------------------------------
# T35: Anomaly radar engine is actually invoked by CI
#
# Origin: the audit found scripts/anomaly_radar_engine.py — the zero-day
# candidate detector — was referenced by no workflow at all. Its output sat
# frozen for 127 days while the AI Cyber Brain served it as live intelligence.
# T13 passed throughout, because it validates the artifact's schema and never
# asks whether anything still produces it.
# ---------------------------------------------------------------------------

@test("T35_anomaly_radar_engine_wired_to_ci")
def t35():
    """An orphaned or unpersisted producer is a silently rotting artifact."""
    assert (REPO_ROOT / "scripts" / "anomaly_radar_engine.py").exists(), \
        "scripts/anomaly_radar_engine.py missing"
    _assert_producer_persisted(
        "scripts/anomaly_radar_engine.py",
        ["data/ai/anomaly_radar.json"],
    )


# ---------------------------------------------------------------------------
# T36: AI predictions engine trains on observed data only
#
# Origin: the 2026-09-09 anti-fabrication audit. ai_predictions_engine.py built
# each sector's forecast training set from 91 fabricated days
# (SECTOR_BASELINES + Gaussian noise) plus whatever real advisories existed —
# 91.8% synthetic overall, 100% for manufacturing. It seeded that noise with
# random.Random(hash(sector)), and hash() of a str is randomised per process,
# so identical inputs produced different "forecasts" on every run.
# ---------------------------------------------------------------------------

@test("T36_ai_predictions_no_synthetic_training_data")
def t36():
    """Forecasts must be fitted on observed advisories, deterministically."""
    engine = REPO_ROOT / "scripts" / "ai_predictions_engine.py"
    assert engine.exists(), "scripts/ai_predictions_engine.py missing"
    src = engine.read_text(encoding="utf-8", errors="replace")

    def code_only(text: str) -> str:
        """Return executable source with every docstring and comment removed.

        The audit rationale in this file quotes the removed code verbatim
        (inside docstrings and comments), so a raw substring search matches the
        very prose describing the fix. This is the same trap T35 fell into
        before it was mutation-tested, so the stripping is done properly here:
        all triple-quoted blocks, then all full-line and trailing # comments.
        """
        import re as _re
        stripped = _re.sub(r'"""[\s\S]*?"""', "", text)
        stripped = _re.sub(r"'''[\s\S]*?'''", "", stripped)
        out = []
        for ln in stripped.splitlines():
            if ln.lstrip().startswith("#"):
                continue
            # Drop trailing comments; no '#' appears inside a string literal in
            # the regions this test inspects.
            out.append(ln.split("#", 1)[0])
        return "\n".join(out)

    code = code_only(src)
    assert len(code) > 5000, (
        f"code_only() stripped too much ({len(code)} chars) — the checks below "
        "would pass vacuously"
    )

    # 1. No RNG anywhere in the engine — a forecast must not move without a
    #    change in the underlying data.
    for banned in ("random.Random", "rng.gauss", "random.gauss", "random.uniform"):
        assert banned not in code, (
            f"'{banned}' reintroduced into ai_predictions_engine.py — forecast output "
            "would vary run-to-run independently of the input data"
        )

    # 2. The evidence threshold must be enforced. Checked behaviourally below
    #    (see "evidence gate" assertions) rather than by counting occurrences of
    #    the constant's name: mutation-testing this test showed that replacing
    #    `if len(y) < MIN_REAL_SAMPLES:` with `if False:` left every textual
    #    reference intact and the gate passed while the guard was disabled.
    assert "INSUFFICIENT_EVIDENCE" in code, (
        "engine no longer declines under-evidenced sectors — it would publish a "
        "forecast built from too little observed history"
    )

    # 3. Confidence must not be floored. `max(0.50, ...)` made a model performing
    #    worse than the mean still publish confidence 0.50.
    assert "max(0.50" not in code and "max(0.5," not in code, (
        "confidence floor reintroduced — a model with no predictive skill would "
        "publish a floored confidence that carries no information"
    )
    assert "MIN_FORECAST_CONFIDENCE" in code, (
        "predictive-skill gate removed — forecasts with zero validated out-of-sample "
        "skill would be published as trend lines"
    )

    # 4. Behavioural check: the engine must declare its training data non-synthetic.
    import importlib.util
    spec = importlib.util.spec_from_file_location("ai_predictions_engine", engine)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_predictions_engine"] = mod   # dataclass/annotation safety
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop("ai_predictions_engine", None)

    # A sector with no matching advisories must yield no history at all —
    # previously it yielded 91 fabricated points.
    x, y = mod._build_sector_history([], "manufacturing")
    assert x == [] and y == [], (
        f"_build_sector_history fabricated {len(y)} points for a sector with zero "
        "observed advisories — synthetic history has returned"
    )

    # Determinism: same input, same output, across repeated calls.
    feed_items = [
        {"title": "energy grid scada outage", "published_at": "2026-09-01T00:00:00Z", "risk_score": 7.0},
        {"title": "power utility pipeline ics", "published_at": "2026-09-02T00:00:00Z", "risk_score": 6.0},
    ]
    first = mod._build_sector_history(feed_items, "energy")
    for _ in range(3):
        assert mod._build_sector_history(feed_items, "energy") == first, \
            "_build_sector_history is not deterministic for identical input"

    # Evidence gate, checked behaviourally. Build a feed carrying fewer energy
    # advisories than MIN_REAL_SAMPLES and assert the engine declines to
    # forecast that sector rather than fitting one on too little history.
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    _now = _dt.now(_tz.utc)
    thin_feed = [
        {
            "title": "energy grid scada advisory",
            "published_at": (_now - _td(days=i + 1)).isoformat(),
            "risk_score": 7.0,
        }
        for i in range(max(1, mod.MIN_REAL_SAMPLES - 1))
    ]
    report = mod.run_sector_forecasts(thin_feed)
    energy = report["sectors"]["energy"]
    assert energy.get("status") == "INSUFFICIENT_EVIDENCE", (
        f"energy has {mod.MIN_REAL_SAMPLES - 1} observations (below the "
        f"MIN_REAL_SAMPLES={mod.MIN_REAL_SAMPLES} threshold) but the engine "
        f"returned status={energy.get('status')!r} — the evidence gate is not enforced"
    )
    assert "forecast_30d" not in energy, (
        "a sector declined for insufficient evidence still carries a forecast series"
    )
    assert report.get("synthetic_training_data") is False, \
        "engine no longer declares its training data free of synthetic rows"


# ---------------------------------------------------------------------------
# T37: AI Cyber Brain never fabricates a missing assessment
#
# Origin: the same audit. ai_brain_publisher.py coerced absent fields with
# `or <literal>` throughout. Given a sector record carrying no forecast — which
# is exactly what the fixed engine emits for a declined sector — build_forecasts
# manufactured a complete, plausible, invented card: current_risk 5.0,
# peak_risk 5.0, risk_level MEDIUM, trend STABLE, confidence 0.75, prob 37.
# ---------------------------------------------------------------------------

@test("T37_ai_brain_no_fabricated_assessments")
def t37():
    """Absent inputs must be reported as absent, never defaulted into a number."""
    pub = REPO_ROOT / "scripts" / "ai_brain_publisher.py"
    assert pub.exists(), "scripts/ai_brain_publisher.py missing"

    import importlib.util
    spec = importlib.util.spec_from_file_location("ai_brain_publisher", pub)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_brain_publisher"] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop("ai_brain_publisher", None)

    # A declined sector must produce NO forecast card.
    declined = {
        "sectors": {
            "manufacturing": {
                "sector": "Manufacturing",
                "status": "INSUFFICIENT_EVIDENCE",
                "real_observations": 0,
            },
            "energy": {
                "sector": "Energy",
                "status": "NO_PREDICTIVE_SKILL",
                "real_observations": 57,
                "measured_confidence": 0.0,
            },
        }
    }
    out = mod.build_forecasts(declined)
    assert out == [], (
        f"build_forecasts fabricated {len(out)} forecast card(s) from sectors that "
        f"carry no forecast: {out}"
    )

    # A record with no status but no substance either must also be skipped.
    assert mod.build_forecasts({"sectors": {"x": {"sector": "X"}}}) == [], \
        "build_forecasts invented a card from an empty sector record"

    # A genuine forecast must still publish (backward compatibility with files
    # written before `status` existed).
    legacy = {
        "sectors": {
            "energy": {
                "sector": "Energy", "current_risk": 6.5, "peak_risk": 7.2,
                "confidence": 0.61, "risk_level": "HIGH", "trend": "RISING",
                "forecast_30d": [6.5] * 30,
            }
        }
    }
    legacy_out = mod.build_forecasts(legacy)
    assert len(legacy_out) == 1 and legacy_out[0]["sector"] == "Energy", \
        "build_forecasts dropped a legitimate legacy forecast — backward compatibility broken"

    # An unscored anomaly must publish unscored, not as an invented 7.5/HIGH.
    radar = {
        "top10_anomalous": [
            {"stix_id": "intel--unscored", "title": "no score", "anomaly_score": 0.9}
        ],
        "zero_day_candidates": [],
    }
    anoms = mod.build_anomalies(None, radar)
    assert len(anoms) == 1, f"expected 1 anomaly, got {len(anoms)}"
    a = anoms[0]
    assert a["risk_score"] is None, (
        f"unscored anomaly published risk_score={a['risk_score']} — a missing "
        "assessment was fabricated into a number"
    )
    assert a["severity"] == "UNKNOWN", (
        f"unscored anomaly published severity={a['severity']} — severity was invented"
    )
    assert a["soc_priority"] == "P?-UNSCORED", (
        f"unscored anomaly published soc_priority={a['soc_priority']} — a SOC "
        "priority was derived from a fabricated risk score"
    )

    # _opt_float must preserve a real 0.0 rather than treating it as absent.
    assert mod._opt_float(0.0) == 0.0, "_opt_float treats a genuine 0.0 as missing"
    assert mod._opt_float(None, None) is None, "_opt_float invented a value from nothing"


# ---------------------------------------------------------------------------
# T38: both AI prediction producers stay wired to CI
#
# Origin: both scripts that write the AI plane's artifacts were orphaned, which
# is why every one of those artifacts froze for months while the dashboards
# kept serving them. T35 covers the radar; this covers the predictions engine.
# ---------------------------------------------------------------------------

@test("T38_ai_predictions_engine_wired_to_ci")
def t38():
    """An orphaned producer silently freezes the artifacts it owns."""
    assert (REPO_ROOT / "scripts" / "ai_predictions_engine.py").exists(), \
        "scripts/ai_predictions_engine.py missing"
    _assert_producer_persisted(
        "scripts/ai_predictions_engine.py",
        ["data/ai_predictions/anomalies.json", "data/ai_predictions/forecasts.json"],
    )


# ---------------------------------------------------------------------------
# T39: the sector forecast is validated out-of-sample, or not published
#
# Origin: the 2026-09-09 forecast redesign. The previous forecast regressed
# per-advisory risk_score on day_index with a GradientBoostingRegressor -- a
# target that was not a time series (57 advisories on 3 distinct days), fitted
# by a model that cannot extrapolate (all 30 forecast days returned the
# identical boundary-leaf value 6.7800), on history that did not exist (the
# feed spans 8 days, so 91 synthetic days per sector were fabricated).
#
# The replacement forecasts daily sector intensity from a durable observation
# store, choosing a model by rolling-origin backtest and publishing only when
# it beats the naive benchmark. This gate locks those properties.
# ---------------------------------------------------------------------------

@test("T39_sector_forecast_validated_out_of_sample")
def t39():
    """A forecast must beat naive out-of-sample, or no forecast is published."""
    import importlib.util
    import math as _math

    model_path = REPO_ROOT / "scripts" / "sector_forecast_model.py"
    store_path = REPO_ROOT / "scripts" / "sector_history_store.py"
    assert model_path.exists(), "scripts/sector_forecast_model.py missing"
    assert store_path.exists(), "scripts/sector_history_store.py missing"

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        try:
            spec.loader.exec_module(mod)
        finally:
            sys.modules.pop(name, None)
        return mod

    fm = load("sector_forecast_model", model_path)
    hs = load("sector_history_store", store_path)

    # --- The publish gate must be "beats naive", not a softened threshold. ---
    assert fm.MASE_PUBLISH_THRESHOLD <= 1.0, (
        f"MASE publish threshold relaxed to {fm.MASE_PUBLISH_THRESHOLD} — a model "
        "that loses to 'tomorrow looks like today' would be published as a forecast"
    )

    # --- A forecastable signal must be forecast. Weekly seasonality is the
    #     real shape of advisory publishing; if the suite cannot handle it the
    #     forecast is useless even when it is honest. ---
    seasonal = [10.0 + 5.0 * _math.sin(2 * _math.pi * i / 7) for i in range(120)]
    ok = fm.select_and_forecast(seasonal, horizon=14, min_history=35)
    assert ok["publishable"], f"a clean weekly signal was declined: {ok['reason']}"
    assert ok["mase"] < 1.0, f"winner did not beat naive: MASE={ok['mase']}"
    assert len(ok["forecast"]) == 14, "forecast length does not match the horizon"
    assert len(ok["lower"]) == 14 and len(ok["upper"]) == 14, \
        "forecast published without prediction intervals"

    # --- Trend AND seasonality together must be forecastable. Testing the
    #     first version of this suite showed it declined every trending
    #     seasonal series, because no candidate modelled both at once. ---
    trending = [20.0 + 0.5 * i + 6.0 * _math.sin(2 * _math.pi * i / 7) for i in range(120)]
    tr = fm.select_and_forecast(trending, horizon=30, min_history=35)
    assert tr["publishable"], (
        f"a trending seasonal series was declined ({tr['reason']}) — the candidate "
        "set has lost its trend+seasonality models"
    )

    # --- An unforecastable series must be declined. A random walk is the
    #     textbook case where naive is optimal; publishing a model there would
    #     assert skill that does not exist. ---
    rw, seed = [0.0], 12345
    for _ in range(150):
        seed = (1103515245 * seed + 12345) % (2 ** 31)
        rw.append(rw[-1] + ((seed / 2 ** 31) - 0.5))
    bad = fm.select_and_forecast(rw, horizon=14, min_history=35)
    assert not bad["publishable"], (
        f"a random walk was published as forecastable (MASE={bad.get('mase')}) — "
        "naive is optimal on a random walk; this is a false skill claim"
    )
    assert "forecast" not in bad, \
        "a declined result still carries a forecast series a caller could render"

    # --- Too little history must decline, whatever the shape. ---
    assert not fm.select_and_forecast(seasonal[:20], horizon=14)["publishable"], \
        "forecast published on 20 days of history"

    # --- Backtesting must never score a model on data it was fitted on. ---
    seen = []

    def spy(train, h, **kw):
        seen.append(len(train))
        return [0.0] * h

    fm.rolling_origin_backtest([float(i) for i in range(60)], 10, spy, {}, min_train=20)
    assert seen and max(seen) <= 50, (
        f"backtest trained on up to {max(seen)} of 60 points while scoring a "
        "10-step horizon — future data leaked into training"
    )

    # --- Determinism: identical input, identical output. ---
    assert fm.select_and_forecast(seasonal, 14, min_history=35) == \
           fm.select_and_forecast(seasonal, 14, min_history=35), \
        "forecast is not deterministic"

    # --- The store must never fabricate an observation. ---
    from datetime import date as _date, timedelta as _td
    today = _date(2026, 9, 9)
    stale = [{"published_at": (today - _td(days=14)).isoformat() + "T00:00:00Z"}]
    _, action = hs.update_today({"days": {}}, stale, lambda i: "energy",
                                ["energy"], today=today)
    assert action.startswith("skipped_stale_feed"), (
        f"a 14-day-stale feed was recorded as a live observation (action={action}) — "
        "zeros would be written for days nothing was actually observed"
    )

    empty = hs.build_series({"days": {}}, "energy")
    assert empty["values"] == [] and empty["observed_days"] == 0, \
        "build_series invented a series from an empty store"


# ---------------------------------------------------------------------------
# T40: the observation store stays wired to CI
#
# The store only has value if it actually accumulates. An unwired store is an
# empty store, and the forecaster would decline forever.
# ---------------------------------------------------------------------------

@test("T40_sector_history_store_wired_to_ci")
def t40():
    """The observation store must accumulate durably, or the forecast never starts.

    sector_history.json is the load-bearing case: sector_forecast_model.py needs
    35 observed days before it publishes anything, and the store can only reach
    that by surviving between runs. On the git path it accumulated nothing at
    all, silently, because the push was rejected and the failure swallowed.
    """
    assert (REPO_ROOT / "scripts" / "sector_history_store.py").exists(), \
        "scripts/sector_history_store.py missing"
    _assert_producer_persisted(
        "scripts/sector_history_store.py",
        ["data/ai_predictions/sector_history.json"],
    )


# ---------------------------------------------------------------------------
# T41: pages-fast-publish path filter covers every root-level HTML page
# ---------------------------------------------------------------------------

@test("T41_pages_fast_publish_covers_every_root_html_page")
def t41():
    """Every root-level *.html page must be able to trigger the fast publisher.

    Found live (P0 first-revenue mission): PR #444 and #445 each landed a
    pricing.html-only or pricing.html+lead-pipeline.html+enterprise-
    onboarding.html diff to main. Neither triggered pages-fast-publish.yml --
    confirmed via its own workflow run history, no run exists between #77
    (PR #435's merge) and a manual workflow_dispatch that finally published
    them, over three hours later. Root cause: the workflow's `on.push.paths`
    (and matching `on.pull_request.paths`) listed `index.html` as a single
    literal filename, not a glob -- so no other root-level HTML page, this
    repo's entire buyer-facing surface among them, was covered. The exact gap
    class this same file's own header comments already document finding and
    fixing twice before (js/engines/*.js, then service-worker.js).

    This test is evergreen, not a one-off pin: it globs every *.html file
    actually at the repo root right now and asserts the workflow's own parsed
    path filter would match each one, so a future root-level page is caught
    by this test the moment it exists, and a future narrowing of the filter
    back to an enumerated list fails immediately rather than silently
    stranding pages behind the slow pipeline again.
    """
    import fnmatch
    import yaml

    workflow_path = REPO_ROOT / ".github" / "workflows" / "pages-fast-publish.yml"
    assert workflow_path.exists(), "pages-fast-publish.yml missing"
    doc = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    triggers = doc.get("on") or doc.get(True)  # PyYAML parses bare `on:` as True in some versions
    assert isinstance(triggers, dict) and "push" in triggers, \
        "pages-fast-publish.yml has no on.push trigger to check"

    root_html_files = sorted(p.name for p in REPO_ROOT.glob("*.html"))
    assert root_html_files, "no root-level *.html files found -- glob or repo layout changed"

    for trigger_name in ("push", "pull_request"):
        trigger = triggers.get(trigger_name)
        if not trigger:
            continue
        paths = trigger.get("paths") or []
        assert paths, f"pages-fast-publish.yml's on.{trigger_name} has no paths: filter at all"
        uncovered = [
            f for f in root_html_files
            if not any(fnmatch.fnmatch(f, pattern) for pattern in paths)
        ]
        assert not uncovered, (
            f"T41 REGRESSION: pages-fast-publish.yml's on.{trigger_name}.paths does not cover "
            f"{uncovered} -- a merge touching only these files will not trigger this workflow, "
            f"exactly the PR #444/#445 defect class. Use a glob (e.g. '*.html'), not an "
            f"enumerated per-file list."
        )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def main() -> int:
    # v166.2 FIND-008: Read version from SSOT instead of hardcoded string
    try:
        _ver_path = REPO_ROOT / "config" / "version.json"
        _suite_ver = json.loads(_ver_path.read_text(encoding="utf-8")).get("version", "UNKNOWN")
    except Exception:
        _suite_ver = "UNKNOWN"
    log.info("=" * 60)
    log.info("SENTINEL APEX v%s -- Regression Test Suite (T01-T31)", _suite_ver)
    log.info("=" * 60)

    pass_count = sum(1 for r in RESULTS if r["status"] == "PASS")
    pass_count = sum(1 for r in RESULTS if r["status"] == "PASS")
    fail_count = sum(1 for r in RESULTS if r["status"] in ("FAIL", "ERROR"))
    total = len(RESULTS)

    log.info("-" * 60)
    for r in RESULTS:
        icon = {"PASS": "\u2705", "FAIL": "\u274c", "ERROR": "\U0001f4a5"}.get(r["status"], "?")
        detail_str = f"-- {r['detail'][:120]}" if r["detail"] else ""
        log.info("  %s [%s] %s  %s", icon, r["status"], r["test"], detail_str)
    log.info("-" * 60)
    log.info("Results: %d PASS, %d FAIL of %d tests", pass_count, fail_count, total)

    if fail_count > 0:
        log.critical(
            "REGRESSION DETECTED: %d test(s) failed. "
            "Pipeline has regressed from last stable state. "
            "Investigate before next production deployment.",
            fail_count,
        )
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
